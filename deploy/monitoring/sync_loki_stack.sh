#!/usr/bin/env bash
set -euo pipefail

# Sync Loki/Promtail configs and Grafana Loki datasource from repo to host.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

LOKI_SOURCE_DEFAULT="$REPO_ROOT/deploy/monitoring/loki-config.yml"
PROMTAIL_SOURCE_DEFAULT="$REPO_ROOT/deploy/monitoring/promtail-config.yml"
DATASOURCE_SOURCE_DEFAULT="$REPO_ROOT/deploy/monitoring/grafana/loki-datasource.yml"

LOKI_TARGET_DEFAULT="/etc/loki/config.yml"
PROMTAIL_TARGET_DEFAULT="/etc/promtail/config.yml"
DATASOURCE_TARGET_DEFAULT="/etc/grafana/provisioning/datasources/loki.yaml"

LOKI_SOURCE="$LOKI_SOURCE_DEFAULT"
PROMTAIL_SOURCE="$PROMTAIL_SOURCE_DEFAULT"
DATASOURCE_SOURCE="$DATASOURCE_SOURCE_DEFAULT"
LOKI_TARGET="$LOKI_TARGET_DEFAULT"
PROMTAIL_TARGET="$PROMTAIL_TARGET_DEFAULT"
DATASOURCE_TARGET="$DATASOURCE_TARGET_DEFAULT"

DRY_RUN="false"
FORCE="false"
BACKUP_DIR=""
MANIFEST_FILE=""

declare -A TARGET_BACKUPS=()
declare -A TARGET_OWNERS=()
declare -A TARGET_GROUPS=()
declare -A TARGET_MODES=()
declare -A TARGET_CREATED=()

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --dry-run   Print actions only, no file or service changes
  --force     Apply file copy and service restart regardless of hash equality
  --backup-dir <path> Backup directory for rollback snapshots (default: auto /tmp path)
  --manifest-file <path> Manifest CSV output path (default: auto /tmp path)
  -h, --help  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --force)
      FORCE="true"
      shift
      ;;
    --backup-dir)
      BACKUP_DIR="$2"
      shift 2
      ;;
    --manifest-file)
      MANIFEST_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

sudo_cmd=(sudo)
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  sudo_cmd=()
fi

if [[ -z "$BACKUP_DIR" ]]; then
  BACKUP_DIR="/tmp/firewall-monitoring-sync-loki-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi

if [[ -z "$MANIFEST_FILE" ]]; then
  MANIFEST_FILE="/tmp/firewall-monitoring-sync-loki-$(date -u +%Y%m%dT%H%M%SZ)-$$.csv"
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

init_manifest() {
  mkdir -p "$(dirname "$MANIFEST_FILE")"
  if [[ ! -f "$MANIFEST_FILE" ]]; then
    cat >"$MANIFEST_FILE" <<EOF
timestamp_utc,mode,source,target,backup_path,old_sha256,new_sha256,status
EOF
  fi
}

append_manifest() {
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" >>"$MANIFEST_FILE"
}

preflight_checks() {
  require_cmd systemctl
  require_cmd sha256sum
  require_cmd install
  require_cmd awk
  require_cmd grep
  require_cmd date
  require_cmd cp
  require_cmd mkdir
  require_cmd sed
  require_cmd id

  if [[ "${EUID:-$(id -u)}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required when not running as root." >&2
    exit 1
  fi
}

rollback() {
  trap - ERR
  set +e

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "Rollback skipped (dry-run)."
    return
  fi

  echo "Attempting rollback for Loki stack sync..."

  for dst in "${!TARGET_BACKUPS[@]}"; do
    backup_path="${TARGET_BACKUPS[$dst]}"
    owner="${TARGET_OWNERS[$dst]}"
    group="${TARGET_GROUPS[$dst]}"
    mode="${TARGET_MODES[$dst]}"
    if [[ -f "$backup_path" ]]; then
      ${sudo_cmd[@]} install -D -o "$owner" -g "$group" -m "$mode" "$backup_path" "$dst"
      echo "Restored: $dst"
    fi
  done

  for dst in "${!TARGET_CREATED[@]}"; do
    if [[ "${TARGET_CREATED[$dst]}" == "true" ]]; then
      ${sudo_cmd[@]} rm -f "$dst"
      echo "Removed newly created target: $dst"
    fi
  done

  for svc in loki promtail grafana-server; do
    if systemctl list-unit-files | grep -q "^${svc}\.service"; then
      ${sudo_cmd[@]} systemctl restart "$svc" >/dev/null 2>&1 || true
    fi
  done
}

on_error() {
  local line="$1"
  local cmd="$2"
  echo "Error on line $line while running: $cmd" >&2
  append_manifest "apply" "n/a" "n/a" "" "" "" "failed"
  rollback
  exit 1
}

trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

preflight_checks
init_manifest

sync_file_if_changed() {
  local src="$1"
  local dst="$2"
  local owner="$3"
  local group="$4"
  local mode="$5"
  local src_sha
  local dst_sha="missing"
  local backup_path=""

  if [[ ! -f "$src" ]]; then
    echo "Missing source file: $src" >&2
    exit 1
  fi

  src_sha="$(sha256sum "$src" | awk '{print $1}')"
  local changed="1"
  if [[ -f "$dst" ]]; then
    dst_sha="$(${sudo_cmd[@]} sha256sum "$dst" | awk '{print $1}')"
    if [[ "$src_sha" == "$dst_sha" ]]; then
      changed="0"
    fi
  fi

  if [[ "$FORCE" == "true" ]]; then
    changed="1"
  fi

  if [[ "$changed" == "0" ]]; then
    echo "Unchanged: $dst"
    append_manifest "check" "$src" "$dst" "$backup_path" "$dst_sha" "$dst_sha" "unchanged"
    return 1
  fi

  echo "Sync: $src -> $dst"
  if [[ "$DRY_RUN" == "true" ]]; then
    append_manifest "dry-run" "$src" "$dst" "$backup_path" "$dst_sha" "$src_sha" "planned"
  else
    mkdir -p "$BACKUP_DIR"
    if [[ -f "$dst" ]]; then
      local safe_name
      safe_name="$(echo "$dst" | sed 's#/#__#g' | sed 's/^__//')"
      backup_path="$BACKUP_DIR/${safe_name}.bak"
      ${sudo_cmd[@]} cp -a "$dst" "$backup_path"
      TARGET_BACKUPS["$dst"]="$backup_path"
      TARGET_OWNERS["$dst"]="$owner"
      TARGET_GROUPS["$dst"]="$group"
      TARGET_MODES["$dst"]="$mode"
    else
      TARGET_CREATED["$dst"]="true"
    fi
    ${sudo_cmd[@]} install -o "$owner" -g "$group" -m "$mode" "$src" "$dst"
    local new_sha
    new_sha="$(${sudo_cmd[@]} sha256sum "$dst" | awk '{print $1}')"
    append_manifest "apply" "$src" "$dst" "$backup_path" "$dst_sha" "$new_sha" "success"
  fi
  return 0
}

restart_if_active() {
  local service="$1"
  if ! systemctl status "$service" >/dev/null 2>&1; then
    echo "Service not installed: $service"
    return
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "Would restart: $service"
    return
  fi

  if systemctl is-active --quiet "$service"; then
    ${sudo_cmd[@]} systemctl restart "$service"
    echo "Restarted: $service"
  else
    ${sudo_cmd[@]} systemctl enable --now "$service"
    echo "Enabled and started: $service"
  fi
}

changed_loki=0
changed_promtail=0
changed_datasource=0

echo "Backup directory: $BACKUP_DIR"

sync_file_if_changed "$LOKI_SOURCE" "$LOKI_TARGET" root root 0644 && changed_loki=1 || true
sync_file_if_changed "$PROMTAIL_SOURCE" "$PROMTAIL_TARGET" root root 0644 && changed_promtail=1 || true
sync_file_if_changed "$DATASOURCE_SOURCE" "$DATASOURCE_TARGET" root root 0644 && changed_datasource=1 || true

if [[ "$DRY_RUN" == "false" ]]; then
  ${sudo_cmd[@]} mkdir -p /var/lib/loki/chunks /var/lib/loki/rules /var/lib/loki/compactor
  ${sudo_cmd[@]} mkdir -p /var/lib/promtail
  ${sudo_cmd[@]} chown -R loki:nogroup /var/lib/loki
  ${sudo_cmd[@]} chown -R promtail:nogroup /var/lib/promtail
fi

if [[ "$changed_loki" == "1" ]]; then
  restart_if_active loki
fi
if [[ "$changed_promtail" == "1" ]]; then
  restart_if_active promtail
fi
if [[ "$changed_datasource" == "1" ]]; then
  restart_if_active grafana-server
fi

if [[ "$changed_loki" == "0" && "$changed_promtail" == "0" && "$changed_datasource" == "0" ]]; then
  echo "Loki stack unchanged; no action required."
fi

echo "Manifest: $MANIFEST_FILE"
