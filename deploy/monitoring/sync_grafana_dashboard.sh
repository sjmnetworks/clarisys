#!/usr/bin/env bash
set -euo pipefail

# Sync Grafana dashboard JSON from repo to provisioned path.
# Restarts Grafana only when the dashboard file changed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SOURCE_DEFAULT="$REPO_ROOT/deploy/monitoring/grafana/firewall-api-observability-dashboard.json"
TARGET_DEFAULT="/var/lib/grafana/dashboards/firewall-api-core-monitoring.json"
SERVICE_DEFAULT="grafana-server"

SOURCE="$SOURCE_DEFAULT"
TARGET="$TARGET_DEFAULT"
SERVICE="$SERVICE_DEFAULT"
DRY_RUN="false"
FORCE="false"
BACKUP_DIR=""
MANIFEST_FILE=""
TARGET_CREATED="false"
TARGET_BACKUP=""
OLD_SHA=""
NEW_SHA=""

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --source <path>   Source dashboard JSON (default: $SOURCE_DEFAULT)
  --target <path>   Provisioned dashboard path (default: $TARGET_DEFAULT)
  --service <name>  Grafana service name (default: $SERVICE_DEFAULT)
  --force           Copy and restart even if file hash matches
  --dry-run         Print actions only, do not modify files/services
  --backup-dir <path> Backup directory for rollback snapshots (default: auto /tmp path)
  --manifest-file <path> Manifest CSV output path (default: auto /tmp path)
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --service)
      SERVICE="$2"
      shift 2
      ;;
    --force)
      FORCE="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
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

if [[ ! -f "$SOURCE" ]]; then
  echo "Source file not found: $SOURCE" >&2
  exit 1
fi

sudo_cmd=(sudo)
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  sudo_cmd=()
fi

if [[ -z "$BACKUP_DIR" ]]; then
  BACKUP_DIR="/tmp/firewall-monitoring-sync-grafana-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi

if [[ -z "$MANIFEST_FILE" ]]; then
  MANIFEST_FILE="/tmp/firewall-monitoring-sync-grafana-$(date -u +%Y%m%dT%H%M%SZ)-$$.csv"
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

write_manifest() {
  mkdir -p "$(dirname "$MANIFEST_FILE")"
  if [[ ! -f "$MANIFEST_FILE" ]]; then
    cat >"$MANIFEST_FILE" <<EOF
timestamp_utc,mode,source,target,backup_path,old_sha256,new_sha256,status
EOF
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$1" "$SOURCE" "$TARGET" "$TARGET_BACKUP" "$OLD_SHA" "$NEW_SHA" "$2" >>"$MANIFEST_FILE"
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

  echo "Attempting rollback for Grafana dashboard..."
  if [[ "$TARGET_CREATED" == "true" ]]; then
    ${sudo_cmd[@]} rm -f "$TARGET"
    echo "Removed newly created target: $TARGET"
  elif [[ -n "$TARGET_BACKUP" && -f "$TARGET_BACKUP" ]]; then
    ${sudo_cmd[@]} install -D -o grafana -g grafana -m 0644 "$TARGET_BACKUP" "$TARGET"
    echo "Restored previous target from backup: $TARGET"
  fi

  if systemctl list-unit-files | grep -q "^${SERVICE}\.service"; then
    ${sudo_cmd[@]} systemctl restart "$SERVICE" >/dev/null 2>&1 || true
  fi
}

on_error() {
  local line="$1"
  local cmd="$2"
  echo "Error on line $line while running: $cmd" >&2
  write_manifest "apply" "failed"
  rollback
  exit 1
}

trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

preflight_checks

needs_update="true"
if [[ -f "$TARGET" ]]; then
  src_sha="$(sha256sum "$SOURCE" | awk '{print $1}')"
  dst_sha="$(${sudo_cmd[@]} sha256sum "$TARGET" | awk '{print $1}')"
  if [[ "$src_sha" == "$dst_sha" ]]; then
    needs_update="false"
  fi
fi

if [[ "$FORCE" == "false" && "$needs_update" == "false" ]]; then
  echo "Dashboard unchanged; no sync required."
  exit 0
fi

echo "Syncing dashboard:"
echo "  source:  $SOURCE"
echo "  target:  $TARGET"
echo "  service: $SERVICE"
echo "  backup:  $BACKUP_DIR"

if [[ "$DRY_RUN" == "true" ]]; then
  echo "Dry-run enabled; no changes applied."
  OLD_SHA="$( [[ -f "$TARGET" ]] && ${sudo_cmd[@]} sha256sum "$TARGET" | awk '{print $1}' || echo "missing" )"
  NEW_SHA="$(sha256sum "$SOURCE" | awk '{print $1}')"
  write_manifest "dry-run" "skipped"
  echo "Manifest: $MANIFEST_FILE"
  exit 0
fi

mkdir -p "$BACKUP_DIR"
if [[ -f "$TARGET" ]]; then
  TARGET_BACKUP="$BACKUP_DIR/firewall-api-core-monitoring.json.bak"
  OLD_SHA="$(${sudo_cmd[@]} sha256sum "$TARGET" | awk '{print $1}')"
  ${sudo_cmd[@]} cp -a "$TARGET" "$TARGET_BACKUP"
else
  TARGET_CREATED="true"
  OLD_SHA="missing"
fi

${sudo_cmd[@]} install -o grafana -g grafana -m 0644 "$SOURCE" "$TARGET"
NEW_SHA="$(${sudo_cmd[@]} sha256sum "$TARGET" | awk '{print $1}')"
${sudo_cmd[@]} systemctl restart "$SERVICE"

echo "Dashboard synced and $SERVICE restarted."
write_manifest "apply" "success"
echo "Manifest: $MANIFEST_FILE"
