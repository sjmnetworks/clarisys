#!/usr/bin/env bash
set -euo pipefail

# Run all monitoring sync scripts with one command and produce one merged
# manifest artifact for release evidence.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DRY_RUN="false"
FORCE="false"
BACKUP_DIR=""
MANIFEST_FILE=""

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --dry-run             Run validation/plan only, no file or service changes
  --force               Force apply in child sync scripts
  --backup-dir <path>   Shared backup directory for child scripts
  --manifest-file <path> Combined manifest CSV output path (default: auto /tmp path)
  -h, --help            Show this help
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

if [[ -z "$MANIFEST_FILE" ]]; then
  MANIFEST_FILE="/tmp/firewall-monitoring-sync-bundle-$(date -u +%Y%m%dT%H%M%SZ)-$$.csv"
fi

if [[ -z "$BACKUP_DIR" ]]; then
  BACKUP_DIR="/tmp/firewall-monitoring-sync-bundle-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi

mkdir -p "$(dirname "$MANIFEST_FILE")"
mkdir -p "$BACKUP_DIR"

TMP_DIR="$(mktemp -d /tmp/firewall-monitoring-sync-bundle-step-XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

manifest_alert="$TMP_DIR/alertmanager.csv"
manifest_grafana="$TMP_DIR/grafana.csv"
manifest_loki="$TMP_DIR/loki.csv"

common_args=(--backup-dir "$BACKUP_DIR")
if [[ "$DRY_RUN" == "true" ]]; then
  common_args+=(--dry-run)
fi
if [[ "$FORCE" == "true" ]]; then
  common_args+=(--force)
fi

echo "Running monitoring bundle sync..."
echo "  backup dir:   $BACKUP_DIR"
echo "  manifest out: $MANIFEST_FILE"

bash "$SCRIPT_DIR/sync_alertmanager_config.sh" \
  "${common_args[@]}" \
  --manifest-file "$manifest_alert"

bash "$SCRIPT_DIR/sync_grafana_dashboard.sh" \
  "${common_args[@]}" \
  --manifest-file "$manifest_grafana"

bash "$SCRIPT_DIR/sync_loki_stack.sh" \
  "${common_args[@]}" \
  --manifest-file "$manifest_loki"

{
  echo "timestamp_utc,mode,source,target,backup_path,old_sha256,new_sha256,status"
  tail -n +2 "$manifest_alert" 2>/dev/null || true
  tail -n +2 "$manifest_grafana" 2>/dev/null || true
  tail -n +2 "$manifest_loki" 2>/dev/null || true
} >"$MANIFEST_FILE"

echo "Combined manifest written to: $MANIFEST_FILE"
echo "Monitoring bundle sync completed."
