#!/usr/bin/env bash

# Sync multiple Grafana dashboards from repo to provisioned path.
# Handles ops metrics and live ROI metrics dashboards.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DRY_RUN="false"
FORCE="false"
BACKUP_DIR=""
MANIFEST_FILE=""

usage() {
  cat <<EOF
Usage: $0 [options]

Syncs all Grafana dashboards (ops metrics + live ROI) from repo to provisioned paths.

Options:
  --force           Sync even if files match hashes
  --dry-run         Print actions only, do not modify files/services
  --backup-dir <path> Backup directory for rollback snapshots (default: auto /tmp path)
  --manifest-file <path> Combined manifest CSV output path (default: auto /tmp path)
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

# Temp dir for individual manifests
TEMP_MANIFEST_DIR="/tmp/firewall-monitoring-grafana-manifests-$$"
mkdir -p "$TEMP_MANIFEST_DIR"
trap 'rm -rf "$TEMP_MANIFEST_DIR"' EXIT

# Auto-set backup & manifest if not provided
if [[ -z "$BACKUP_DIR" ]]; then
  BACKUP_DIR="/tmp/firewall-monitoring-sync-grafana-bundle-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi

if [[ -z "$MANIFEST_FILE" ]]; then
  MANIFEST_FILE="/tmp/firewall-monitoring-sync-grafana-bundle-$(date -u +%Y%m%dT%H%M%SZ)-$$.csv"
fi

# Define dashboards: (source_repo_path target_provisioned_path dashboard_name)
declare -a DASHBOARDS=(
  "$REPO_ROOT/deploy/monitoring/grafana/firewall-api-observability-dashboard.json:/var/lib/grafana/dashboards/firewall-api-core-monitoring.json:ops-metrics"
  "$REPO_ROOT/deploy/monitoring/grafana/opa-roi-live-dashboard.json:/var/lib/grafana/dashboards/opa-roi-live-dashboard.json:roi-live"
)

echo "Syncing Grafana dashboards bundle..."
echo "  Total dashboards: ${#DASHBOARDS[@]}"
echo "  Backup dir: $BACKUP_DIR"
echo "  Combined manifest: $MANIFEST_FILE"
echo ""

sync_count=0
skip_count=0

for dashboard_def in "${DASHBOARDS[@]}"; do
  IFS=':' read -r source target name <<<"$dashboard_def"
  
  echo "Syncing dashboard: $name"
  echo "  source: $source"
  echo "  target: $target"
  
  # Use individual manifest for each sync
  individual_manifest="$TEMP_MANIFEST_DIR/$name.csv"
  
  # Call the individual sync script with our shared options
  cmd=(
    "$SCRIPT_DIR/sync_grafana_dashboard.sh"
    "--source" "$source"
    "--target" "$target"
    "--backup-dir" "$BACKUP_DIR"
    "--manifest-file" "$individual_manifest"
  )
  
  if [[ "$FORCE" == "true" ]]; then
    cmd+=(--force)
  fi
  
  if [[ "$DRY_RUN" == "true" ]]; then
    cmd+=(--dry-run)
  fi
  
  # Execute sync and check output
  if output=$("${cmd[@]}" 2>&1); then
    if echo "$output" | grep -q "unchanged"; then
      ((skip_count++))
      echo "  ○ Unchanged (no sync needed)"
    else
      ((sync_count++))
      echo "  ✓ Synced"
    fi
  else
    echo "  ✗ Sync failed for $name" >&2
  fi
  echo ""
done

# Merge individual manifests into combined CSV
mkdir -p "$(dirname "$MANIFEST_FILE")"
cat >"$MANIFEST_FILE" <<'EOF'
timestamp_utc,mode,source,target,backup_path,old_sha256,new_sha256,status
EOF

for individual_manifest in "$TEMP_MANIFEST_DIR"/*.csv; do
  if [[ -f "$individual_manifest" ]]; then
    # Skip header, append data rows
    tail -n +2 "$individual_manifest" >>"$MANIFEST_FILE" 2>/dev/null || true
  fi
done

echo "==============================================="
echo "Bundle sync complete:"
echo "  Synced:  $sync_count"
echo "  Skipped: $skip_count (unchanged)"
echo "  Total:   ${#DASHBOARDS[@]}"
echo "Combined manifest: $MANIFEST_FILE"
echo "==============================================="
