#!/usr/bin/env bash
set -euo pipefail

# Check recent API errors in Loki + systemd journal for a configurable window.

WINDOW_MINUTES="${1:-30}"
OUT_DIR="${2:-/tmp}"

OUT_FILE="${OUT_DIR%/}/opa_api_error_check_$(date -u +%Y%m%dT%H%M%SZ).log"
START_NS=$(date -u -d "${WINDOW_MINUTES} minutes ago" +%s%N)
END_NS=$(date -u +%s%N)

mkdir -p "$OUT_DIR"

{
  echo "== API error check run at $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
  echo "== Window: last ${WINDOW_MINUTES} minutes =="
  echo "== Loki: opa-api-8001 permission/audit/errors =="
  curl -sG 'http://127.0.0.1:3100/loki/api/v1/query_range' \
    --data-urlencode 'query={job="systemd-journal",unit="opa-api-8001.service"} |~ "PermissionError|audit_store.record_failed|exception|traceback|\\\"level\\\": \\\"error\\\""' \
    --data-urlencode "start=$START_NS" \
    --data-urlencode "end=$END_NS" \
    --data-urlencode 'limit=200' | jq -r '.data.result[]?.values[]?[1]'
  echo
  echo "== Journal: opa-api-8001 permission/audit/errors =="
  journalctl -u opa-api-8001.service --since "${WINDOW_MINUTES} min ago" --no-pager | rg -i 'permissionerror|audit_store.record_failed|exception|traceback|"level": "error"' || true
} > "$OUT_FILE" 2>&1

printf '%s\n' "$OUT_FILE"
