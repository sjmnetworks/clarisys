#!/usr/bin/env bash
# Periodic perf sampler for the OPA policy API.
# Runs a lightweight perf sweep and appends a one-line summary per batch size
# to /var/log/opa-api-perf.log. Designed to run from cron every N minutes.

set -euo pipefail

URL="${OPA_PERF_URL:-https://127.0.0.1}"
LOG="${OPA_PERF_LOG:-/var/log/opa-api-perf.log}"
RUNS="${OPA_PERF_RUNS:-1}"
SIZES="${OPA_PERF_SIZES:-1,10,50,100}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Run perf_test.py (insecure for self-signed cert) and capture data rows.
python3 "${SCRIPT_DIR}/perf_test.py" \
    --url "${URL}" \
    --insecure \
    --runs "${RUNS}" \
    --sizes "${SIZES}" 2>&1 \
  | awk -v ts="${TS}" '
      /^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/ {
          printf "%s size=%s calls=%s mean_s=%s p95_s=%s req_s=%s status=%s\n",
                 ts, $1, $2, $5, $6, $8, $NF
      }
    ' >> "${LOG}"
