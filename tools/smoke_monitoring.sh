#!/usr/bin/env bash
set -euo pipefail

# Lightweight smoke checks for API, Grafana path routing, and Prometheus ROI scrape.
# Uses localhost TLS plus Host header to avoid cloud hairpin NAT issues.
PUBLIC_HOST="${1:-18.170.45.5}"
BASE_URL="https://127.0.0.1"
API_HEALTH_URL="${BASE_URL}/health"
GRAFANA_LOGIN_URL="${BASE_URL}/grafana/login"
PROM_URL="http://127.0.0.1:9090/api/v1/targets"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

code_health="$(curl -k -sS -H "Host: ${PUBLIC_HOST}" -o /tmp/smoke_health.json -w '%{http_code}' "$API_HEALTH_URL")"
[[ "$code_health" == "200" ]] || fail "API health returned HTTP ${code_health}"
pass "API health endpoint reachable (${API_HEALTH_URL}, Host=${PUBLIC_HOST})"

code_grafana="$(curl -k -sS -H "Host: ${PUBLIC_HOST}" -o /tmp/smoke_grafana_login.html -w '%{http_code}' "$GRAFANA_LOGIN_URL")"
[[ "$code_grafana" == "200" ]] || fail "Grafana login returned HTTP ${code_grafana}"
pass "Grafana login reachable (${GRAFANA_LOGIN_URL}, Host=${PUBLIC_HOST})"

if grep -q -i '<!DOCTYPE html>' /tmp/smoke_grafana_login.html; then
  pass "Grafana login response looks like HTML"
else
  fail "Grafana login response did not look like HTML"
fi

if curl -sS "$PROM_URL" | jq -e '.data.activeTargets[] | select(.labels.job=="firewall-api-roi" and .health=="up")' >/dev/null; then
  pass "Prometheus ROI target firewall-api-roi is up"
else
  fail "Prometheus ROI target firewall-api-roi is not up"
fi

echo "Smoke checks completed successfully."
