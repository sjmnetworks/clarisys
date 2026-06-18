#!/usr/bin/env bash
# Start the Clarisys Firewall Policy Compliance API.
#
# Modes:
#   APP_ENV=development (default)  → reload, bind 0.0.0.0, single worker, /docs enabled
#   APP_ENV=production             → no reload, bind 127.0.0.1, multi-worker, /docs disabled
#
# In production, run behind a TLS-terminating reverse proxy (ALB / NGINX /
# Azure App Gateway) that forwards to 127.0.0.1:8000. Never expose this
# process directly to the public network.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

VENV_UVICORN=".venv/bin/uvicorn"
APP_ENV="${APP_ENV:-development}"
PORT="${PORT:-8000}"

if [[ "$APP_ENV" == "production" ]]; then
  HOST="${HOST:-127.0.0.1}"
  WORKERS="${WORKERS:-2}"
  echo "Starting Clarisys Firewall Policy API [PRODUCTION] on http://${HOST}:${PORT}"
  echo "  Workers:  ${WORKERS}"
  echo "  Docs:     disabled"
  echo "  Front this process with a TLS terminator + WAF + auth proxy."
  echo ""
  exec env APP_ENV=production "$VENV_UVICORN" api.main:app \
    --host "$HOST" \
    --port "$PORT" \
    --workers "$WORKERS" \
    --proxy-headers \
    --forwarded-allow-ips="*" \
    --no-access-log
else
  HOST="${HOST:-0.0.0.0}"
  echo "Starting Clarisys Firewall Policy API [DEVELOPMENT] on http://${HOST}:${PORT}"
  echo "  Docs:     http://${HOST}:${PORT}/docs"
  echo "  Evaluate: POST http://${HOST}:${PORT}/evaluate"
  echo "  Health:   GET  http://${HOST}:${PORT}/health"
  echo ""
  exec env APP_ENV=development "$VENV_UVICORN" api.main:app \
    --host "$HOST" \
    --port "$PORT" \
    --reload
fi
