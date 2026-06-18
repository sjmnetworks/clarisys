#!/usr/bin/env bash
set -euo pipefail

# Install Loki + Promtail from Grafana apt repo and apply repo configs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUN_UPDATE="true"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --no-update  Skip apt-get update
  -h, --help   Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-update)
      RUN_UPDATE="false"
      shift
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

if [[ "$RUN_UPDATE" == "true" ]]; then
  sudo apt-get update
fi

sudo apt-get install -y loki promtail

# Promtail needs journal read permissions.
if getent group systemd-journal >/dev/null 2>&1; then
  sudo usermod -a -G systemd-journal promtail || true
fi

bash "$SCRIPT_DIR/sync_loki_stack.sh" --force

echo "Loki stack install and sync complete."
