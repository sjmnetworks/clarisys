#!/usr/bin/env bash
# Installs systemd drop-ins and updated configs from deploy/ to enforce memory
# limits on Loki, Grafana, Prometheus, Promtail, and the OPA API.
# Must be run as root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_dropin() {
  local service="$1" src="$2"
  local dir="/etc/systemd/system/${service}.service.d"
  mkdir -p "$dir"
  cp "$src" "$dir/memory.conf"
  echo "  Installed $dir/memory.conf"
}

echo "Installing systemd memory drop-ins..."
install_dropin loki             "$SCRIPT_DIR/systemd-dropin/loki-memory.conf"
install_dropin grafana-server   "$SCRIPT_DIR/systemd-dropin/grafana-server-memory.conf"
install_dropin prometheus       "$SCRIPT_DIR/systemd-dropin/prometheus-memory.conf"
install_dropin promtail         "$SCRIPT_DIR/systemd-dropin/promtail-memory.conf"
install_dropin opa-api-8001     "$SCRIPT_DIR/systemd-dropin/opa-api-8001-memory.conf"

echo "Installing Loki config..."
cp "$SCRIPT_DIR/loki-config.yml" /etc/loki/config.yml

echo "Setting Prometheus retention flags..."
sed -i 's/^ARGS=.*/ARGS="--storage.tsdb.retention.time=7d --storage.tsdb.retention.size=1GB"/' /etc/default/prometheus

echo "Reloading systemd and restarting services..."
systemctl daemon-reload
systemctl restart loki prometheus promtail grafana-server opa-api-8001

echo "Done. Verify with: systemctl status loki prometheus promtail grafana-server opa-api-8001"
