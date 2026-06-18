# Monitoring Quick Ops

Fast commands for on-call checks of the firewall policy API monitoring stack.

## Baseline

```bash
API_BASE_URL="http://127.0.0.1:8001"
PROM_BASE_URL="http://127.0.0.1:9090"
GRAFANA_URL="http://127.0.0.1:3000"
LOKI_BASE_URL="http://127.0.0.1:3100"
PROMTAIL_BASE_URL="http://127.0.0.1:9080"
```

## Service Health

```bash
systemctl is-active prometheus grafana-server loki promtail opa-api-8001
curl -s "$API_BASE_URL/health" | jq
curl -s "$PROM_BASE_URL/-/healthy"
curl -s "$GRAFANA_URL/api/health" | jq
curl -s "$LOKI_BASE_URL/ready"
curl -s "$PROMTAIL_BASE_URL/ready"

# One-shot incident bundle (systemd, logs, health, Prometheus, Loki)
python3 tools/ops_kit.py snapshot --unit opa-api-8001.service

# Startup/restart watchdog
python3 tools/ops_kit.py watchdog --unit opa-api-8001.service

# Monitoring drift check against provisioned host files
python3 tools/ops_kit.py verify-drift

# Alert-driven operator runbook
python3 tools/ops_kit.py runbook --topic auto

# Incident timeline (decisions + lifecycle + journal + alert snapshot)
python3 tools/ops_kit.py timeline

# End-to-end ingress smoke check (API + Grafana path + ROI scrape)
bash tools/smoke_monitoring.sh 18.170.45.5

# Full release gate (includes ingress /grafana/login and firewall-api-roi target checks)
python3 tools/release_gate_check.py \
  --base-url http://127.0.0.1:8001 \
  --ingress-base-url https://127.0.0.1 \
  --ingress-host 18.170.45.5
```

## Prometheus Target Check

```bash
curl -s "$PROM_BASE_URL/api/v1/targets" | jq '.data.activeTargets[] | {job: .labels.job, scrapeUrl: .scrapeUrl, health: .health, lastError: .lastError}'
```

Expected scrape targets:

- firewall-api-slo -> 127.0.0.1:8001/metrics/slo
- firewall-api-alerts -> 127.0.0.1:8001/metrics/alerts
- firewall-api-roi -> 127.0.0.1:8001/metrics

## Prometheus Rules Validation

```bash
promtool check rules deploy/monitoring/firewall-rules.yml

# Unit-test critical alert behavior
promtool test rules deploy/monitoring/firewall-rules.test.yml
```

## Core KPI Queries

```bash
# Total requests
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=sum(firewall_decisions_total)' | jq

# Accepted total
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=sum(clamp_min(firewall_decisions_total - firewall_decisions_deny, 0))' | jq

# Denied total
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=sum(firewall_decisions_deny)' | jq

# Service up (1 up, 0 down)
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=firewall:service_up' | jq
```

## Latency Queries

```bash
# API mean latency (ms)
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=firewall_latency_avg_ms' | jq

# API p95 latency (ms)
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=firewall_latency_p95_ms' | jq

# Slack dispatch latency p95 (ms)
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=firewall_slack_dispatch_latency_p95_ms' | jq
```

## Standards Failure Totals

```bash
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=sum(firewall_failed_standard_ms_nfr_total)' | jq
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=sum(firewall_failed_standard_cis_v81_total)' | jq
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=sum(firewall_failed_standard_iso_27001_total)' | jq
curl -s --get "$PROM_BASE_URL/api/v1/query" --data-urlencode 'query=sum(firewall_failed_standard_pci_dss_total)' | jq
```

## Slack Delivery and Latency Source Check

```bash
curl -s "$API_BASE_URL/notifications/slack/metrics" | jq '{dispatch_successes,dispatch_failures,dispatch_latency_count,dispatch_latency_avg_ms,dispatch_latency_p95_ms,last_error}'
```

If dispatch_latency_count is 0 after test traffic, verify Slack env is loaded by opa-api-8001.

## Trigger Test Traffic

```bash
curl -s -N -X POST "$API_BASE_URL/evaluate/bulk/stream" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/postman_payload.json | tail -n 1
```

## Loki Log Search

```bash
# List discovered systemd units in Loki labels
curl -sG "$LOKI_BASE_URL/loki/api/v1/label/unit/values" | jq

# Last 5 minutes of API service logs
START_NS=$(date -u -d '5 minutes ago' +%s%N)
END_NS=$(date -u +%s%N)
curl -sG "$LOKI_BASE_URL/loki/api/v1/query_range" \
  --data-urlencode 'query={job="systemd-journal",unit="opa-api-8001.service"}' \
  --data-urlencode "start=$START_NS" \
  --data-urlencode "end=$END_NS" \
  --data-urlencode 'limit=20' | jq

# Filter only ERROR lines from API logs
curl -sG "$LOKI_BASE_URL/loki/api/v1/query_range" \
  --data-urlencode 'query={job="systemd-journal",unit="opa-api-8001.service"} |= "error"' \
  --data-urlencode "start=$START_NS" \
  --data-urlencode "end=$END_NS" \
  --data-urlencode 'limit=20' | jq
```

## Grafana Dashboards

### Ops Metrics Dashboard

URL: http://127.0.0.1:3000/d/firewall-policy-api-slo-alerts/firewall-policy-api-core-monitoring

Displays: Request volume, latency (p95), deny rates, audit metrics, standards compliance failures.

### Live ROI Tracking Dashboard

URL: http://127.0.0.1:3000/d/opa-rules-live-roi/opa-rules-live-roi-tracking

Displays: live rules processed, HIPS freed, hours saved, cost saved, and ROI trend lines.

### Sync Commands

**Sync all dashboards (ops + ROI) in one bundle:**

```bash
bash deploy/monitoring/sync_grafana_dashboards_bundle.sh
```

**With explicit backup location:**

```bash
bash deploy/monitoring/sync_grafana_dashboards_bundle.sh --backup-dir /tmp/firewall-sync-backups
```

**With dry-run preview:**

```bash
bash deploy/monitoring/sync_grafana_dashboards_bundle.sh --dry-run
```

**Validate dashboard JSON integrity (parse + schema + uid/title uniqueness + query text):**

```bash
python3 tools/validate_grafana_dashboards.py
```

**Sync individual dashboards:**

Ops metrics only:
```bash
bash deploy/monitoring/sync_grafana_dashboard.sh \
  --source deploy/monitoring/grafana/firewall-api-observability-dashboard.json \
  --target /var/lib/grafana/dashboards/firewall-api-core-monitoring.json
```

Live ROI dashboard only:
```bash
bash deploy/monitoring/sync_grafana_dashboard.sh \
  --source deploy/monitoring/grafana/opa-roi-live-dashboard.json \
  --target /var/lib/grafana/dashboards/opa-roi-live-dashboard.json
```

### Full Monitoring Stack Sync

Run all monitoring sync operations in one command (Alertmanager + Grafana dashboards + Loki stack):

```bash
bash deploy/monitoring/sync_monitoring_bundle.sh
```

With optional bundle manifest output:

```bash
bash deploy/monitoring/sync_monitoring_bundle.sh --manifest-file /tmp/firewall-sync-bundle.csv
```

With dry-run preview:

```bash
bash deploy/monitoring/sync_monitoring_bundle.sh --dry-run
```

Sync Alertmanager config from repo to host path:

bash deploy/monitoring/sync_alertmanager_config.sh

Optional explicit backup location:

bash deploy/monitoring/sync_alertmanager_config.sh --backup-dir /tmp/firewall-sync-backups

Optional explicit manifest output:

bash deploy/monitoring/sync_alertmanager_config.sh --manifest-file /tmp/firewall-sync-alertmanager.csv

Install and sync Loki + Promtail + Grafana Loki datasource:

bash deploy/monitoring/install_loki_stack.sh

Resync Loki stack configs after edits:

bash deploy/monitoring/sync_loki_stack.sh

Optional explicit backup location:

bash deploy/monitoring/sync_loki_stack.sh --backup-dir /tmp/firewall-sync-backups

Optional explicit manifest output:

bash deploy/monitoring/sync_loki_stack.sh --manifest-file /tmp/firewall-sync-loki.csv

All sync scripts now create a pre-change backup and auto-rollback if apply/restart fails.
All sync scripts now also run fail-fast preflight checks for required commands and emit a checksum manifest.

If panels do not refresh after changes:

1. Hard refresh browser.
2. Run dashboard sync: bash deploy/monitoring/sync_grafana_dashboard.sh
3. Confirm provisioned file exists: /var/lib/grafana/dashboards/firewall-api-core-monitoring.json
