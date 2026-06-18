# Firewall Policy API Monitoring Runbook

This runbook maps each shipped monitoring alert to triage steps and first remediation actions.

For fast daily checks and copy/paste command snippets, use `deploy/monitoring/QUICK_OPS.md`.

## Endpoint Baseline

Use the monitored API instance for all checks unless your environment differs.

```bash
API_BASE_URL="http://127.0.0.1:8001"
```

When dashboard JSON changes in this repo, sync it into Grafana provisioning with:

```bash
bash deploy/monitoring/sync_grafana_dashboard.sh
```

When Alertmanager config changes in this repo, sync it with:

```bash
bash deploy/monitoring/sync_alertmanager_config.sh
```

When Loki/Promtail config changes in this repo, sync log stack with:

```bash
bash deploy/monitoring/sync_loki_stack.sh
```

If calling through Nginx ingress with auth enabled, include your API key header:

```bash
curl -s -H "X-API-Key: $FIREWALL_API_KEY" "https://<host>/health"
```

## Monthly Drill Script

Use the bundled drill helper to validate monitoring surfaces and generate a small
synthetic traffic burst for dashboard movement.

```bash
python3 tools/run_alert_drill.py \
  --base-url "$API_BASE_URL" \
  --generate-traffic 20 \
  --wait-after-traffic 15
```

## New Operator Utilities

These commands condense the new ops helpers into one surface:

```bash
python3 tools/ops_kit.py snapshot --unit opa-api-8001.service
python3 tools/ops_kit.py watchdog --unit opa-api-8001.service
python3 tools/ops_kit.py verify-drift
python3 tools/ops_kit.py runbook --topic auto
python3 tools/ops_kit.py timeline
```

Use `--json` on any subcommand when you want to attach the output to a ticket.

If auth is enabled, pass a token:

```bash
python3 tools/run_alert_drill.py \
  --base-url "$API_BASE_URL" \
  --token "$FIREWALL_API_TOKEN"
```

## Scheduled GitHub Action Drill

Workflow: `.github/workflows/monitoring-drill.yml`

- Schedule: monthly on day 1 at 06:00 UTC
- Manual trigger: `workflow_dispatch` with optional base URL override
- Artifact: uploads `monitoring-drill-output.txt` for every run

Required GitHub configuration:

- Secret: `FIREWALL_API_BASE_URL` (non-prod target URL)
- Secret: `FIREWALL_API_TOKEN` (optional, only if auth is enabled)

Optional repository variables:

- `MONITORING_DRILL_GENERATE_TRAFFIC` (default `20`)
- `MONITORING_DRILL_WAIT_AFTER_TRAFFIC` (default `15`)

## Quick Triage (all alerts)

Run the post-deploy smoke check bundle first:

```bash
bash tools/smoke_monitoring.sh 18.170.45.5
```

This validates:

- `/health` via Nginx/TLS
- `/grafana/login` via Nginx subpath routing
- Prometheus `firewall-api-roi` target status

1. Check current alert state:

```bash
curl -s "$API_BASE_URL/metrics/alerts" | jq
```

1. Check service health:

```bash
curl -s "$API_BASE_URL/health" | jq
```

1. Check systemd and recent logs:

```bash
systemctl status opa-api-8001.service --no-pager
journalctl -u opa-api-8001.service -n 200 --no-pager
```

1. Check Loki/Promtail readiness and recent log visibility:

```bash
curl -s http://127.0.0.1:3100/ready
curl -s http://127.0.0.1:9080/ready

START_NS=$(date -u -d '10 minutes ago' +%s%N)
END_NS=$(date -u +%s%N)
curl -sG 'http://127.0.0.1:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="systemd-journal",unit="opa-api-8001.service"}' \
  --data-urlencode "start=$START_NS" \
  --data-urlencode "end=$END_NS" \
  --data-urlencode 'limit=20' | jq
```

## Loki Log Triage Shortcuts

Use these LogQL patterns in Grafana Explore (Loki datasource) or Loki HTTP API:

- API service logs:
  `{job="systemd-journal",unit="opa-api-8001.service"}`
- Error-focused API logs:
  `{job="systemd-journal",unit="opa-api-8001.service"} |= "error"`
- OPA availability signals:
  `{job="systemd-journal",unit="opa-api-8001.service"} |= "opa"`
- Prometheus scrape failures:
  `{job="systemd-journal",unit="prometheus.service"} |= "error"`
- Promtail shipping failures:
  `{job="systemd-journal",unit="promtail.service"} |= "error sending batch"`

1. Check Prometheus view of the metrics:

```bash
curl -s "$API_BASE_URL/metrics/slo?format=prometheus" | head -n 120
curl -s "$API_BASE_URL/metrics/alerts?format=prometheus" | head -n 120

# verify Prometheus scrape target is the monitored instance
curl -s 'http://127.0.0.1:9090/api/v1/targets' | jq '.data.activeTargets[] | {job: .labels.job, scrapeUrl: .scrapeUrl, health: .health}'
```

## Alert Mapping

## Alertmanager Inhibition Behavior

To reduce noise during incidents, Alertmanager inhibition is configured so that:

- Any `warning` or `info` alert for `firewall-policy-api` is suppressed while a `critical` alert for the same service is firing.
- `FirewallAlertEngineWarning` is explicitly suppressed while `FirewallAlertEngineCritical` is firing.

If you need to see all suppressed alerts during an incident review, temporarily disable inhibition in `deploy/monitoring/alertmanager.yml` and reload Alertmanager.

## FirewallApiErrorRateHigh

Trigger:

- `firewall:request_error_rate_5m > 0.02` for 5 minutes.

Likely causes:

- OPA endpoint failures/timeouts.
- Bad upstream payloads causing server exceptions.
- Transient infrastructure/network faults.

Triage:

```bash
# confirm current error-rate metrics
curl -s "$API_BASE_URL/metrics/slo" | jq '.error_rate, .requests_error, .requests_total'

# inspect recent 5xx in app logs
journalctl -u opa-api-8001.service --since '15 min ago' --no-pager | grep -E ' 50[0-9] |exception|traceback|opa'
```

Remediation:

- Restart service if in bad state: `sudo systemctl restart opa-api-8001.service`
- If OPA-related errors are present, follow `FirewallOPAUnavailable` remediation.
- If payload-related exceptions spike, rollback recent deploy and/or tighten input validation paths.

## FirewallApiLatencyP95High

Trigger:

- `firewall:latency_p95_ms_5m_max > 1500` for 10 minutes.

Likely causes:

- OPA slowness, high CPU, or saturation.
- Heavy bulk/stream traffic.
- Resource contention on host.

Triage:

```bash
curl -s "$API_BASE_URL/metrics/slo" | jq '.latency_avg_ms, .latency_p95_ms, .latency_p50_ms'

# host pressure
uptime
free -m
```

Remediation:

- Temporarily reduce load (throttle callers, postpone bulk jobs).
- Restart API and OPA services if stalled.
- Scale out API instances and split traffic if sustained.

## FirewallBulkStreamP95High

Trigger:

- `histogram_quantile(0.95, sum by (le) (rate(firewall_request_latency_seconds_bucket{endpoint="/evaluate/bulk/stream"}[5m]))) > 20` for 10 minutes.

This is a per-endpoint Histogram-driven SLO specifically for the NDJSON
streaming endpoint, which has very different latency characteristics from
the main `/evaluate` path (latency scales linearly with batch size; one
OPA call per item).

Baseline (live, including audit + decision-history disk writes):

| batch | p95     |
| ----- | ------- |
|     1 |   ~36ms |
|    10 |  ~330ms |
|    50 |   ~1.6s |
|   100 |   ~3.3s |
|   250 |   ~6.9s |
|   500 |  ~15.6s |

Throughput is essentially constant at ~30 items/sec. The 20s threshold
gives roughly 25% headroom over the 500-item baseline.

Likely causes:

- OPA decision latency has degraded (check `firewall_opa_unavailable_total`,
  CPU on the OPA process).
- Disk pressure on the audit / decision-history append path.
- Genuinely heavier traffic — large batches sustained over 10 minutes.

Triage:

```bash
# Confirm the breach and isolate the endpoint
curl -s "$API_BASE_URL/metrics" \
  | grep '^firewall_request_latency_seconds_count{endpoint="/evaluate/bulk/stream"}'

# Compare with the non-streaming path — if p95 is fine on /evaluate
# but bad on /evaluate/bulk/stream, the issue is batch-specific.
curl -s "$API_BASE_URL/metrics/slo" | jq '.latency_p95_ms'

# Disk write pressure on the audit + history append path
iostat -x 5 3
ls -la ~/.firewall-api/ /var/log/firewall-audit/ 2>/dev/null

# Reproduce in isolation (does NOT touch prod state):
python3 test-payloads/perf_test_stream.py --runs 5 --sizes 50,100,250,500
```

Remediation:

- If OPA is the bottleneck, restart OPA and re-check.
- If disk is saturated, free space or rotate audit/history.
- Throttle large-batch callers; shrink batch sizes client-side.
- For sustained legit growth, raise the threshold after re-baselining.

## FirewallOPAUnavailable

Trigger:

- `increase(firewall_opa_unavailable_total[5m]) > 0`.

Likely causes:

- OPA process down.
- OPA listener unavailable on configured host/port.
- Connectivity to OPA broken.

Triage:

```bash
curl -s "$API_BASE_URL/metrics/slo" | jq '.opa_unavailable'

# check configured OPA endpoint from environment if needed
systemctl show opa-api-8001.service --property=Environment --no-pager
```

Remediation:

- Verify OPA service status and restart if needed.
- Verify `OPA_HOST`, `OPA_PORT`, `OPA_TIMEOUT` runtime settings.
- Validate policy/data files are present and readable.

## FirewallAlertEngineCritical / FirewallAlertEngineWarning

Trigger:

- `firewall_alert_status{level="critical"} == 1` or `firewall_alert_status{level="warn"} == 1`.

Meaning:

- Aggregated alert-state summary from API thresholds is elevated.

Triage:

```bash
curl -s "$API_BASE_URL/metrics/alerts" | jq
```

Remediation:

- Resolve underlying active threshold alerts listed in `active_alerts`.
- Confirm `status` returns to `ok` after mitigation.

## FirewallSpecificThresholdBreach

Trigger:

- `firewall_alert_active == 1` with labels including `alert_id`.

Current `alert_id` values:

- `api.error-rate`
- `api.latency-p95`
- `opa.unavailable`
- `slack.dispatch-failures`
- `slack.digest-backlog`

Triage:

```bash
curl -s "$API_BASE_URL/metrics/alerts" | jq '.active_alerts'
```

Remediation:

- `api.error-rate`: Follow `FirewallApiErrorRateHigh`.
- `api.latency-p95`: Follow `FirewallApiLatencyP95High`.
- `opa.unavailable`: Follow `FirewallOPAUnavailable`.
- `slack.dispatch-failures`: verify Slack webhooks and network egress; check `/notifications/slack/metrics`.
- `slack.digest-backlog`: flush digest and verify auto-flush settings.

Digest backlog command:

```bash
curl -s -X POST "$API_BASE_URL/notifications/slack/digest/flush" | jq

## FirewallPilotKeyStale

Trigger:

- `max by (username) (firewall_pilot_key_age_days{enabled="true"}) > 90` for 1h.

Pilot API keys are the only auth artifact actually live in production
(see `policy/pilot_users.json` — the `auth.env` JWT path keeps
`AUTH_ENABLED=false`). A leaked key is valid forever unless rotated, so
the 90-day threshold matches AWS IAM credential rotation guidance.

Triage:

```bash
# Confirm which user is stale and how stale
curl -s "$PROM_BASE_URL/api/v1/query?query=firewall_pilot_key_age_days" | jq

# Confirm rotated_at / created_at on the actual record
sudo -u ubuntu jq '.users[] | {username, created_at, rotated_at, enabled}' \
  /home/ubuntu/OPA-policymodule/policy/pilot_users.json
```

Remediation:

```bash
# Rotate. The raw key is printed ONCE — capture it immediately.
cd /home/ubuntu/OPA-policymodule
python3 tools/pilot_key_age.py --rotate <USERNAME>

# Distribute the new key to the consumer through the normal secure
# channel. The old key stops working as soon as the file is replaced
# (atomic rename on the JSON store). There is no grace period.

# Force the exporter to re-emit so the gauge drops to ~0d immediately
# instead of waiting for the daily 04:23 timer.
sudo systemctl start opa-api-pilot-key-age.service
```

If rotation isn't possible (e.g. consumer is unreachable), disable the
user instead — the `enabled="true"` filter in the alert will then
ignore them:

```bash
python3 - <<'PY'
from api import pilot_users
pilot_users.disable_user("<USERNAME>")
PY
```

## FirewallPilotKeyExporterStale

Trigger:

- `time() - max(firewall_pilot_key_exporter_last_run_timestamp_seconds) > 129600` (36h).

The exporter timer fires daily; 36h gives one missed run plus tolerance.
Without this alert, `FirewallPilotKeyStale` silently freezes at the last
emitted age value.

Triage:

```bash
systemctl status opa-api-pilot-key-age.timer
systemctl list-timers opa-api-pilot-key-age.timer
journalctl -u opa-api-pilot-key-age.service --since '36h ago'
```

Remediation:

```bash
# Most common cause: timer not enabled after install
sudo systemctl enable --now opa-api-pilot-key-age.timer

# Force a one-off run to refresh the metric
sudo systemctl start opa-api-pilot-key-age.service

# If the .prom file is unwritable, check the textfile dir perms:
ls -la /var/lib/prometheus/node-exporter/
```

## KPI Checks (Core Monitoring)

Use these queries to validate core dashboard signals directly in Prometheus:

```bash
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=sum(firewall_decisions_total)' | jq
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=sum(clamp_min(firewall_decisions_total - firewall_decisions_deny, 0))' | jq
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=sum(firewall_decisions_deny)' | jq
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=firewall_latency_avg_ms' | jq
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=firewall_slack_dispatch_latency_p95_ms' | jq
```

Standards-failure totals:

```bash
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=sum(firewall_failed_standard_ms_nfr_total)' | jq
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=sum(firewall_failed_standard_cis_v81_total)' | jq
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=sum(firewall_failed_standard_iso_27001_total)' | jq
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=sum(firewall_failed_standard_pci_dss_total)' | jq
```

## Troubleshooting: Slack Latency Not Moving

1. Check Slack metrics at source:

```bash
curl -s "$API_BASE_URL/notifications/slack/metrics" | jq '{dispatch_successes,dispatch_failures,dispatch_latency_count,dispatch_latency_avg_ms,last_error}'
```

1. If `dispatch_latency_count` is `0`, verify webhook env vars on monitored service and restart `opa-api-8001`.

1. Confirm Prometheus scrape values:

```bash
curl -s --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=firewall_slack_dispatch_latency_count' | jq
```
```

## Post-Incident Checklist

1. Confirm alerts are cleared:

```bash
curl -s "$API_BASE_URL/metrics/alerts" | jq '.status, .active_alerts_count'
```

1. Capture evidence:

```bash
curl -s "$API_BASE_URL/compliance/evidence?format=json&days=1&persist=true" | jq '.report_id, .generated_at'
```

1. Add incident notes to your ticket including:

- Alert name and trigger window.
- Root cause.
- Mitigation taken.
- Follow-up action to prevent recurrence.

---

## Dashboard Response Guide

This section maps each Grafana dashboard panel to ordered first-response steps.
Open the named dashboard, look at the named panel, act in order.

---

### Incident Triage Board (`firewall-incident-triage`)

Use this as your **first screen** when an alert fires.

| Panel | Green = | Red/amber = |
|-------|---------|-------------|
| Service Up | 1 = healthy | 0 → check `systemctl status opa-api-8001` |
| Metrics Stale (2m) | 0 = data flowing | 1 → check Prometheus scrape and `systemctl status promtail` |
| Error Budget Burn Fast | < 6 | ≥ 14.4 → treat as critical error-rate incident |
| OPA Timeouts (10m) | 0 | > 0 → see [FirewallOPATimeouts](#firewallOPATimeouts) |
| State Write Failures (15m) | 0 | > 0 → check disk space and `/home/ubuntu/.firewall-api/` permissions |
| API Error Rate (5m) | < 1% | > 3% → see [FirewallApiErrorRateHigh](#firewallapierrorratehigh) |

**Step-by-step:**
1. Read panels top-left to top-right. Stop at the first red.
2. If **Service Up = 0**: `systemctl restart opa-api-8001`, wait 30s, re-check.
3. If **Metrics Stale = 1**: `systemctl status prometheus loki promtail` — restart stale one.
4. If **Burn Fast ≥ 14.4**: move to core monitoring board, check error rate and latency simultaneously.
5. If **OPA Timeouts > 0**: move to OPA Performance board (below).
6. Scroll to the **API Error Logs (Loki)** panel — scan for the repeating exception pattern and note it for the ticket.

---

### Core Monitoring (`firewall-policy-api-slo-alerts`)

Confirms service-level health and ROI state integrity.

| Panel | First action |
|-------|-------------|
| Service Status | 0 → `systemctl restart opa-api-8001` |
| Error Budget Burn Fast/Slow | Elevated → check error-rate and latency panels below it |
| State Write Failures (15m) | Non-zero → `ls -la /home/ubuntu/.firewall-api/` and `df -h` |
| OPA Timeouts (10m) | Non-zero → move to OPA Performance board |
| ROI State Drift & Auto-Correct | Rising autocorrect → `curl -s $API_BASE_URL/metrics/roi \| jq` and reconcile against `wc -l policy/decision_history.jsonl` |
| Top Error Volume by Unit (Loki) | Identify unit with highest volume, check its journal |

```bash
# Quick reconciliation
curl -s http://127.0.0.1:8001/metrics | grep firewall_rules_processed_current
wc -l policy/decision_history.jsonl
```

---

### OPA Performance Deep Dive (`firewall-opa-performance`)

Use when latency or timeout signals are active.

| Panel | Threshold | Action |
|-------|-----------|--------|
| OPA p95 Single (5m) | < 500ms green, > 1000ms red | > 1000ms: check OPA server process `systemctl status opa` |
| OPA p95 Batch (5m) | < 500ms green, > 1000ms red | elevated batch but not single → batch size explosion, check caller payloads |
| OPA Timeouts (10m) | 0 = clean | any timeout → circuit breaker may open; check `firewall_opa_unavailable_total` |
| OPA Non-Success Ratio (10m) | < 1% | > 5% → OPA degraded or policy load failure |
| OPA Cache Hit Rate | > 90% = green | < 70% → cache invalidation storm? check policy file mtimes |
| OPA Cache Entries | Shows fill level | 0 at high traffic → cache disabled or cleared by restart |

**Steps for OPA degradation:**
1. `systemctl status opa` — is the OPA server process up?
2. Check OPA server logs: `journalctl -u opa -n 40 --no-pager`
3. Verify OPA responds directly: `curl -s http://127.0.0.1:8181/health | jq`
4. If OPA is healthy but latency is high, the issue is upstream (payload size, policy complexity).
5. If circuit breaker opened: wait `OPA_CB_COOLDOWN_SECONDS` (default 30s) or restart the API to reset.

```bash
# Direct OPA health check
curl -s http://127.0.0.1:8181/health | jq
# Check circuit-breaker state indirectly (non-zero = breaker events)
curl -sG 'http://127.0.0.1:9090/api/v1/query' \
  --data-urlencode 'query=firewall_opa_unavailable_total' | jq '.data.result[0].value[1]'
```

---

### Decision Quality & Policy Drift (`firewall-decision-quality-drift`)

Use when investigating behavioral regressions (policy changes, silent failures).

| Panel | What to look for |
|-------|-----------------|
| Accept Ratio (1h) | Sudden drop from baseline → policy change or data issue |
| Deny Ratio (1h) | Sudden spike → new policy rule, misconfiguration, or upstream sending invalid requests |
| Deny Rate Shift (5m vs 6h avg) | > 10% positive shift → something changed this session; correlate with Git deploy time |
| Accept vs Deny Volume | Compare absolute volumes; ratio change at low volume is less significant |
| Failed Standards Mix | Which standard suddenly increased? Identifies the control category |
| Policy/Decision Error Logs | Any `opa unavailable` or `policy` errors here mean the signal is environmental not behavioral |

**Steps for deny-rate spike:**
1. Check the shift panel value. If shift > 10%, a genuine policy change happened in last 5m.
2. Cross-reference with `Service Restarts` annotation on the timeline — did a deploy just happen?
3. Check `git log --oneline -5` for recent policy/ directory changes.
4. If rate shifted without a deploy: check for upstream payload changes using Loki logs.
5. If a specific standard spiked (e.g. ISO 27001): check which control is new or changed.

```bash
# Which standard is driving denies right now?
curl -s "$API_BASE_URL/metrics/slo?format=prometheus" | \
  grep firewall_failed_standard
# Recent policy changes
git log --oneline -5 -- policy/
```

---

## FirewallApiErrorBudgetBurnFast

**Alert meaning:** Error budget burning > 14.4x (fast window: 5m + 1h). At this rate the monthly 1% error budget is exhausted in ~2 days.

**First response:**
1. Open Incident Triage Board and read the API Error Rate panel.
2. If error rate is > 3%: follow [FirewallApiErrorRateHigh](#firewallapierrorratehigh).
3. If rate is between 1–3%: check if it's sustained using the 30m burn panel on the Core board.
4. Look at Error Logs (Loki) on the triage board for the failing endpoint.

---

## FirewallApiErrorBudgetBurnSlow

**Alert meaning:** Slow sustained burn > 6x in both 30m and 6h windows. Lower urgency but will exhaust budget in ~5 days if not addressed.

**First response:**
1. Is this persistent (several scrape cycles) or a spike? Check the timeseries on Core board.
2. Look for a correlated service restart annotation on the same timeline.
3. If persistent: treat like a low-severity [FirewallApiErrorRateHigh](#firewallapierrorratehigh).

---

## FirewallOPATimeouts

**Alert meaning:** OPA HTTP timeouts detected in the last 10 minutes.

**First response:**
1. Open OPA Performance board → check p95 single/batch panels.
2. `curl -s http://127.0.0.1:8181/health | jq` — OPA process healthy?
3. If OPA is healthy but timing out: check `OPA_TIMEOUT` env var; default is 30s, large batches at 500 items can push close to this.
4. If OPA process is down: `systemctl restart opa`, monitor for 2m.

---

## FirewallOPALatencyP95High

**Alert meaning:** OPA p95 > 1000ms for 10 minutes. Policy evaluations are consistently slow.

**First response:**
1. Open OPA Performance board → compare single vs batch p95.
2. If batch p95 elevated, single p95 ok → callers are sending large batches; no OPA fault.
3. If single p95 elevated → OPA server is slow. Check CPU/memory on the host: `top -b -n1 | head -20`.
4. If elevated after a policy reload: the new policy is more complex. Review recent `policy/` changes.
