# Firewall Policy API - Production Release Checklist

Use this checklist immediately before and after each production release.

## Automated Gate (recommended)

Run this first to execute the core release probes automatically:

```bash
python3 tools/release_gate_check.py \
  --base-url http://127.0.0.1:8000
```

Capture a machine-readable gate result for CI artifacts or change records:

```bash
python3 tools/release_gate_check.py \
  --base-url http://127.0.0.1:8000 \
  --output-json /tmp/firewall-release-gate.json
```

Use retry/backoff for transient network or startup jitter:

```bash
python3 tools/release_gate_check.py \
  --base-url http://127.0.0.1:8000 \
  --retries 2 \
  --initial-backoff-seconds 0.75
```

If auth is enabled:

```bash
python3 tools/release_gate_check.py \
  --base-url http://127.0.0.1:8000 \
  --token "$FIREWALL_API_TOKEN"
```

Use stricter/looser thresholds if needed:

```bash
python3 tools/release_gate_check.py \
  --base-url http://127.0.0.1:8000 \
  --max-error-rate 0.01 \
  --max-latency-p95-ms 1200 \
  --max-opa-unavailable 0 \
  --max-slack-dispatch-failures 0
```

## Preconditions

- [ ] Change ticket approved and linked to release.
- [ ] Release notes prepared (features, risks, rollback owner).
- [ ] On-call engineer and approver assigned.
- [ ] Deployment window confirmed.

## Pre-Deploy Checks (T-30 to T-5 min)

### Service and dependency health

- [ ] API health endpoint responds.

```bash
curl -s 'http://127.0.0.1:8000/health' | jq
```

- [ ] SLO snapshot is reachable and readable.

```bash
curl -s 'http://127.0.0.1:8000/metrics/slo' | jq
```

- [ ] Alerts snapshot is reachable.

```bash
curl -s 'http://127.0.0.1:8000/metrics/alerts' | jq
```

### Monitoring and alerting readiness

- [ ] Prometheus scrape endpoints return Prometheus text.

```bash
curl -s 'http://127.0.0.1:8000/metrics/slo?format=prometheus' | head -n 40
curl -s 'http://127.0.0.1:8000/metrics/alerts?format=prometheus' | head -n 60
```

- [ ] Alertmanager route config is current and receiver destination is valid.
- [ ] Grafana dashboard loads and panels update (SLO + alert health).

### Persistence and notification readiness

- [ ] Evidence archive path writable.

```bash
test -w "${EVIDENCE_DIR:-/tmp/firewall-evidence}" && echo 'evidence dir writable'
```

- [ ] Slack metrics endpoint reachable and no sustained failures.

```bash
curl -s 'http://127.0.0.1:8000/notifications/slack/metrics' | jq
```

## Deploy Execution (T0)

- [ ] Deploy new version.
- [ ] Confirm service restarted cleanly.

```bash
systemctl status opa-api.service --no-pager
journalctl -u opa-api.service -n 100 --no-pager
```

## Post-Deploy Validation (T+1 to T+15 min)

### Functional smoke checks

- [ ] Single evaluate request returns `ACCEPTABLE` or `DENY` without 5xx.
- [ ] Bulk or stream endpoint responds for a small test payload.

### Operational checks

- [ ] Error rate remains below threshold.
- [ ] p95 latency stays within expected range.
- [ ] No new OPA unavailable increments.
- [ ] No persistent Slack dispatch failures.

```bash
curl -s 'http://127.0.0.1:8000/metrics/slo' | jq '{error_rate, latency_p95_ms, opa_unavailable, active_alerts_count}'
curl -s 'http://127.0.0.1:8000/metrics/alerts' | jq '{status, active_alerts_count, active_alerts}'
```

### Evidence and governance checks

- [ ] Generate and persist one evidence report.

```bash
curl -s 'http://127.0.0.1:8000/compliance/evidence?format=json&days=1&persist=true' | jq
```

- [ ] Retrieve recent archive list includes new report.

```bash
curl -s 'http://127.0.0.1:8000/compliance/evidence/archive?limit=5&days=7' | jq
```

## Release Decision

- [ ] If all checks pass, mark release successful and close deployment task.
- [ ] If any rollback trigger is hit, execute rollback immediately per `deploy/monitoring/ROLLBACK_TRIGGERS.md`.
