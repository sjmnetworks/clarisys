# OPA Policy Module - M&S Security Standards Evaluation API

FastAPI service backed by Open Policy Agent (OPA) for evaluating proposed firewall and network rules against:

- M&S NFR
- ISO 27001
- CIS Controls v8.1
- PCI-DSS

The API supports single request evaluation, bulk evaluation, streaming bulk evaluation, intake workflows, compliance evidence export, decision lifecycle management, and Slack notification operations.

## What It Does

- Evaluates proposed traffic changes against policy-as-code rules.
- Returns structured verdicts with risk, failed controls, and remediation context.
- Stores decision history and lifecycle state.
- Emits Slack notifications with routing, deduplication, digesting, and metrics.
- Produces compliance evidence reports and CSV-driven audit reports.

## Quick Start

### Prerequisites

- Python 3.11+
- OPA binary available (`opa`)

### Local run

```bash
python3 -m venv .venv
.venv/bin/pip install -r api/requirements.txt
./start_api.sh
```

Default API base URL: `http://127.0.0.1:8000`

Operational monitoring note:

- The monitored instance used by Prometheus/Grafana runs on `http://127.0.0.1:8001`.
- Nginx ingress (`https://<host>`) is routed to the monitored 8001 instance.
- If ingress auth is enabled, include `X-API-Key: <key>` in calls through Nginx.

- Swagger UI: `/docs` (non-production)
- OpenAPI: `/openapi.json` (non-production)

## Authentication and Scopes

When auth is enabled, endpoints require scopes (bearer token or pilot API key depending on mode).

Primary scopes used by this API:

- `firewall.evaluate` for evaluation and read operations.
- `firewall.audit` for audit import endpoints (`/audit/csv*`, `/audit/xlsx*`, `/audit/json*`, `/audit/ui`).
- `firewall.ops` for Slack notification operations endpoints.

Auth behavior is configured via `AUTH_*` environment variables.

## Request Modes

### Raw evaluation mode

Uses direct traffic fields such as `source`, `destination`, `protocol`, `port`, `log`, and optional standards metadata.

### Intake evaluation mode

Uses CMDB/logical fields such as `app_id`, `source_name`, `destination_name`, `destination_port`, and business context fields.

## Endpoint Reference

### Evaluation

- `POST /evaluate`
- `POST /evaluate/bulk` (1-500 items)
- `POST /evaluate/bulk/stream` (1-5000 items, NDJSON stream)
- `POST /evaluate/explain`

### Intake

- `POST /intake/evaluate`
- `POST /intake/evaluate/bulk` (1-500 items)
- `POST /intake/evaluate/bulk/stream` (1-5000 items, NDJSON stream)

### Decisions and Governance

- `GET /decisions/history`
- `GET /decisions/lifecycle/{decision_id}`
- `PUT /decisions/lifecycle/{decision_id}`
- `POST /decisions/drift/recheck`

### Compliance

- `GET /compliance/coverage`
- `GET /compliance/evidence`
- `GET /compliance/evidence/archive`
- `GET /compliance/evidence/archive/{report_id}`

### Operational Metrics and Cache

- `GET /metrics/slo`
- `GET /metrics/alerts`
- `GET /cache/stats`
- `POST /cache/clear`

### Slack Notification Operations

- `GET /notifications/slack/metrics`
- `POST /notifications/slack/metrics/reset`
- `POST /notifications/slack/digest/flush`

### Health and Metadata

- `GET /health`
- `GET /rules/summary`
- `GET /policy/metadata`

### Operations Helpers

- `python3 tools/ops_kit.py snapshot`
- `python3 tools/ops_kit.py watchdog`
- `python3 tools/ops_kit.py verify-drift`
- `python3 tools/ops_kit.py runbook`
- `python3 tools/ops_kit.py timeline`
- `python3 tools/release_gate_check.py`

### Audit Import

- `POST /audit/csv`
- `POST /audit/csv/html` - Upload CSV as multipart and receive HTML compliance report
- `POST /audit/csv/cleaned` - Upload CSV and download normalized cleaned artifact (CSV or JSON)
- `POST /audit/xlsx` - Upload XLSX firewall policy files for compliance auditing
- `POST /audit/xlsx/cleaned` - Upload XLSX and download normalized cleaned artifact (CSV or JSON)
- `POST /audit/json/html` - Upload Juniper SRX `.json` or `.xml` and receive HTML compliance report
- `POST /audit/json/cleaned` - Upload Juniper SRX `.json` or `.xml` and download normalized cleaned artifact (CSV or JSON)
- `GET /audit/ui` - Backend route serving the compliance audit upload form

## Firewall Compliance Audit

The audit upload endpoints evaluate firewall policy exports (Fortinet, Palo Alto, or standard schema) against M&S security standards and generate professional HTML compliance reports with risk status indicators.

### Using the Web Upload UI

Navigate to the HTTPS audit endpoint to upload firewall policies:

```
https://13.43.195.150/firewall-audit-ui/
```

The page is intentionally public so users can open the form directly in a browser. Every submission from that page still requires a valid `X-API-Key`, and the backend enforces the `firewall.audit` permission on each upload.

Features:
- Drag-and-drop or file picker for XLSX, CSV, JSON, and XML firewall policy exports
- Real-time compliance evaluation against M&S security standards
- HTML report generation with M&S professional branding
- Direct Palo Alto security-rule CSV support (native export headers)
- Direct Juniper SRX JSON/XML policy export support
- **RAG Status Badges**: Red/Amber/Green visual risk indicators for each evaluated rule
  - 🟢 **GREEN** - LOW risk
  - 🟡 **AMBER** - MEDIUM risk
  - 🔴 **RED** - HIGH/CRITICAL risk
- Downloadable HTML report with violation details and remediation context
- Optional cleaned normalized artifact download in CSV or JSON

### Programmatic Audit via API

```bash
curl -X POST https://<host>/audit/xlsx \
  -H "X-API-Key: <your-api-key>" \
  -F "file=@firewall_policy.xlsx" \
  -o compliance_report.html
```

Request headers:
- `X-API-Key` (required if auth is enabled) - Audit scope required

Response headers:
- `X-Audit-Acceptable` - Count of rules that passed compliance
- `X-Audit-Denied` - Count of rules that failed compliance
- `X-Audit-Invalid-Rows` - Count of unparseable rows

Response body: HTML compliance report (displayable in browser, downloadable as .html file)

### Supported Firewall Formats

- **Fortinet Fortigate**: Exports with source/destination/protocol/port/action columns
- **Palo Alto**: Native security-rule CSV export columns (`Source Zone`, `Source Address`, `Destination Zone`, `Destination Address`, `Application`, `Service`, `Action`, `Options`)
- **Juniper SRX**: Native policy exports in JSON (`.json`) and XML (`.xml`) zone-policy structures
- **Standard Schema**: Custom XLSX or CSV with compliant raw/intake column naming
- **Standard Schema**: Custom XLSX or CSV with compliant raw/intake column naming

## Streaming Endpoints

### `POST /evaluate/bulk/stream`

Evaluates up to 5000 raw requests and streams NDJSON lines:

- `{"type":"verdict","data":...}` for each evaluated item
- Final summary line: `{"type":"summary","data":...}`

Example:

```bash
curl -N -X POST http://127.0.0.1:8000/evaluate/bulk/stream \
  -H 'Content-Type: application/json' \
  -d '{
    "requests": [
      {
        "source": "10.157.26.5",
        "destination": "10.221.126.33",
        "protocol": "tcp",
        "port": 443,
        "log": "all",
        "source_interface": "finance-src",
        "destination_interface": "analytics-dst"
      }
    ]
  }'
```

### `POST /intake/evaluate/bulk/stream`

Uses the same streaming pattern for intake payloads (up to 5000 items).

## API Cookbook

Set a base URL once and reuse it:

```bash
BASE_URL='http://127.0.0.1:8000'
```

### 1) Single evaluate (`/evaluate`)

```bash
curl -s -X POST "$BASE_URL/evaluate" \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "10.157.26.5",
    "destination": "10.221.126.33",
    "protocol": "tcp",
    "port": 443,
    "log": "all",
    "action": "allow",
    "source_interface": "finance-src",
    "destination_interface": "analytics-dst"
  }' | jq
```

### 2) Bulk evaluate (`/evaluate/bulk`)

```bash
curl -s -X POST "$BASE_URL/evaluate/bulk" \
  -H 'Content-Type: application/json' \
  -d '{
    "requests": [
      {
        "source": "10.157.26.5",
        "destination": "10.221.126.33",
        "protocol": "tcp",
        "port": 443,
        "log": "all",
        "action": "allow"
      },
      {
        "source": "10.157.26.5",
        "destination": "8.8.8.8",
        "protocol": "tcp",
        "port": 22,
        "log": "disable",
        "action": "allow"
      }
    ]
  }' | jq
```

### 3) Intake bulk stream (`/intake/evaluate/bulk/stream`)

```bash
curl -N -X POST "$BASE_URL/intake/evaluate/bulk/stream" \
  -H 'Content-Type: application/json' \
  -d '{
    "requests": [
      {
        "app_id": "APP-1234",
        "portfolio": "finance",
        "environment": "prod",
        "requested_by": "alice@example.com",
        "expires_at": "2026-12-31T23:59:59Z",
        "project_reference": "CHG-7890",
        "source_name": "finance-api",
        "destination_name": "analytics-db",
        "destination_port": 5432,
        "protocol": "tcp",
        "action": "allow",
        "business_justification": "Nightly reporting pipeline"
      }
    ]
  }'
```

### 4) Compliance evidence query (`/compliance/evidence`)

```bash
curl -s "$BASE_URL/compliance/evidence?framework=PCI-DSS&status=non_compliant&limit=20" | jq
```

### 5) Decision lifecycle update (`/decisions/lifecycle/{decision_id}`)

```bash
DECISION_ID='replace-with-real-decision-id'

curl -s -X PUT "$BASE_URL/decisions/lifecycle/$DECISION_ID" \
  -H 'Content-Type: application/json' \
  -d '{
    "state": "implemented",
    "notes": "Rule deployed in firewall change window CHG-7890",
    "actor": "netops-automation"
  }' | jq
```

## Slack Notifications

Decision notifications include top-level rule headers:

- Source network
- Destination network
- Protocol
- Port
- Rule fingerprint (stable short hash from rule tuple)

Denied and non-compliant decisions include the top 3 normalized unique remediations.

### Slack routing and format

- `SLACK_WEBHOOK_URLS=https://hooks.slack.com/services/...`
- `SLACK_HIGH_PRIORITY_WEBHOOK_URLS=https://hooks.slack.com/services/...` (HIGH and CRITICAL)
- `SLACK_LOW_PRIORITY_WEBHOOK_URLS=https://hooks.slack.com/services/...` (LOW and MEDIUM)
- `SLACK_API_BASE_URL=https://api.example.com` (adds deep links)
- `SLACK_MESSAGE_FORMAT=verbose` (`verbose` or `compact`)

### Slack dedup and state persistence

- `SLACK_DEDUP_WINDOW_SECONDS=300`
- `SLACK_STATE_FILE=/tmp/opa-slack-state.json`

### Slack policy controls

- `SLACK_SEND_ONLY_DENY=false`
- `SLACK_REALTIME_MIN_RISK=LOW` (LOW, MEDIUM, HIGH, CRITICAL)
- `SLACK_MAX_ALERTS_PER_MINUTE=0` (0 disables cap)

### Slack digest mode

- `SLACK_DIGEST_MODE=true|false`
- `SLACK_DIGEST_WINDOW_SECONDS=3600`
- `SLACK_DIGEST_AUTO_FLUSH=true`
- `SLACK_DIGEST_FLUSH_INTERVAL_SECONDS=30`

Manual flush:

```bash
curl -s -X POST "$BASE_URL/notifications/slack/digest/flush"
```

## Slack Metrics

`GET /notifications/slack/metrics` returns counters and active config snapshot, including:

- `decision_notifications_sent`
- `batch_notifications_sent`
- `digest_notifications_sent`
- `digest_items_buffered`
- `notifications_dedup_suppressed`
- `dispatch_successes`
- `dispatch_failures`
- `policy_suppressed`
- `rate_limited`
- `last_error`
- `last_error_at`
- `dedup_window_seconds`
- `dedup_cache_active_keys`
- `digest_mode`
- `digest_window_seconds`
- `send_only_deny`
- `realtime_min_risk`
- `max_alerts_per_minute`
- `message_format`
- `state_file`

Reset metrics:

```bash
curl -s -X POST "$BASE_URL/notifications/slack/metrics/reset?clear_dedup_cache=true"
```

## SLO Alerting

`GET /metrics/alerts` returns evaluated alert state across API and Slack delivery signals.
`GET /metrics/slo` and `GET /metrics/alerts` both support `format=prometheus` for scrape-friendly output.

Default alert checks:

- API error rate
- API p95 latency
- OPA unavailable counter
- Slack dispatch failures
- Slack digest backlog

Response shape includes:

- `status` (`ok`, `warn`, `critical`)
- `active_alerts_count`
- `active_alerts[]`
- `thresholds`

`GET /metrics/slo` now also includes `active_alerts_count` for quick dashboard rollups.

Example:

```bash
curl -s "$BASE_URL/metrics/alerts" | jq
```

Prometheus examples:

```bash
curl -s "$BASE_URL/metrics/slo?format=prometheus"
curl -s "$BASE_URL/metrics/alerts?format=prometheus"
```

Slack dispatch latency metrics are exported in `/metrics/slo?format=prometheus`:

- `firewall_slack_dispatch_latency_count`
- `firewall_slack_dispatch_latency_avg_ms`
- `firewall_slack_dispatch_latency_p50_ms`
- `firewall_slack_dispatch_latency_p95_ms`
- `firewall_slack_dispatch_latency_max_ms`
- `firewall_slack_dispatch_latency_last_ms`

Quick query examples:

```bash
curl -s "$BASE_URL/metrics/slo?format=prometheus" | grep 'firewall_slack_dispatch_latency_'
```

### Prometheus, Alertmanager, and Loki Starter Pack

Repository starter configs are provided in `deploy/monitoring`:

- `deploy/monitoring/prometheus.yml`
- `deploy/monitoring/firewall-rules.yml`
- `deploy/monitoring/alertmanager.yml`
- `deploy/monitoring/loki-config.yml`
- `deploy/monitoring/promtail-config.yml`
- `deploy/monitoring/grafana/loki-datasource.yml`
- `deploy/monitoring/grafana/firewall-api-observability-dashboard.json`
- `deploy/monitoring/RUNBOOK.md`
- `deploy/monitoring/QUICK_OPS.md`
- `deploy/monitoring/RELEASE_CHECKLIST.md`
- `deploy/monitoring/ROLLBACK_TRIGGERS.md`
- `deploy/monitoring/install_loki_stack.sh`
- `deploy/monitoring/sync_loki_stack.sh`
- `tools/run_alert_drill.py`
- `tools/release_gate_check.py`
- `.github/workflows/monitoring-drill.yml`

These include:

- scrape jobs for `/metrics/slo?format=prometheus` and `/metrics/alerts?format=prometheus`
- fast scrape/evaluation cadence for near-real-time dashboard updates
- recording rules for request error rate, request volume, deny rate, and p95 latency
- alert rules for high error rate, high latency, OPA unavailability, and active threshold breaches
- sample Alertmanager routes for warning vs critical notifications
- Loki log storage plus Promtail journald ingestion for API/monitoring services
- a Grafana dashboard for API SLO, accepted/denied totals, Slack response times, mean latency, and standards-failure totals
- an on-call runbook mapping alerts to triage and remediation steps
- a release-time production readiness checklist
- a rollback trigger matrix with threshold-driven actions
- one-command install/sync helpers for Loki and Grafana datasource provisioning
- a non-prod drill helper script for recurring monitoring validation
- an automated release gate checker that exits non-zero on failed probes
- a scheduled monthly GitHub Action drill with artifact output

Quick start:

```bash
# 1) Run Prometheus with the provided config
prometheus --config.file=deploy/monitoring/prometheus.yml

# 2) Run Alertmanager with the provided config
alertmanager --config.file=deploy/monitoring/alertmanager.yml
```

Important:

- Replace the sample webhook receivers in `deploy/monitoring/alertmanager.yml` with your real paging destination.
- If API auth is enabled, configure bearer token auth in the Prometheus scrape jobs.

Grafana import:

1. Open Grafana and go to Dashboards -> Import.
2. Upload `deploy/monitoring/grafana/firewall-api-observability-dashboard.json`.
3. Select your Prometheus datasource when prompted (`DS_PROMETHEUS`).

GitHub Action drill setup:

1. Set repository secret `FIREWALL_API_BASE_URL` (non-prod API URL).
2. Optionally set secret `FIREWALL_API_TOKEN` if auth is enabled.
3. (Optional) set vars `MONITORING_DRILL_GENERATE_TRAFFIC` and `MONITORING_DRILL_WAIT_AFTER_TRAFFIC`.
4. Trigger `.github/workflows/monitoring-drill.yml` manually once to validate setup.

Alert tuning environment variables:

- `SLO_ALERT_ERROR_RATE_THRESHOLD` (default `0.02`)
- `SLO_ALERT_P95_MS_THRESHOLD` (default `1500`)
- `SLO_ALERT_OPA_UNAVAILABLE_THRESHOLD` (default `1`)
- `SLO_ALERT_SLACK_FAILURES_THRESHOLD` (default `1`)
- `SLO_ALERT_DIGEST_BACKLOG_THRESHOLD` (default `100`)

### Core Monitoring Queries (Minimal Set)

For your requested core signals, use these PromQL queries:

- OPA requests in via API (request throughput):
  `firewall:request_volume_rps_5m`

- OPA requests in via API (last 5m total):
  `firewall:requests_total_5m`

- Accepted rules total:
  `sum(clamp_min(firewall_decisions_total - firewall_decisions_deny, 0))`

- Denied rules total:
  `sum(firewall_decisions_deny)`

- Accepted rules in last 5m:
  `firewall:decisions_accepted_5m`

- Denied rules in last 5m:
  `firewall:decisions_denied_5m`

- Slack response time p95 (5m max):
  `firewall:slack_dispatch_latency_p95_ms_5m_max`

- Service status:
  `firewall:service_up` (1 = up, 0 = down)

- API mean latency (ms):
  `firewall_latency_avg_ms`

- Standards failure totals:
  `sum(firewall_failed_standard_ms_nfr_total)`
  `sum(firewall_failed_standard_cis_v81_total)`
  `sum(firewall_failed_standard_iso_27001_total)`
  `sum(firewall_failed_standard_pci_dss_total)`

Related critical alert:

- `FirewallApiScrapeDown` triggers when `firewall:service_up < 1` for 2 minutes.

## Evidence Retention Archive

`GET /compliance/evidence` now supports `persist=true|false` (default `true`).

When persistence is enabled, generated reports are archived and indexed locally for audit retrieval:

- List: `GET /compliance/evidence/archive?limit=50&days=30`
- Fetch: `GET /compliance/evidence/archive/{report_id}`

For `csv` and `markdown` responses, the generated report ID is returned as header:

- `X-Evidence-Report-Id`

Archive configuration:

- `EVIDENCE_DIR` (default `/tmp/firewall-evidence`)
- `EVIDENCE_RETENTION_DAYS` (default `365`)

## Audit Imports

Audit import supports CSV, XLSX, and Juniper SRX JSON/XML uploads.

- `POST /audit/csv`: Raw/intake CSV via request body; returns Markdown report
- `POST /audit/csv/html`: CSV multipart upload; returns HTML report
- `POST /audit/xlsx`: XLSX multipart upload; returns HTML report
- `POST /audit/json/html`: Juniper SRX JSON/XML multipart upload; returns HTML report
- `POST /audit/*/cleaned`: Returns normalized cleaned artifact (CSV or JSON)

CSV request body content types: `text/csv` or `text/plain`.
Invalid rows are reported and skipped, not fatal to valid rows.

Raw CSV columns:

```text
source,destination,protocol,port,log,action,source_interface,destination_interface,data_classification,approved_external_sharing,contract_reference,encryption_required,tls_version_minimum
```

Intake CSV columns:

```text
app_id,portfolio,environment,requested_by,expires_at,project_reference,source_name,destination_name,destination_port,protocol,action,business_justification
```

Juniper SRX upload support:

- `.json` and `.xml` policy exports
- Parsed fields: from-zone, to-zone, source-address, destination-address, permit/deny action

## Environment Variables (Core)

### App/runtime

- `APP_ENV` (`development` or `production`)
- `OPA_BINARY` (default `/usr/local/bin/opa`)
- `MAX_REQUEST_BODY_BYTES`

### OPA circuit breaker

- `OPA_CB_FAILURE_THRESHOLD`
- `OPA_CB_COOLDOWN_SECONDS`

### Risk model

- `RISK_MODEL_FILE`

### Decision history

- `DECISION_HISTORY_FILE`
- `DECISION_HISTORY_RETENTION_DAYS`

### Audit store

- `AUDIT_BACKEND` (`local`, `s3`, `noop`)
- `AUDIT_DIR` (local backend)
- `AUDIT_S3_BUCKET`
- `AUDIT_S3_PREFIX`
- `AUDIT_S3_OBJECT_LOCK_MODE`
- `AUDIT_S3_RETAIN_UNTIL`

### Policy webhook and signing

- `POLICY_WEBHOOK_URLS`
- `POLICY_SIGNING_KEY`

## Testing

```bash
.venv/bin/pytest -q tests/test_auth_and_audit.py tests/test_api.py
```

## Operational Notes

- In production, `/docs` and `/openapi.json` are disabled when `APP_ENV=production`.
- If local audit storage is not writable at startup, the app logs a warning.
- Slack operations endpoints under `/notifications/slack/*` require `firewall.ops` when auth is enabled.
- Prometheus is expected to scrape the monitored API instance (`127.0.0.1:8001`) for `/metrics/slo` and `/metrics/alerts`.
- The Grafana dashboard is file-provisioned and UI edits are disabled to prevent query drift.
