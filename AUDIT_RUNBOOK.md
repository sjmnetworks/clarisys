# Firewall Audit Feature Runbook

## Overview

The audit feature provides an immutable, append-only trail of all policy evaluation decisions, along with file-import compliance reporting (CSV, XLSX, Juniper JSON/XML). It serves both operational accountability (who evaluated what, when) and governance (proving compliance with standards during audits).

### Three Components

1. **Audit Trail** — Immutable per-request log of evaluations (compliance evidence)
2. **Decision History** — Structured JSON record of accept/deny verdicts (for ROI analysis and drift detection)
3. **Audit Import Reports** — Bulk file upload that evaluates multiple rules and generates compliance reports/artifacts

---

## Architecture

### Audit Trail

Every evaluation endpoint records a lightweight event to an append-only sink:

```json
{
  "request_id": "abc123def456",
  "endpoint": "/evaluate",
  "caller_sub": "user@example.com",
  "payload_summary": {
    "source": "10.1.1.1",
    "destination": "10.2.2.2",
    "protocol": "tcp",
    "port": 443
  },
  "verdict_summary": {
    "verdict": "DENY",
    "overall_status": "NON-COMPLIANT",
    "failed_controls": ["CIS-v81-4.1", "ISO-27001-A.12.4.1"],
    "failed_standards": ["CIS v8.1", "ISO 27001"]
  },
  "elapsed_ms": 142,
  "timestamp": "2026-06-15T10:45:23.456Z"
}
```

#### Backends (Environment: `AUDIT_BACKEND`)

| Backend | Best For | Config |
|---------|----------|--------|
| `local` (default) | Dev, on-prem, local testing | `AUDIT_DIR=/var/log/firewall-audit` |
| `s3` | Production, immutable cloud storage | `AUDIT_S3_BUCKET=my-audit-bucket` + boto3 |
| `noop` | Unit tests only | `AUDIT_BACKEND=noop` |

#### Local Backend (`AUDIT_BACKEND=local`)

- Appends JSONL records to `AUDIT_DIR/<UTC-date>.jsonl`
- Default location: `/var/log/firewall-audit/` (fallback: `~/.firewall-api/audit/`)
- Thread-safe via OS append-mode guarantee on POSIX
- **Retention:** Configure via OS/filesystem (e.g., systemd timer, logrotate, btrfs snapshots)

#### S3 Backend (`AUDIT_BACKEND=s3`)

- Each record → one S3 object: `<prefix>/<UTC-date>/<request_id>.json`
- Optional Object Lock (WORM) for immutability
- Requires `boto3` (lazy-imported, not in base dependencies)
- Configuration:
  ```bash
  export AUDIT_BACKEND=s3
  export AUDIT_S3_BUCKET=audit-bucket-name
  export AUDIT_S3_PREFIX=firewall-api  # optional
  export AUDIT_S3_OBJECT_LOCK_MODE=GOVERNANCE  # optional: GOVERNANCE, COMPLIANCE
  export AUDIT_S3_RETAIN_DAYS=7  # optional
  export AWS_REGION=eu-west-1
  ```

### Decision History

Parallel to the audit trail, accepted/denied verdicts are recorded to `policy/decision_history.jsonl` for:
- ROI metrics (rules processed, cost savings)
- Drift detection (re-evaluate past decisions if policy changes)
- Historical context during investigation

**NOT recorded:**
- Synthetic canary probes (x-monitoring-synthetic header)
- Health check endpoints

### Audit Import Reports

Use audit import endpoints to bulk-evaluate firewall exports and generate markdown/HTML reports and cleaned artifacts.

**Endpoints supported:**

- `POST /audit/csv` (CSV request body, markdown report)
- `POST /audit/csv/html` (CSV multipart upload, HTML report)
- `POST /audit/csv/cleaned` (CSV multipart upload, cleaned CSV/JSON)
- `POST /audit/xlsx` (XLSX multipart upload, HTML report)
- `POST /audit/xlsx/cleaned` (XLSX multipart upload, cleaned CSV/JSON)
- `POST /audit/json/html` (Juniper SRX `.json` or `.xml` upload, HTML report)
- `POST /audit/json/cleaned` (Juniper SRX `.json` or `.xml` upload, cleaned CSV/JSON)

**Input formats supported:**

#### Raw traffic (headers: source, destination, protocol, port, etc.)
```csv
source,destination,protocol,port,log,data_classification
10.1.1.1,10.2.2.2,tcp,443,all,Internal
10.3.3.3,10.4.4.4,udp,53,critical,Internal
```

#### Intake (headers: app_id, source_name, destination_name, protocol, destination_port, environment, etc.)
```csv
app_id,source_name,destination_name,protocol,destination_port,environment
app-auth,frontend-lb,auth-service,tcp,9000,production
app-orders,orders-api,payment-gateway,tcp,443,production
```

#### Juniper SRX JSON/XML

- Native SRX zone-policy exports (`.json` or `.xml`)
- Extracted fields include: zone pair, source-address, destination-address, and permit/deny action

---

## Configuration

### Environment Variables

```bash
# Audit trail backend and path
export AUDIT_BACKEND=local              # or: s3, noop
export AUDIT_DIR=/var/log/firewall-audit

# S3 backend (if AUDIT_BACKEND=s3)
export AUDIT_S3_BUCKET=my-audit-bucket
export AUDIT_S3_PREFIX=firewall-api
export AUDIT_S3_OBJECT_LOCK_MODE=GOVERNANCE  # optional
export AUDIT_S3_RETAIN_DAYS=7                # optional

# Decision history (separate file, for ROI)
export DECISION_HISTORY_FILE=policy/decision_history.jsonl

# Auth: who can use audit import endpoints?
export AUTH_ENABLED=true
export FIREWALL_AUDIT_SCOPE=firewall.audit
```

### File Permissions (Local Backend)

```bash
# Audit directory
ls -ld /var/log/firewall-audit/
# Expected: drwx------ root root (or app:app if running as app user)

# Current day's file
ls -la /var/log/firewall-audit/audit-2026-06-15.jsonl
# Expected: -rw-r--r-- app app
```

---

## Usage

### Public Audit UI

The user-facing upload form is published at:

```text
https://13.43.195.150/firewall-audit-ui/
```

The page is public so users can load it without authenticating through nginx. Actual uploads from that form still require a valid `X-API-Key`; submissions without one are rejected by the backend.

### 1. Single Request Audit

Every call to `/evaluate`, `/evaluate/bulk`, `/evaluate/bulk/stream`, `/intake/evaluate`, etc. is automatically recorded.

```bash
curl -X POST http://127.0.0.1:8001/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "10.1.1.1",
    "destination": "10.2.2.2",
    "protocol": "tcp",
    "port": 443
  }'

# Automatically recorded to:
# /var/log/firewall-audit/audit-2026-06-15.jsonl
```

### 2. Bulk Audit Import Report

Upload firewall policy files to evaluate many rules at once and get compliance reports/artifacts.

```bash
# Create CSV
cat > rules.csv <<EOF
source,destination,protocol,port,log
10.1.1.1,10.2.2.2,tcp,443,all
10.3.3.3,10.4.4.4,tcp,22,critical
EOF

# Submit to /audit/csv
curl -X POST https://<host>/audit/csv \
  -H "X-API-Key: <key>" \
  -H 'Content-Type: text/csv' \
  --data-binary @rules.csv \
  > compliance-report.md

# View report
cat compliance-report.md
```

**Response format:** Markdown report with:
- Summary (total rules, acceptable, denied, invalid rows)
- Failed standards breakdown
- Failed controls breakdown
- Per-rule findings with verdict and violations

For interactive browser-based uploads, direct users to `https://13.43.195.150/firewall-audit-ui/` rather than the internal backend path. The page is public, but every file submission still needs a valid API key.

#### HTML report from XLSX

```bash
curl -X POST https://<host>/audit/xlsx \
  -H "X-API-Key: <key>" \
  -F 'file=@firewall_policy.xlsx' \
  -o compliance-report.html
```

#### HTML report from Juniper XML

```bash
curl -X POST https://<host>/audit/json/html \
  -H "X-API-Key: <key>" \
  -F 'file=@deploy/srx policies.xml;type=application/xml' \
  -o compliance-report.html
```

#### Cleaned artifact (CSV) from Juniper JSON/XML

```bash
curl -X POST 'https://<host>/audit/json/cleaned?format=csv' \
  -H "X-API-Key: <key>" \
  -F 'file=@deploy/srx policies.xml;type=application/xml' \
  -o cleaned-rules.csv
```

### 3. Query Audit Trail

#### List today's audit records
```bash
jq '.' /var/log/firewall-audit/audit-2026-06-15.jsonl | head -20
```

#### Search for a specific request
```bash
grep '"request_id":"abc123"' /var/log/firewall-audit/audit-*.jsonl
```

#### Count decisions by endpoint
```bash
jq -s 'group_by(.endpoint) | map({endpoint: .[0].endpoint, count: length})' \
  /var/log/firewall-audit/audit-2026-06-15.jsonl
```

#### Find all denials
```bash
jq 'select(.verdict_summary.verdict == "DENY")' \
  /var/log/firewall-audit/audit-*.jsonl
```

---

## Monitoring & Troubleshooting

### Check Audit Trail Health

```bash
# Verify audit directory exists and is writable
ls -ld /var/log/firewall-audit/

# Check today's file
ls -lh /var/log/firewall-audit/audit-$(date -u +%Y-%m-%d).jsonl

# Count records written today
wc -l /var/log/firewall-audit/audit-$(date -u +%Y-%m-%d).jsonl
```

### Audit Path Writable Check

The API runs a startup check to ensure the audit path is writable. If it fails:

```bash
# Check logs
journalctl -u opa-api-8001 --no-pager | grep audit

# Expected output on success:
# audit_path_writable_check: True
```

### Disk Space Issues

If audit disk usage is high:

```bash
# Check disk usage
du -sh /var/log/firewall-audit/

# List files by date
ls -lh /var/log/firewall-audit/ | tail -20

# Compress old files (keep recent 7 days)
find /var/log/firewall-audit/ -name 'audit-*.jsonl' -mtime +7 -exec gzip {} \;

# Or delete (if retention is not a compliance requirement)
find /var/log/firewall-audit/ -name 'audit-*.jsonl' -mtime +30 -delete
```

### S3 Backend Diagnostics

```bash
# Verify S3 bucket and credentials
aws s3 ls s3://$AUDIT_S3_BUCKET/ --region $AWS_REGION

# Check recent audit objects
aws s3 ls s3://$AUDIT_S3_BUCKET/$AUDIT_S3_PREFIX/ \
  --region $AWS_REGION \
  --recursive | tail -20

# Test write (manual)
echo '{"test": "record"}' | aws s3 cp - \
  s3://$AUDIT_S3_BUCKET/$AUDIT_S3_PREFIX/test.json
```

### Common Issues

| Issue | Symptom | Fix |
|-------|---------|-----|
| Audit path not writable | API startup fails; logs show `PermissionError` | `chmod 0700 /var/log/firewall-audit/` or set `AUDIT_DIR` to a writable path |
| Disk full | Audit writes hang; requests timeout | Rotate/delete old audit files or expand disk |
| S3 credentials invalid | API logs boto3 auth errors | Verify `AWS_REGION`, IAM role, or credentials |
| Audit import upload fails | 400/415 response | Check file extension and endpoint match (`csv`, `xlsx`, or Juniper `json/xml`) |
| Import contains invalid rows | Report shows "Invalid rows: N" | Review the "Invalid rows" section in report; fix source file and re-submit |

---

## Operations

### Retention Policy

**Recommended:**
- Local backend: Keep 90 days (rotate via logrotate or systemd timer)
- S3 backend: Enable Object Lock + set retention to 7 years (compliance requirement)

#### Logrotate Configuration (Local)

```bash
# /etc/logrotate.d/firewall-audit
/var/log/firewall-audit/*.jsonl {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 app app
    sharedscripts
}
```

#### Systemd Timer (Local)

```ini
# /etc/systemd/system/firewall-audit-rotate.timer
[Unit]
Description=Daily rotation of firewall audit logs

[Timer]
OnCalendar=daily
OnBootSec=10min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# /etc/systemd/system/firewall-audit-rotate.service
[Unit]
Description=Rotate firewall audit logs

[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/log/firewall-audit/ -name 'audit-*.jsonl' -mtime +90 -delete
```

### Backup & Recovery (Local)

```bash
# Backup recent audit files
tar -czf firewall-audit-$(date -u +%Y%m%d).tar.gz \
  /var/log/firewall-audit/audit-*.jsonl

# Restore
tar -xzf firewall-audit-20260615.tar.gz -C /

# Verify integrity (count records before/after)
jq -s length firewall-audit-20260615.jsonl
```

### Audit Trail Export

Export audit for external systems (SIEM, compliance platform):

```bash
# Daily JSON export
jq -s '.' /var/log/firewall-audit/audit-$(date -u +%Y-%m-%d).jsonl \
  > audit-export-$(date -u +%Y-%m-%d).json

# Push to external system
curl -X POST https://siem.example.com/ingest \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  --data-binary @audit-export-$(date -u +%Y-%m-%d).json
```

### Audit Trail Analysis

#### Approve/deny ratio by day
```bash
for f in /var/log/firewall-audit/audit-*.jsonl; do
  echo "=== $(basename $f) ==="
  jq -s 'group_by(.verdict_summary.verdict) | map({verdict: .[0].verdict_summary.verdict, count: length})' "$f"
done
```

#### Busiest endpoint
```bash
jq -s 'group_by(.endpoint) | map({endpoint: .[0].endpoint, count: length}) | sort_by(-.count) | .[0:5]' \
  /var/log/firewall-audit/audit-*.jsonl
```

#### Top callers
```bash
jq -s 'group_by(.caller_sub) | map({caller: .[0].caller_sub, count: length}) | sort_by(-.count) | .[0:10]' \
  /var/log/firewall-audit/audit-*.jsonl
```

---

## Best Practices

1. **Immutability First**
   - Use S3 with Object Lock for production
   - Local backend should live on a read-only or WORM volume

2. **Rotate Regularly**
   - Compress audit files older than 7 days
   - Archive to cold storage after 90 days

3. **Monitor Disk Space**
   - Set up alerting on `/var/log/firewall-audit/` usage
   - Pre-emptively rotate before reaching 80% capacity

4. **Separate Concerns**
   - Audit trail (this feature) = evidence of evaluation
   - Decision history (policy/decision_history.jsonl) = ROI metrics
   - Don't mix retention policies

5. **Test CSV Uploads**
   - Validate CSV format locally before uploading
   - Start with small batches (10 rules) to test

6. **Exclude Synthetic Traffic**
   - Canary probes have `x-monitoring-synthetic: true` header
   - They are excluded from decision counters automatically
   - But still appear in audit trail if audit is enabled

---

## Examples

### Example 1: Post-Deployment Audit

After deploying a new firewall rule, audit existing estate to check for drift:

```bash
# Export current rules as CSV
firewall export-rules > current-rules.csv

# Evaluate against policy
curl -X POST https://<host>/audit/csv \
  -H "X-API-Key: <key>" \
  -H 'Content-Type: text/csv' \
  --data-binary @current-rules.csv \
  > drift-report.md

# Review non-compliant rules in report
grep -A 10 "^## Denied rules" drift-report.md
```

### Example 2: Compliance Investigation

A rule was denied. Find all details:

```bash
# Find in audit trail
RULE_ID="10.1.1.1-10.2.2.2-tcp-443"
jq "select(.payload_summary | contains({source: \"10.1.1.1\"}))" \
  /var/log/firewall-audit/audit-*.jsonl | head -5

# Find in decision history (for drift context)
grep '"source":"10.1.1.1"' policy/decision_history.jsonl | jq '.'
```

### Example 3: Automated Daily Report

Scheduled job to generate daily compliance summary:

```bash
#!/bin/bash
# /usr/local/bin/daily-audit-summary.sh

DATE=$(date -u +%Y-%m-%d)
AUDIT_FILE="/var/log/firewall-audit/audit-${DATE}.jsonl"

if [[ ! -f "$AUDIT_FILE" ]]; then
  echo "No audit file for $DATE"
  exit 1
fi

# Count by verdict
echo "=== Daily Audit Summary ($DATE) ==="
echo "Total decisions: $(wc -l < "$AUDIT_FILE")"
echo "Denials: $(grep -c 'DENY' "$AUDIT_FILE")"
echo "Acceptances: $(grep -c 'ACCEPTABLE' "$AUDIT_FILE")"

# Top failed standards
echo ""
echo "=== Top Failed Standards ==="
jq -s 'flatten | map(.verdict_summary.failed_standards // []) | flatten | group_by(.) | map({standard: .[0], count: length}) | sort_by(-.count) | .[0:5]' "$AUDIT_FILE" | jq '.'
```

---

## Support

For issues with the audit feature:

1. Check the logs: `journalctl -u opa-api-8001 --no-pager | grep audit`
2. Verify disk and permissions: `ls -ld /var/log/firewall-audit/`
3. Test manually: `curl http://127.0.0.1:8001/health`
4. Review this runbook's troubleshooting section

For S3 backend issues, also check AWS IAM, KMS (if Object Lock), and region configuration.
