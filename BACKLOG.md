# Reliability / observability backlog

Living log of reliability and observability work on this codebase.
Items are appended in the order they shipped (or, for open items, in the
order they were proposed). Each closed item links to its commit.

The newest entries are at the bottom.

---

## Closed: 2026-06-10

### 1. Audit store path resilience — `8e06548`
Default `/var/log/firewall-audit` falls back to `~/.firewall-api/audit/`
with stderr warning when unwritable; explicit `AUDIT_DIR` re-raises.
+5 tests.

### 2. JSON state-file atomicity — `a5ac605`
Shipped `api/atomic_io.py:atomic_write_json()` (temp + fsync +
`os.replace`). Replaced 4 call sites (ROI, Slack, SLO, decision
lifecycle). +8 tests.

### 3. Health endpoint enhancements — `08a6ef0`
`/health?verbose=true` returns `opa_cache` + `decision_history` + `slo` +
`slack` sub-blocks, each independently fault-isolated. Default `/health`
stays minimal so liveness probe semantics are preserved.

---

## Closed: 2026-06-11

### 4. Install opa-api-watchdog timer
Units copied to `/etc/systemd/system/`, `/etc/opa-api/ops-kit.env`
populated (reused existing `SLACK_HIGH_PRIORITY_WEBHOOK_URLS` from
`slack.env`), timer enabled.

### 5. State-drift reconciliation at startup — `905b2c1`
`_load_state()` now compares disk snapshot against history-derived
count; when `|delta| >= max(5, 10% of history)` it increments
`firewall_roi_state_drift_total{direction=...}` and logs
`roi.state_drift_detected`. Caught a real 22-vs-505 desync.

### 6. Slack failure surfaced in `/health?verbose=true` — `905b2c1`
Verbose health emits `warnings: ["slack.recent_failure"]` when
`slack.last_error_at` is within
`HEALTH_SLACK_RECENT_FAILURE_WINDOW_SECONDS` (default 900s). Default
`/health` and the `status` field stay untouched.

### 7. Atomic-write sweep — `905b2c1`
Found one production-state writer using temp+rename without fsync
(`api/pilot_users.py:_save()`); migrated to `atomic_write_json`. Other
`json.dump` sites are debug/snapshot outputs.

### O1. Auto-correct extreme ROI drift — `96879d7`
When `|delta| / max(history, 1) >= 0.5` at bootstrap, `_load_state()`
rebuilds from `_bootstrap_from_history()` instead of trusting the
obviously-stale snapshot. Increments
`firewall_roi_state_drift_autocorrect_total{direction=...}`.

### O2. Grafana drift panel — `eec0a14`
"ROI State Drift & Auto-Correct (Cumulative)" added to core monitoring
dashboard. Auto-correct series rendered red.

### O3. Watchdog forensics auto-attach — `96879d7`
`tools/ops_kit.py` writes
`~/.firewall-api/forensics/watchdog-<ts>-<unit>.json` (systemd
properties + diagnosis + journal tail + `/metrics` dump) before posting
a Slack alert. Skipped on dedup. +5 tests.

### O4. Prometheus alerts on drift counters — `407c9e3`
Two new alerts in `deploy/monitoring/firewall-rules.yml`:
- `FirewallROIStateDriftAutocorrect` (warning, fires on any increase).
- `FirewallROIStateDriftElevated` (info, fires when low-grade drift
  happens >=3 times in 24h).

### O5. Nginx security headers on 401 paths — `407c9e3`
App middleware already set STS/nosniff/DENY/Referrer-Policy on proxied
2xx; the nginx 401 path (no API key) had no security headers because
of nginx's `add_header` inheritance quirk. Added them inside each
`if ($opa_api_key_valid != 1)` block. Repo's `deploy/nginx-opa-api.conf`
was out of date and was resynced to live.

### O6. ROI undercount fix — `120fb5f`
Four endpoints wrote to history but never called
`record_rule_processed`, silently undercounting ROI. Fixed for
`/evaluate/bulk` + 3 intake variants. Also fixed Bug 2:
`_bootstrap_from_history` now clears `_SEEN_REQUEST_IDS`. Live
reconciled 725 vs 725. +4 tests.

### O7. Watchdog liveness metrics — `3b9937a`
Watchdog writes a textfile-collector `.prom` on every run. Two new
Prom alerts: `FirewallWatchdogStale` (timestamp_seconds stale > 15min)
and `FirewallWatchdogReportsUnhealthy` (gauge==0). Repo
`prometheus.yml` resynced from live and node-exporter scrape job
added. +4 tests.

### O8. ROI dashboard inconsistency — `8a8e36e`
"Rules Processed" panel was reading
`sum(firewall_rules_processed_total)` (labelled Counter, resets on
restart) while HIPS/cost/FTE panels read bootstrapped Gauges. Showed
10 rules vs £742k saved on the same dashboard. Added
`firewall_rules_processed_current` Gauge mirroring `_METRICS_STATE`.
+1 test.

### O9. Decision-history daily backup — `5647be3`
gzip+retention backup tool, sandboxed systemd service+timer (daily
03:17 UTC), SHA-based no-op skip, textfile-collector `.prom`, two
Prom alerts (stale > 36h, failing). +9 tests.

### O10. pip-audit CVE gate in CI — `325b69c`
CI runs `pip-audit` against the resolved venv on every PR and push.
Baseline scan caught 11 CVEs:
- pyjwt 2.12.1 → 2.13.0 (PYSEC-2026-175/177/178/179)
- starlette 1.0.0 → 1.0.1 (PYSEC-2026-161, transitive via fastapi)
- 5 pip-itself CVEs ignored (build tool, not shipped at runtime).

Floors locked in `api/requirements.txt` and asserted by
`tests/test_requirements_constraints.py` so a future contributor can't
silently relax them. +2 tests.

### O11. ROI dashboard responds to time picker
- The dashboard's time picker was decorative: every stat panel used
  `lastNotNull` on cumulative gauges, so changing "Last 24h" to "Last
  7 days" had zero effect.
- **Top row** ("Selected Range") now uses
  `current - min_over_time(current[$__range])` — derives the windowed
  delta from a single monotonic gauge. Cold-start safe: while the
  metric is younger than the window you simply see lifetime accrual.
  All four panels (rules / HIPS / hours / cost) use the *same* base
  expression, so they can never disagree again.
- **Bottom row** ("Lifetime Totals") preserves the unwindowed view for
  board decks.
- Live verified: 5 evaluations → range delta = 5 rules, £5,048.40 cost
  (= 5 × £1,009.68). Dashboard synced via
  `deploy/monitoring/sync_grafana_dashboard.sh`.

### O12. Test isolation for stateful artifacts
- Discovered: `pytest` was contaminating production state. The bulk
  ROI regression tests post through `TestClient` with no isolation,
  so each run appended ~7 synthetic rules to
  `~/.firewall-api/roi-metrics.json` and
  `policy/decision_history.jsonl` (the same files the live service
  reads).
- Fixed: `tests/conftest.py` rewrites `ROI_METRICS_STATE_FILE`,
  `DECISION_HISTORY_FILE`, `DECISION_LIFECYCLE_FILE`, and `AUDIT_DIR`
  to a per-session `tmpdir` *before* the first `import api.*` (module
  constants are resolved at import time).
- Regression-guarded by `tests/test_state_isolation.py`: if a future
  conftest change breaks the redirect, the test fails loudly rather
  than silently re-contaminating prod.
- E2E proof: full 213-test suite run; SHA of
  `policy/decision_history.jsonl` and `~/.firewall-api/roi-metrics.json`
  unchanged before vs after; live `firewall_rules_processed_current`
  stayed at 0.

### O13. Prometheus full reset to zero
- Stopped `prometheus` and `opa-api-8001`.
- Wiped `/var/lib/prometheus/metrics2/*` and the
  textfile-collector `.prom` files in
  `/var/lib/prometheus/node-exporter/`.
- Removed `~/.firewall-api/roi-metrics.json` and rotated
  `policy/decision_history.jsonl` to
  `policy/decision_history.jsonl.scrubbed.<UTC-ts>`.
- Reversible: full backup at `/var/backups/opa-scrub-<UTC-ts>/`
  (TSDB + node-exporter + ~/.firewall-api + decision_history snapshot).

### F. Bulk-stream NDJSON p95 SLO + alert
- Added `firewall_request_latency_seconds` Histogram (labelled by
  route template) in `api/roi_metrics.py`. Recorded from the request
  middleware in `api/main.py` after `_record_slo`. Server-side
  `histogram_quantile` lets Prometheus compute correct windowed
  quantiles by endpoint without re-implementing the math in-process.
- Live bench (test-payloads/perf_test_stream.py, prod-shaped writes):
  size=1 p95 36ms; 10 → 330ms; 50 → 1.6s; 100 → 3.3s; 250 → 6.9s;
  500 → 15.6s. Throughput ~30 items/s constant (one OPA call/item).
- Alert `FirewallBulkStreamP95High`: fires when p95 > 20s for 10min
  (~25% headroom over the 500-item baseline). Prom now loads 25 rules
  (was 24); validated with `promtool check rules` before reload.
- Tests: +3 (Histogram registered, observed per endpoint, label uses
  route template not URL — bounds cardinality).

### O14. Bench scripts no longer pollute prod state
- `test-payloads/perf_test_stream.py` and `test-payloads/perf_test.py`
  now spawn an isolated uvicorn instance by default, with every
  state-bearing path (`FIREWALL_API_STATE_DIR`, `ROI_METRICS_STATE_FILE`,
  `DECISION_HISTORY_FILE`, `DECISION_LIFECYCLE_FILE`, `SLO_STATE_FILE`,
  `AUDIT_DIR`, `EVIDENCE_DIR`) redirected into a tempdir. Hitting prod
  is now an explicit opt-in: `--target-existing URL` or `--url URL`.
- This was needed because the F-bench against the live 8001 service
  added 9165 fake rules / £9.25M / 192k pseudo-HIPS to prod ROI before
  the prod state was scrubbed a second time.
- Regression test `tests/test_bench_isolation.py` (+4 tests) locks the
  contract: scripts with a non-None URL default fail the test, and any
  state env var omitted from the spawn helper fails the test. Suite
  220 tests.

### G. Pilot API key age tracking + rotation tooling
**Item G was originally framed as "audit-encryption key rotation cron".
That framing is wrong**: `api/audit_encryption.py` and
`api/request_signing.py` are dead code — they have unit tests but
neither is imported by `api/main.py` or `api/audit_store.py`, and
`AUDIT_ENCRYPTION_ENABLED` is not set in `/etc/opa-api/`. Building a
rotation cron for a feature that isn't wired into the runtime would
be security theatre. See "Lessons learned" #9.

The actual live secret that rotates is the pilot API key in
`policy/pilot_users.json`, which had no age tracking and no
rotation tooling. Shipped:
- `tools/pilot_key_age.py` (--export | --rotate USERNAME). Export mode
  writes `firewall_pilot_key_age_days{username,enabled}` to the
  node-exporter textfile-collector. Rotate mode uses
  `secrets.token_urlsafe(32)`, sets `rotated_at`, prints raw key once.
  Atomic write to `pilot_users.json` (temp + fsync + os.replace).
  Reimplements `atomic_write_json` locally to avoid importing
  `api.*` (which would resolve module-level prod paths).
- `deploy/opa-api-pilot-key-age.{service,timer}` — sandboxed
  (ProtectSystem=strict, ReadOnlyPaths=policy/,
  ReadWritePaths=textfile dir only). Daily 04:23 UTC, offset from the
  03:17 decision-history-backup timer.
- Alert `FirewallPilotKeyStale`: enabled key > 90d for 1h.
- Alert `FirewallPilotKeyExporterStale`: timer hasn't refreshed metric
  in 36h (one missed run + tolerance). Without it,
  `FirewallPilotKeyStale` silently freezes at the last value.
- Tests: +7 (exporter renders age, prefers `rotated_at`, skips users
  without timestamps, emits enabled/disabled counts, escapes
  Prom-special chars in usernames; rotation updates hash + sets
  `rotated_at` + leaves `created_at`; unknown user errors without
  writing). Suite 227.
- Live verification: 27 Prom rules loaded (was 25); textfile written;
  `johnata` (live enabled key) showing 24.1d, well under threshold.

### O15. Fix slo.state_save_failed errors and test-isolation gap — `85b2be6`
- **Root cause**: Tests were writing to production state files
  (`/home/ubuntu/.firewall-api/slo-metrics.json`,
  `slack-state.json`) because `conftest.py` wasn't rerouting
  `SLO_STATE_FILE`, `SLACK_STATE_FILE`, and `EVIDENCE_DIR` to
  tmpdir before imports. When the live API's `/metrics/alerts`
  endpoint wrote SLO state, concurrent test writes caused
  permission/conflict errors in `atomic_write_json()`.
- **Same bug as O14**: Lesson #6 says "the redirect must happen
  in conftest *before* any `import api.*`". Item O14 fixed bench
  scripts; this fixes the test suite itself.
- **Fixes**:
  1. Enhanced `api/atomic_io.py` error handling: wrap `open(tmp)`,
     `os.replace()`, and `mkdir()` with contextual OSError messages
     so future failures show "cannot write to X: Y" instead of
     cryptic "No such file or directory" at replace stage. Add type
     check for Path argument.
  2. Updated `tests/conftest.py`: added missing state files
     (`SLO_STATE_FILE`, `SLACK_STATE_FILE`, `EVIDENCE_DIR`) to env
     reroutes list. Create `evidence/` tmpdir. Added regression test
     that validates all required state env vars are isolated
     *before* any test runs — if a future change breaks isolation,
     the test fails loudly rather than silently re-contaminating
     prod.
- **Verification**: No `slo.state_save_failed` errors in journalctl
  for 1+ hour; `/metrics/alerts` and `/metrics/slo` endpoints
  returning 200 OK consistently.
- **Lesson #10**: When adding a new state file in `main.py`, it
  must be enumerated in `conftest.py` *before* imports. The
  regression test prevents this from drifting again.

---

## Still open (not started)

Backlog clear for the reliability / observability thread.

### Closed after handoff (2026-06-12)
- `7226fb1` Deleted unwired dead-code modules `api/audit_encryption.py`
  and `api/request_signing.py` plus their tests. This resolved the last
  stale "open dead-code question" from the previous session.
- `5ef71c6` Added synthetic canary probe (`tools/canary_probe.py`),
  Prometheus alerts (`FirewallCanaryFailed`, `FirewallCanaryStale`),
  and incident-triage dashboard panels.

### Next candidates (future work)
Request-rate/backpressure visibility, security posture dashboard, and
weekly reliability export have all shipped (`236c78e`, `e967818`).

1. Grafana annotation delivery hardening
   - Add retry/backoff coverage tests for `tools/post_grafana_annotation.py`
     and tune retry defaults from live behavior.
2. Weekly reliability report contract tests
   - Lock report schema + key PromQL query outputs so report changes are
     intentional and reviewable.
3. Dashboard drift guard in CI
   - Add a lightweight check that provisioned Grafana JSON artifacts stay
     syntactically valid and internally consistent before merge.
4. React frontend (Vite + React in `frontend/`)
   - Replace Jinja templates with a proper SPA.
   - Accounts & authentication (login, registration, session management).
   - Role-based views (admin vs auditor vs read-only).
   - Interactive results dashboard (filter/sort violations, drill into rules).
   - Historical audit comparisons / trend charts.
   - Serve as static assets from FastAPI (`/app` → `frontend/dist/`).

---

## Lessons learned

These are the patterns that bit us repeatedly. Apply preemptively in
new code.

1. **ROI accounting requires explicit `record_rule_processed` calls
   per endpoint.** Writing a row to `decision_history.jsonl` is *not*
   sufficient — that's the audit trail, not the counter.

2. **`_bootstrap_from_history` must clear `_SEEN_REQUEST_IDS`.**
   Composite bulk/stream keys (`request_id:item_index`) are not
   recoverable from the history file alone, so any rebuild must reset
   the dedup set.

3. **Two metrics with two semantics on one dashboard = permanent
   inconsistency.** When a Counter and a Gauge represent "the same
   thing" but reset/persist differently, picking one for the panel
   doesn't fix the underlying split — derive everything from one
   source of truth.

4. **systemd `ProtectSystem=strict` + `PrivateTmp` works fine** as
   long as `ReadWritePaths` whitelists the target dirs.

5. **`pip-audit` against the resolved venv catches transitive CVEs**
   that auditing only `requirements.txt` would miss (e.g.
   `fastapi → starlette 1.0.0`).

6. **Tests using `TestClient` mutate prod state by default.** Module
   constants (`ROI_METRICS_STATE_FILE`, `_history_path()`'s env-var
   fallback) are resolved at import time, so the redirect must happen
   in a `conftest.py` *before* any `import api.*` runs.

7. **Time pickers on Grafana stat panels are decorative** unless
   the expression is windowed. `lastNotNull` on a cumulative gauge
   ignores the picker entirely. Use
   `metric - min_over_time(metric[$__range])` for cold-start-safe
   windowed deltas on monotonic gauges.

8. **Bench scripts that default to a live URL silently corrupt prod
   state.** A `default="http://127.0.0.1:8001"` on a `--url` flag
   means `python perf_test.py` (no flags) will write thousands of
   synthetic accept verdicts into the live ROI counters and audit
   trail. The fix is to default to `None` and have the script spawn
   its own isolated uvicorn with state env vars pointed at a tempdir;
   hitting prod must be an explicit opt-in. `tests/test_bench_isolation.py`
   guards this.

9. **A backlog item that names a feature is not the same as a backlog
   item that names a risk.** Item G was originally "audit-encryption
   key rotation cron" — but `api/audit_encryption.py` and
   `api/request_signing.py` aren't imported by `main.py` or
   `audit_store.py`, and `AUDIT_ENCRYPTION_ENABLED` is unset on the
   host. Building rotation infrastructure for unwired code is
   theatre. Before shipping, verify the runtime path actually
   imports the module: `grep -rE 'from api.<mod>|import api.<mod>'`
   in the live entrypoints. The real risk in production was unrotated
   pilot keys in `policy/pilot_users.json`, which is what G actually
   shipped against.

10. **State env vars in conftest must stay exhaustive.** A new state
    file in `main.py` (e.g. `SLO_STATE_FILE`) is invisible to tests
    unless it's explicitly rerouted in `conftest.py` *before* imports.
    Missing one var = tests pollute prod. Item O15 fixed this by
    (a) adding a regression test to validate all *_FILE/*_DIR vars are
    isolated, and (b) explicitly listing them at the top of conftest.
    When refactoring state management, audit conftest for drift.
