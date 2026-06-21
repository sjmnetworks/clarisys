"""Tests for auth (B) and audit-trail (D) hardening."""
from __future__ import annotations

import json
import os
import socket
import shutil
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import audit_store, auth
from api.decision_history import append_decision_history
from api import main as api_main
from api.main import OPA_BINARY, app

pytestmark = pytest.mark.skipif(
    shutil.which(OPA_BINARY) is None and not shutil.which("opa"),
    reason="OPA binary is required for endpoint tests",
)

client = TestClient(app)


@pytest.fixture()
def acceptable_request() -> dict:
    return {
        "source": "10.157.26.5",
        "destination": "10.221.126.33",
        "protocol": "tcp",
        "port": 443,
        "log": "all",
        "data_classification": "Internal",
        "source_interface": "finance-src",
        "destination_interface": "analytics-dst",
    }


# ── Auth (B) ──────────────────────────────────────────────────────────────────
def test_auth_disabled_by_default_allows_evaluate(acceptable_request: dict) -> None:
    # AUTH_ENABLED is unset / "false" so /evaluate must respond without a token.
    resp = client.post("/evaluate", json=acceptable_request)
    assert resp.status_code == 200, resp.text


def test_auth_enabled_rejects_missing_bearer(
    monkeypatch: pytest.MonkeyPatch, acceptable_request: dict
) -> None:
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_ISSUER", "https://example.test/issuer")
    monkeypatch.setenv("AUTH_AUDIENCE", "api://firewall")
    monkeypatch.setenv("AUTH_JWKS_URL", "https://example.test/jwks")
    auth.reload_settings_for_tests()
    try:
        resp = client.post("/evaluate", json=acceptable_request)
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate", "").startswith("Bearer")
    finally:
        monkeypatch.delenv("AUTH_ENABLED", raising=False)
        auth.reload_settings_for_tests()


def test_auth_enabled_rejects_token_missing_required_scope(
    monkeypatch: pytest.MonkeyPatch, acceptable_request: dict
) -> None:
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_ISSUER", "https://example.test/issuer")
    monkeypatch.setenv("AUTH_AUDIENCE", "api://firewall")
    monkeypatch.setenv("AUTH_JWKS_URL", "https://example.test/jwks")
    auth.reload_settings_for_tests()

    # Bypass real JWKS lookup: return a caller with no useful scopes.
    monkeypatch.setattr(
        auth,
        "_validate_token",
        lambda token: auth.CallerIdentity(sub="alice", scopes=frozenset({"firewall.read"}), raw_claims={}, tenant_id=""),
    )
    try:
        resp = client.post(
            "/evaluate",
            json=acceptable_request,
            headers={"Authorization": "Bearer fake.jwt.value"},
        )
        assert resp.status_code == 403
        assert "firewall.evaluate" in resp.text
    finally:
        monkeypatch.delenv("AUTH_ENABLED", raising=False)
        auth.reload_settings_for_tests()


def test_auth_enabled_accepts_token_with_required_scope(
    monkeypatch: pytest.MonkeyPatch, acceptable_request: dict
) -> None:
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_ISSUER", "https://example.test/issuer")
    monkeypatch.setenv("AUTH_AUDIENCE", "api://firewall")
    monkeypatch.setenv("AUTH_JWKS_URL", "https://example.test/jwks")
    auth.reload_settings_for_tests()

    monkeypatch.setattr(
        auth,
        "_validate_token",
        lambda token: auth.CallerIdentity(
            sub="alice",
            scopes=frozenset({"firewall.evaluate"}),
            raw_claims={},
            tenant_id="",
        ),
    )
    try:
        resp = client.post(
            "/evaluate",
            json=acceptable_request,
            headers={"Authorization": "Bearer fake.jwt.value"},
        )
        assert resp.status_code == 200, resp.text
    finally:
        monkeypatch.delenv("AUTH_ENABLED", raising=False)
        auth.reload_settings_for_tests()


# ── Audit trail (D) ───────────────────────────────────────────────────────────
def test_audit_store_records_evaluation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, acceptable_request: dict
) -> None:
    store = audit_store.LocalJsonlAuditStore(tmp_path)
    audit_store.reset_for_tests(store)
    try:
        resp = client.post("/evaluate", json=acceptable_request)
        assert resp.status_code == 200

        files = sorted(tmp_path.glob("audit-*.jsonl"))
        assert files, "expected an audit-trail file to be written"
        lines = files[-1].read_text(encoding="utf-8").strip().splitlines()
        assert lines, "expected at least one audit record"

        record = json.loads(lines[-1])
        assert record["endpoint"] == "/evaluate"
        assert record["caller_sub"] == "dev"  # auth disabled → synthetic dev caller
        assert record["payload"]["protocol"] == "tcp"
        assert record["verdict"]["verdict"] in {"ACCEPTABLE", "DENY"}
        assert isinstance(record["request_id"], str) and len(record["request_id"]) >= 16
    finally:
        audit_store.reset_for_tests(None)


def test_audit_store_records_intake_bulk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = audit_store.LocalJsonlAuditStore(tmp_path)
    audit_store.reset_for_tests(store)
    try:
        payload = {
            "requests": [
                {
                    "app_id": "ap-A1234",
                    "portfolio": "Finance & Payroll",
                    "environment": "production",
                    "requested_by": "alice@example.com",
                    "expires_at": "2027-03-01",
                    "project_reference": "CHG0012345",
                    "source_name": "payroll-app",
                    "destination_name": "hmrc-api",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "action": "ALLOW",
                    "business_justification": "Required to submit payroll data to HMRC via their API gateway.",
                }
            ]
        }
        resp = client.post("/intake/evaluate/bulk", json=payload)
        assert resp.status_code == 200, resp.text

        files = sorted(tmp_path.glob("audit-*.jsonl"))
        assert files
        record = json.loads(files[-1].read_text(encoding="utf-8").strip().splitlines()[-1])
        assert record["endpoint"] == "/intake/evaluate/bulk"
        assert record["payload"]["total"] == 1
        assert "overall_status" in record["verdict"]
    finally:
        audit_store.reset_for_tests(None)


def test_request_id_header_is_returned(acceptable_request: dict) -> None:
    resp = client.post("/evaluate", json=acceptable_request)
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-Id"), "X-Request-Id must be stamped on every response"


def test_decision_history_pruning_is_deferred_not_per_append(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify pruning is deferred to avoid O(n²) behavior on bulk appends."""
    from api import decision_history as dh
    
    history_path = Path("/tmp") / "decision-history-prune-defer-test.jsonl"
    if history_path.exists():
        history_path.unlink()
    
    monkeypatch.setenv("DECISION_HISTORY_FILE", str(history_path))
    # Set very high thresholds so pruning won't trigger during the test
    monkeypatch.setattr(dh, "_PRUNE_INTERVAL_SECONDS", 999999.0)
    monkeypatch.setattr(dh, "_PRUNE_APPEND_THRESHOLD", 999999)
    # Reset prune state so we start fresh
    monkeypatch.setattr(dh, "_PRUNE_STATE", {
        "last_prune_monotonic": 0.0,
        "appends_since_prune": 0,
    })
    
    # Track how many times the actual prune function is called
    prune_call_count = {"count": 0}
    original_prune = dh._prune_expired_entries
    def counting_prune(path):
        prune_call_count["count"] += 1
        return original_prune(path)
    monkeypatch.setattr(dh, "_prune_expired_entries", counting_prune)
    
    try:
        # First append triggers bootstrap prune (initialization)
        dh.append_decision_history({
            "request_id": "req-0",
            "endpoint": "/evaluate",
            "caller_sub": "test",
            "action_requested": "accept",
            "decision_verdict": "ACCEPTABLE",
            "overall_status": "COMPLIANT",
            "overall_risk": "LOW",
            "details": {"source": "a", "destination": "b"},
        })
        assert prune_call_count["count"] == 1, "First append should trigger bootstrap prune"
        
        # Subsequent 100 appends should NOT trigger pruning (deferred)
        for i in range(1, 101):
            dh.append_decision_history({
                "request_id": f"req-{i}",
                "endpoint": "/evaluate",
                "caller_sub": "test",
                "action_requested": "accept",
                "decision_verdict": "ACCEPTABLE",
                "overall_status": "COMPLIANT",
                "overall_risk": "LOW",
                "details": {"source": "a", "destination": "b"},
            })
        
        assert prune_call_count["count"] == 1, (
            f"Pruning should be deferred, not run per-append. "
            f"Expected 1 prune (bootstrap), got {prune_call_count['count']}"
        )
        
        # Verify all 101 entries are in the file
        lines = history_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 101, f"Expected 101 entries, got {len(lines)}"
        
        # Force prune should run regardless of thresholds
        result = dh.force_prune()
        assert result["pruned"] is True
        assert prune_call_count["count"] == 2, "force_prune() should always trigger pruning"
        assert "duration_ms" in result
        assert "bytes_freed" in result
        
        # Stats endpoint should work
        stats = dh.prune_stats()
        assert stats["retention_days"] == 548  # default max
        assert stats["prune_interval_seconds"] == 999999.0
        assert stats["prune_append_threshold"] == 999999
        assert stats["appends_since_last_prune"] == 0  # reset after force_prune
        assert stats["history_size_bytes"] > 0
        
    finally:
        monkeypatch.delenv("DECISION_HISTORY_FILE", raising=False)
        if history_path.exists():
            history_path.unlink()


def test_decision_history_pruning_triggers_after_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify pruning triggers when append count threshold is exceeded."""
    from api import decision_history as dh
    
    history_path = Path("/tmp") / "decision-history-prune-threshold-test.jsonl"
    if history_path.exists():
        history_path.unlink()
    
    monkeypatch.setenv("DECISION_HISTORY_FILE", str(history_path))
    # Set high time threshold, low append threshold
    monkeypatch.setattr(dh, "_PRUNE_INTERVAL_SECONDS", 999999.0)
    monkeypatch.setattr(dh, "_PRUNE_APPEND_THRESHOLD", 5)
    monkeypatch.setattr(dh, "_PRUNE_STATE", {
        "last_prune_monotonic": 0.0,
        "appends_since_prune": 0,
    })
    
    prune_call_count = {"count": 0}
    original_prune = dh._prune_expired_entries
    def counting_prune(path):
        prune_call_count["count"] += 1
        return original_prune(path)
    monkeypatch.setattr(dh, "_prune_expired_entries", counting_prune)
    
    try:
        # Append 12 entries; expect prune at append 0 (bootstrap) and at append 6 (threshold=5)
        for i in range(12):
            dh.append_decision_history({
                "request_id": f"req-{i}",
                "endpoint": "/evaluate",
                "caller_sub": "test",
                "action_requested": "accept",
                "decision_verdict": "ACCEPTABLE",
                "overall_status": "COMPLIANT",
                "overall_risk": "LOW",
                "details": {"source": "a", "destination": "b"},
            })
        
        # Bootstrap (1) + threshold trigger at append 6 (2) — append 12 doesn't trigger as
        # range(12) is 0..11, so appends counter reaches 5 again but doesn't trigger.
        assert prune_call_count["count"] == 2, (
            f"Expected 2 prunes (bootstrap + 1 threshold), got {prune_call_count['count']}"
        )
        
    finally:
        monkeypatch.delenv("DECISION_HISTORY_FILE", raising=False)
        if history_path.exists():
            history_path.unlink()


def test_decision_history_records_accept_and_decline(monkeypatch: pytest.MonkeyPatch) -> None:
    history_path = Path("/tmp") / "decision-history-test.jsonl"
    if history_path.exists():
        history_path.unlink()
    monkeypatch.setenv("DECISION_HISTORY_FILE", str(history_path))

    payload = {
        "requests": [
            {
                "source": "10.157.26.5",
                "destination": "10.221.126.33",
                "protocol": "tcp",
                "port": 443,
                "log": "all",
                "source_interface": "finance-src",
                "destination_interface": "analytics-dst",
                "data_classification": "Internal",
            },
            {
                "source": "10.157.26.5",
                "destination": "payment.example.com",
                "protocol": "tcp",
                "port": 80,
                "log": "no_log",
                "source_interface": "retail-src",
                "destination_interface": "payment-dst",
                "data_classification": "Confidential",
                "approved_external_sharing": True,
                "action": "deny",
                "standards": ["ISO 27001", "CIS v8.1"],
            },
        ]
    }

    try:
        resp = client.post("/evaluate/bulk", json=payload)
        assert resp.status_code == 200, resp.text

        lines = history_path.read_text(encoding="utf-8").strip().splitlines()
        # Bulk endpoint records per-rule entries (one per request in the batch)
        # plus the overall bulk decision record.
        assert len(lines) >= 2

        records = [json.loads(line) for line in lines]
        verdicts = {record["decision_verdict"] for record in records}
        assert "ACCEPTABLE" in verdicts or "DENY" in verdicts

        history_resp = client.get("/decisions/history?limit=5")
        assert history_resp.status_code == 200, history_resp.text
        body = history_resp.json()
        assert body["total"] >= 2
        assert len(body["items"]) >= 2
    finally:
        monkeypatch.delenv("DECISION_HISTORY_FILE", raising=False)
        if history_path.exists():
            history_path.unlink()


def test_decision_history_retention_capped_to_18_months(monkeypatch: pytest.MonkeyPatch) -> None:
    from api import decision_history as dh
    
    history_path = Path("/tmp") / "decision-history-retention-test.jsonl"
    if history_path.exists():
        history_path.unlink()

    monkeypatch.setenv("DECISION_HISTORY_FILE", str(history_path))
    # Intentionally larger than 18 months; module must cap it.
    monkeypatch.setenv("DECISION_HISTORY_RETENTION_DAYS", "10000")
    # Reset prune state so the bootstrap prune fires on the next append
    monkeypatch.setattr(dh, "_PRUNE_STATE", {
        "last_prune_monotonic": 0.0,
        "appends_since_prune": 0,
    })

    old_ts = (datetime.now(timezone.utc) - timedelta(days=549)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    fresh_ts = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    history_path.write_text(
        "\n".join(
            [
                json.dumps({"ts": old_ts, "decision_verdict": "DENY", "action_requested": "deny"}),
                json.dumps({"ts": fresh_ts, "decision_verdict": "ACCEPTABLE", "action_requested": "accept"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    try:
        append_decision_history(
            {
                "request_id": "req-retention",
                "endpoint": "/evaluate",
                "caller_sub": "dev",
                "action_requested": "accept",
                "decision_verdict": "ACCEPTABLE",
                "overall_status": "COMPLIANT",
                "overall_risk": "LOW",
                "details": {"source": "a", "destination": "b"},
            }
        )

        lines = history_path.read_text(encoding="utf-8").strip().splitlines()
        records = [json.loads(line) for line in lines]
        assert len(records) == 2
        assert {r.get("request_id") for r in records} == {None, "req-retention"}
        assert all(r.get("ts") != old_ts for r in records)
    finally:
        monkeypatch.delenv("DECISION_HISTORY_FILE", raising=False)
        monkeypatch.delenv("DECISION_HISTORY_RETENTION_DAYS", raising=False)
        if history_path.exists():
            history_path.unlink()


def test_policy_metadata_endpoint_exposes_hash_and_version() -> None:
    resp = client.get("/policy/metadata")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body.get("policy_version"), str) and len(body["policy_version"]) == 12
    assert isinstance(body.get("policy_hash"), str) and len(body["policy_hash"]) == 64


def test_lifecycle_and_explain_endpoints(acceptable_request: dict) -> None:
    eval_resp = client.post("/evaluate", json=acceptable_request)
    assert eval_resp.status_code == 200, eval_resp.text
    decision_id = eval_resp.json().get("decision_id")
    assert isinstance(decision_id, str)

    put_resp = client.put(
        f"/decisions/lifecycle/{decision_id}",
        json={"status": "approved", "notes": "approved by security lead"},
    )
    assert put_resp.status_code == 200, put_resp.text
    assert put_resp.json()["status"] == "approved"

    before_get_total = api_main._slo_snapshot()["requests_total"]
    get_resp = client.get(f"/decisions/lifecycle/{decision_id}")
    assert get_resp.status_code == 200, get_resp.text
    assert get_resp.json()["status"] == "approved"
    after_get_total = api_main._slo_snapshot()["requests_total"]
    assert after_get_total == before_get_total

    explain_resp = client.post("/evaluate/explain", json=acceptable_request)
    assert explain_resp.status_code == 200, explain_resp.text
    explain_body = explain_resp.json()
    assert "verdict" in explain_body
    assert "explanation" in explain_body
    assert "triggered_violations" in explain_body["explanation"]


def test_metrics_endpoints_are_excluded_from_request_totals() -> None:
    """Monitoring endpoints should not inflate API request trend counters."""
    baseline = api_main._slo_snapshot()["requests_total"]

    # Control check: a normal endpoint increments request totals.
    health_resp = client.get("/health", headers={"x-request-id": "manual-health-included"})
    assert health_resp.status_code == 200, health_resp.text
    after_health = api_main._slo_snapshot()["requests_total"]
    assert after_health == baseline + 1

    # Metrics surfaces must remain excluded even when request_id is non-test.
    for path in (
        "/metrics",
        "/metrics/slo",
        "/metrics/alerts",
        "/notifications/slack/metrics",
    ):
        resp = client.get(path, headers={"x-request-id": f"manual-metrics-{path.replace('/', '-') or 'root'}"})
        assert resp.status_code == 200, f"{path} failed: {resp.text}"

    after_metrics = api_main._slo_snapshot()["requests_total"]
    assert after_metrics == after_health


def test_synthetic_evaluate_excluded_from_dashboard_counters(
    acceptable_request: dict,
) -> None:
    """Synthetic-tagged decisions must not affect decision or ROI dashboard counters."""
    before = api_main._slo_snapshot()

    # Capture rules-processed counter before the synthetic request
    metrics_text_before = client.get("/metrics").text
    before_line = next(
        (
            line
            for line in metrics_text_before.splitlines()
            if line.startswith("firewall_rules_processed_current ")
        ),
        None,
    )
    before_value = float(before_line.split()[1]) if before_line else 0.0

    resp = client.post(
        "/evaluate",
        json=acceptable_request,
        headers={
            "x-monitoring-synthetic": "true",
            "x-request-id": "synthetic-dashboard-exclude-1",
        },
    )
    assert resp.status_code == 200, resp.text

    after = api_main._slo_snapshot()
    assert after["decisions_total"] == before["decisions_total"]
    assert after["decisions_deny"] == before["decisions_deny"]

    # Verify rules-processed counter unchanged after synthetic request
    metrics_text_after = client.get("/metrics").text
    after_line = next(
        (
            line
            for line in metrics_text_after.splitlines()
            if line.startswith("firewall_rules_processed_current ")
        ),
        None,
    )
    assert after_line is not None
    after_value = float(after_line.split()[1])
    assert after_value == before_value


def test_evidence_and_slo_endpoints() -> None:
    evidence_resp = client.get("/compliance/evidence?format=json&days=1")
    assert evidence_resp.status_code == 200, evidence_resp.text
    evidence = evidence_resp.json()
    assert "report_id" in evidence
    assert "total" in evidence
    assert "denied" in evidence

    slo_resp = client.get("/metrics/slo")
    assert slo_resp.status_code == 200, slo_resp.text
    slo = slo_resp.json()
    assert "requests_total" in slo
    assert "latency_p95_ms" in slo
    assert "active_alerts_count" in slo

    alerts_resp = client.get("/metrics/alerts")
    assert alerts_resp.status_code == 200, alerts_resp.text
    alerts = alerts_resp.json()
    assert "status" in alerts
    assert "active_alerts" in alerts
    assert "thresholds" in alerts

    slo_prom_resp = client.get("/metrics/slo?format=prometheus")
    assert slo_prom_resp.status_code == 200, slo_prom_resp.text
    assert "firewall_requests_total" in slo_prom_resp.text
    assert "firewall_latency_p95_ms" in slo_prom_resp.text
    assert "firewall_slack_dispatch_latency_p95_ms" in slo_prom_resp.text
    assert "firewall_state_write_total" in slo_prom_resp.text
    assert 'component="slo",outcome="success"' in slo_prom_resp.text
    assert 'component="slack",outcome="failure"' in slo_prom_resp.text

    roi_prom_resp = client.get("/metrics")
    assert roi_prom_resp.status_code == 200, roi_prom_resp.text
    assert "firewall_opa_requests_total" in roi_prom_resp.text
    assert "firewall_opa_request_latency_seconds" in roi_prom_resp.text
    assert "firewall_opa_timeout_total" in roi_prom_resp.text

    alerts_prom_resp = client.get("/metrics/alerts?format=prometheus")
    assert alerts_prom_resp.status_code == 200, alerts_prom_resp.text
    assert "firewall_alerts_active_count" in alerts_prom_resp.text
    assert "firewall_alert_status" in alerts_prom_resp.text

    slack_metrics_resp = client.get("/notifications/slack/metrics")
    assert slack_metrics_resp.status_code == 200, slack_metrics_resp.text
    slack_metrics = slack_metrics_resp.json()
    assert "decision_notifications_sent" in slack_metrics
    assert "batch_notifications_sent" in slack_metrics
    assert "notifications_dedup_suppressed" in slack_metrics
    assert "dispatch_successes" in slack_metrics
    assert "dispatch_failures" in slack_metrics
    assert "dedup_window_seconds" in slack_metrics
    assert "digest_mode" in slack_metrics
    assert "policy_suppressed" in slack_metrics
    assert "rate_limited" in slack_metrics
    assert "dispatch_latency_count" in slack_metrics
    assert "dispatch_latency_avg_ms" in slack_metrics
    assert "dispatch_latency_p50_ms" in slack_metrics
    assert "dispatch_latency_p95_ms" in slack_metrics


def test_evidence_archive_list_and_get(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    monkeypatch.setattr(api_main, "EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr(api_main, "EVIDENCE_INDEX_FILE", evidence_dir / "index.jsonl")
    monkeypatch.setattr(api_main, "EVIDENCE_RETENTION_DAYS", 365)

    generate_resp = client.get("/compliance/evidence?format=json&days=1&persist=true")
    assert generate_resp.status_code == 200, generate_resp.text
    report_id = generate_resp.json().get("report_id")
    assert isinstance(report_id, str) and report_id

    list_resp = client.get("/compliance/evidence/archive?limit=10&days=30")
    assert list_resp.status_code == 200, list_resp.text
    items = list_resp.json().get("items", [])
    assert any(item.get("report_id") == report_id for item in items)

    get_resp = client.get(f"/compliance/evidence/archive/{report_id}")
    assert get_resp.status_code == 200, get_resp.text
    payload = get_resp.json()
    assert payload.get("report_id") == report_id
    assert "total" in payload


def test_metrics_alerts_flags_threshold_breaches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_main, "SLO_ALERT_ERROR_RATE_THRESHOLD", 0.01)
    monkeypatch.setattr(api_main, "SLO_ALERT_P95_MS_THRESHOLD", 100)
    monkeypatch.setattr(api_main, "SLO_ALERT_OPA_UNAVAILABLE_THRESHOLD", 1)
    monkeypatch.setattr(api_main, "SLO_ALERT_SLACK_FAILURES_THRESHOLD", 1)
    monkeypatch.setattr(api_main, "SLO_ALERT_DIGEST_BACKLOG_THRESHOLD", 1)

    with api_main._SLO_LOCK:
        api_main._SLO_COUNTERS["requests_total"] = 100
        api_main._SLO_COUNTERS["requests_error"] = 5
        api_main._SLO_COUNTERS["opa_unavailable"] = 1
        api_main._SLO_LATENCIES_MS.clear()
        api_main._SLO_LATENCIES_MS.extend([200, 250, 300])

    with api_main._SLACK_METRICS_LOCK:
        api_main._SLACK_METRICS["dispatch_failures"] = 2
        api_main._SLACK_METRICS["digest_items_buffered"] = 2

    resp = client.get("/metrics/alerts")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] in {"warn", "critical"}
    active_ids = {item.get("id") for item in body.get("active_alerts", [])}
    assert "api.error-rate" in active_ids
    assert "api.latency-p95" in active_ids
    assert "opa.unavailable" in active_ids
    assert "slack.dispatch-failures" in active_ids
    assert "slack.digest-backlog" in active_ids


def test_decision_is_sent_to_slack_helper(
    monkeypatch: pytest.MonkeyPatch, acceptable_request: dict
) -> None:
    emitted: list[dict] = []

    monkeypatch.setattr(api_main, "_emit_slack_decision", lambda payload: emitted.append(payload))

    resp = client.post("/evaluate", json=acceptable_request)
    assert resp.status_code == 200, resp.text
    assert len(emitted) == 1
    assert emitted[0]["decision_verdict"] == "ACCEPTABLE"
    assert emitted[0]["endpoint"] == "/evaluate"
    assert "details" in emitted[0]


def test_slack_risk_label_normalizes_case_and_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "acceptable",
            "overall_status": "compliant",
            "overall_risk": " low ",
            "endpoint": "/evaluate",
            "decision_id": "dec-1",
        }
    )

    assert len(sent_messages) == 1
    body = sent_messages[0]
    fields = body["blocks"][1]["fields"]
    assert any(field["text"].endswith("🟢 LOW") for field in fields)


def test_slack_batch_summary_status_normalizes_case_and_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_INCLUDE_JSON_DETAILS", False)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_batch_summary(
        "Firewall bulk summary",
        {
            "overall_status": " non-compliant ",
            "total": 2,
            "acceptable": 1,
            "denied": 1,
        },
    )

    assert len(sent_messages) == 1
    assert "Overall status: :x: NON-COMPLIANT" in sent_messages[0]["text"]


def test_slack_batch_summary_compliant_omits_failure_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_INCLUDE_JSON_DETAILS", True)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_batch_summary(
        "Firewall bulk summary",
        {
            "overall_status": "COMPLIANT",
            "total": 2,
            "acceptable": 2,
            "denied": 0,
            "failed_controls": ["Enc-Transit"],
            "by_failed_control": {"Enc-Transit": 1},
            "by_failed_standard": {"ISO 27001": 1},
        },
    )

    assert len(sent_messages) == 1
    text = sent_messages[0]["text"]
    assert "Failed controls:" not in text
    assert "By failed standard:" not in text
    assert "By failed control:" not in text
    assert "```" not in text


def test_slack_batch_summary_non_compliant_includes_failure_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_INCLUDE_JSON_DETAILS", False)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_batch_summary(
        "Firewall bulk summary",
        {
            "overall_status": "NON-COMPLIANT",
            "total": 2,
            "acceptable": 1,
            "denied": 1,
            "failed_controls": ["Enc-Transit"],
            "by_failed_control": {"Enc-Transit": 1},
            "by_failed_standard": {"ISO 27001": 1},
        },
    )

    assert len(sent_messages) == 1
    text = sent_messages[0]["text"]
    assert "Failed controls: Enc-Transit" in text
    assert "By failed standard:" in text
    assert "By failed control:" in text


def test_slack_compliant_decision_omits_failure_reason_and_remediation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "ACCEPTABLE",
            "overall_status": "COMPLIANT",
            "overall_risk": "LOW",
            "endpoint": "/evaluate",
            "decision_id": "dec-2",
            "details": {
                "reason": "Permitted: the proposed request is compliant with Clarisys NFR controls.",
                "remediations": ["Do something"],
            },
        }
    )

    assert len(sent_messages) == 1
    message = sent_messages[0]
    assert "Failure reason:" not in message["text"]
    assert "Remediation:" not in message["text"]
    assert not any(
        block.get("type") == "section"
        and "Failure reason" in block.get("text", {}).get("text", "")
        for block in message["blocks"]
    )


def test_slack_non_compliant_decision_includes_failure_reason_and_remediation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "DENY",
            "overall_status": "NON-COMPLIANT",
            "overall_risk": "CRITICAL",
            "endpoint": "/evaluate",
            "decision_id": "dec-3",
            "details": {
                "reason": "Denied due to CIS v8.1 failures.",
                "remediations": ["Enable encryption in transit"],
            },
        }
    )

    assert len(sent_messages) == 1
    message = sent_messages[0]
    assert "Failure reason:" in message["text"]
    assert "Remediation:" in message["text"]


def test_slack_decision_headers_include_rule_network_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "ACCEPTABLE",
            "overall_status": "COMPLIANT",
            "overall_risk": "LOW",
            "endpoint": "/evaluate",
            "decision_id": "dec-headers-1",
            "details": {
                "source": "10.157.26.5",
                "destination": "10.221.126.33",
                "protocol": "tcp",
                "port": 443,
            },
        }
    )

    assert len(sent_messages) == 1
    message = sent_messages[0]
    fields = message["blocks"][1]["fields"]
    field_texts = [field["text"] for field in fields]
    assert "*Source network*\n10.157.26.5" in field_texts
    assert "*Destination network*\n10.221.126.33" in field_texts
    assert "*Protocol*\ntcp" in field_texts
    assert "*Port*\n443" in field_texts


def test_slack_decision_dedup_suppresses_identical_events_within_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []
    current_time = {"value": 1000.0}

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 60)
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {})
    monkeypatch.setattr(api_main.time, "time", lambda: current_time["value"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    payload = {
        "decision_verdict": "DENY",
        "overall_status": "NON-COMPLIANT",
        "overall_risk": "HIGH",
        "endpoint": "/evaluate",
        "details": {"reason": "Denied", "remediations": ["Fix"]},
    }

    api_main._emit_slack_decision(payload)
    api_main._emit_slack_decision(payload)
    assert len(sent_messages) == 1

    current_time["value"] = 1061.0
    api_main._emit_slack_decision(payload)
    assert len(sent_messages) == 2


def test_slack_decision_dedup_keeps_distinct_rules_within_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []
    current_time = {"value": 4000.0}

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 300)
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {})
    monkeypatch.setattr(api_main.time, "time", lambda: current_time["value"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    payload_1 = {
        "decision_verdict": "ACCEPTABLE",
        "overall_status": "COMPLIANT",
        "overall_risk": "LOW",
        "endpoint": "/evaluate/bulk/stream",
        "details": {
            "source": "10.157.26.5",
            "destination": "10.221.126.33",
            "protocol": "tcp",
            "port": 443,
        },
    }
    payload_2 = {
        "decision_verdict": "ACCEPTABLE",
        "overall_status": "COMPLIANT",
        "overall_risk": "LOW",
        "endpoint": "/evaluate/bulk/stream",
        "details": {
            "source": "10.157.26.6",
            "destination": "10.221.126.34",
            "protocol": "tcp",
            "port": 443,
        },
    }

    api_main._emit_slack_decision(payload_1)
    api_main._emit_slack_decision(payload_2)

    assert len(sent_messages) == 2


def test_slack_policy_send_only_deny_suppresses_acceptable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_SEND_ONLY_DENY", True)
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_MODE", False)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "ACCEPTABLE",
            "overall_status": "COMPLIANT",
            "overall_risk": "LOW",
            "endpoint": "/evaluate",
            "details": {"source": "a", "destination": "b", "protocol": "tcp", "port": 443},
        }
    )

    assert len(sent_messages) == 0


def test_slack_policy_min_risk_suppresses_lower_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_REALTIME_MIN_RISK", "HIGH")
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_MODE", False)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "DENY",
            "overall_status": "NON-COMPLIANT",
            "overall_risk": "MEDIUM",
            "endpoint": "/evaluate",
            "details": {"source": "a", "destination": "b", "protocol": "tcp", "port": 443},
        }
    )

    assert len(sent_messages) == 0


def test_slack_policy_rate_limit_caps_alerts_per_minute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []
    current_time = {"value": 7000.0}

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_MAX_ALERTS_PER_MINUTE", 1)
    monkeypatch.setattr(api_main, "_SLACK_RATE_STATE", {"window_start": 0.0, "sent": 0})
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_MODE", False)
    monkeypatch.setattr(api_main.time, "time", lambda: current_time["value"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    payload = {
        "decision_verdict": "DENY",
        "overall_status": "NON-COMPLIANT",
        "overall_risk": "HIGH",
        "endpoint": "/evaluate",
        "details": {"source": "a", "destination": "b", "protocol": "tcp", "port": 443},
    }

    api_main._emit_slack_decision(payload)
    api_main._emit_slack_decision(payload)
    assert len(sent_messages) == 1


def test_slack_batch_dedup_suppresses_identical_events_within_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []
    current_time = {"value": 2000.0}

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 60)
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {})
    monkeypatch.setattr(api_main.time, "time", lambda: current_time["value"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    summary = {
        "overall_status": "NON-COMPLIANT",
        "total": 2,
        "acceptable": 1,
        "denied": 1,
        "failed_controls": ["Enc-Transit"],
        "by_failed_standard": {"ISO 27001": 1},
        "by_failed_control": {"Enc-Transit": 1},
    }

    api_main._emit_slack_batch_summary("Firewall bulk summary", summary)
    api_main._emit_slack_batch_summary("Firewall bulk summary", summary)
    assert len(sent_messages) == 1

    current_time["value"] = 2061.0
    api_main._emit_slack_batch_summary("Firewall bulk summary", summary)
    assert len(sent_messages) == 2


def test_slack_metrics_track_success_and_dedup_suppression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []
    current_time = {"value": 3000.0}

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 60)
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {})
    monkeypatch.setattr(
        api_main,
        "_SLACK_METRICS",
        {
            "decision_notifications_sent": 0,
            "batch_notifications_sent": 0,
            "digest_notifications_sent": 0,
            "digest_items_buffered": 0,
            "notifications_dedup_suppressed": 0,
            "dispatch_successes": 0,
            "dispatch_failures": 0,
            "last_error": None,
            "last_error_at": None,
        },
    )
    monkeypatch.setattr(api_main.time, "time", lambda: current_time["value"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    payload = {
        "decision_verdict": "DENY",
        "overall_status": "NON-COMPLIANT",
        "overall_risk": "HIGH",
        "endpoint": "/evaluate",
        "details": {"reason": "Denied", "remediations": ["Fix"]},
    }
    api_main._emit_slack_decision(payload)
    api_main._emit_slack_decision(payload)

    summary = {
        "overall_status": "NON-COMPLIANT",
        "total": 2,
        "acceptable": 1,
        "denied": 1,
        "failed_controls": ["Enc-Transit"],
        "by_failed_standard": {"ISO 27001": 1},
        "by_failed_control": {"Enc-Transit": 1},
    }
    api_main._emit_slack_batch_summary("Firewall bulk summary", summary)

    metrics = api_main._slack_metrics_snapshot()
    assert metrics["decision_notifications_sent"] == 1
    assert metrics["batch_notifications_sent"] == 1
    assert metrics["notifications_dedup_suppressed"] == 1
    assert metrics["dispatch_successes"] == 2
    assert metrics["dispatch_failures"] == 0
    assert len(sent_messages) == 2


def test_slack_metrics_track_dispatch_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        @staticmethod
        def request(method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            raise RuntimeError("simulated slack failure")

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {})
    monkeypatch.setattr(
        api_main,
        "_SLACK_METRICS",
        {
            "decision_notifications_sent": 0,
            "batch_notifications_sent": 0,
            "digest_notifications_sent": 0,
            "digest_items_buffered": 0,
            "notifications_dedup_suppressed": 0,
            "dispatch_successes": 0,
            "dispatch_failures": 0,
            "last_error": None,
            "last_error_at": None,
        },
    )
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FailingConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "DENY",
            "overall_status": "NON-COMPLIANT",
            "overall_risk": "CRITICAL",
            "endpoint": "/evaluate",
            "details": {"reason": "Denied", "remediations": ["Fix"]},
        }
    )

    metrics = api_main._slack_metrics_snapshot()
    assert metrics["decision_notifications_sent"] == 0
    assert metrics["dispatch_successes"] == 0
    assert metrics["dispatch_failures"] == 1
    assert "simulated slack failure" in str(metrics["last_error"])
    assert isinstance(metrics["last_error_at"], str)


def test_slack_webhook_retry_with_exponential_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that webhook dispatch retries on transient failures with exponential backoff."""
    attempt_count = {"count": 0}
    
    class _RetryableConnection:
        def __init__(self, netloc: str, timeout: float = 5.0) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            attempt_count["count"] += 1
            if attempt_count["count"] < 3:
                # Fail first 2 attempts with 5xx error
                raise RuntimeError(f"Temporary error on attempt {attempt_count['count']}")
            # Succeed on 3rd attempt
            self.response = _FakeResponse()

        def getresponse(self):
            return self.response

        @staticmethod
        def close() -> None:
            return None

    class _FakeResponse:
        status = 200
        
        def read(self) -> bytes:
            return b"ok"

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {})
    monkeypatch.setattr(
        api_main,
        "_SLACK_METRICS",
        {
            "decision_notifications_sent": 0,
            "batch_notifications_sent": 0,
            "digest_notifications_sent": 0,
            "digest_items_buffered": 0,
            "notifications_dedup_suppressed": 0,
            "dispatch_successes": 0,
            "dispatch_failures": 0,
            "last_error": None,
            "last_error_at": None,
        },
    )
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _RetryableConnection)
    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_MAX_RETRIES", 3)
    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_BACKOFF_BASE_SECONDS", 0.01)  # Fast backoff for testing
    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_BACKOFF_MULTIPLIER", 2.0)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "DENY",
            "overall_status": "NON-COMPLIANT",
            "overall_risk": "CRITICAL",
            "endpoint": "/evaluate",
            "details": {"reason": "Denied", "remediations": ["Fix"]},
        }
    )

    # Should have retried 3 times total (initial + 2 retries) and succeeded
    assert attempt_count["count"] == 3
    
    metrics = api_main._slack_metrics_snapshot()
    assert metrics["decision_notifications_sent"] == 1
    assert metrics["dispatch_successes"] == 1
    assert metrics["dispatch_failures"] == 0



def test_slack_metrics_reset_endpoint_clears_counters_and_dedup_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    future = api_main.time.time() + 3600
    monkeypatch.setattr(
        api_main,
        "_SLACK_METRICS",
        {
            "decision_notifications_sent": 3,
            "batch_notifications_sent": 2,
            "digest_notifications_sent": 1,
            "digest_items_buffered": 4,
            "notifications_dedup_suppressed": 7,
            "dispatch_successes": 9,
            "dispatch_failures": 1,
            "last_error": "boom",
            "last_error_at": "2026-06-09T00:00:00+00:00",
        },
    )
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {"k1": future, "k2": future})

    resp = client.post("/notifications/slack/metrics/reset?clear_dedup_cache=true")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reset"] is True
    assert body["cleared_dedup_cache"] is True
    assert body["decision_notifications_sent"] == 0
    assert body["batch_notifications_sent"] == 0
    assert body["digest_notifications_sent"] == 0
    assert body["digest_items_buffered"] == 0
    assert body["notifications_dedup_suppressed"] == 0
    assert body["dispatch_successes"] == 0
    assert body["dispatch_failures"] == 0
    assert body["last_error"] is None
    assert body["last_error_at"] is None
    assert body["dedup_cache_active_keys"] == 0


def test_slack_metrics_reset_endpoint_can_keep_dedup_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    future = api_main.time.time() + 3600
    monkeypatch.setattr(
        api_main,
        "_SLACK_METRICS",
        {
            "decision_notifications_sent": 1,
            "batch_notifications_sent": 1,
            "digest_notifications_sent": 1,
            "digest_items_buffered": 2,
            "notifications_dedup_suppressed": 1,
            "dispatch_successes": 1,
            "dispatch_failures": 1,
            "last_error": "boom",
            "last_error_at": "2026-06-09T00:00:00+00:00",
        },
    )
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_CACHE", {"k1": future})

    resp = client.post("/notifications/slack/metrics/reset?clear_dedup_cache=false")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reset"] is True
    assert body["cleared_dedup_cache"] is False
    assert body["decision_notifications_sent"] == 0
    assert body["dispatch_failures"] == 0
    assert body["dedup_cache_active_keys"] == 1


def test_slack_decision_includes_links_when_base_url_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_API_BASE_URL", "https://api.example.test")
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "DENY",
            "overall_status": "NON-COMPLIANT",
            "overall_risk": "HIGH",
            "endpoint": "/evaluate",
            "decision_id": "abc123:evaluate",
            "details": {"source": "a", "destination": "b", "protocol": "tcp", "port": 443},
        }
    )

    assert len(sent_messages) == 1
    body = sent_messages[0]
    assert "https://api.example.test/decisions/lifecycle/abc123:evaluate" in body["text"]
    assert "https://api.example.test/evaluate/explain" in body["text"]


def test_slack_decision_remediation_is_top_three_deduped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "DENY",
            "overall_status": "NON-COMPLIANT",
            "overall_risk": "CRITICAL",
            "endpoint": "/evaluate",
            "decision_id": "abc123:evaluate",
            "details": {
                "source": "a",
                "destination": "b",
                "protocol": "tcp",
                "port": 443,
                "reason": "Denied",
                "remediations": [
                    "Enable TLS 1.2+",
                    " enable tls 1.2+ ",
                    "Fix segmentation",
                    "Add audit logging",
                    "Rotate secrets",
                ],
            },
        }
    )

    assert len(sent_messages) == 1
    text = sent_messages[0]["text"]
    assert "- Enable TLS 1.2+" in text
    assert "- Fix segmentation" in text
    assert "- Add audit logging" in text
    assert "Rotate secrets" not in text


def test_slack_severity_routing_uses_priority_webhooks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets: list[str] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            targets.append(self.netloc)

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://default.slack.test/services/base"])
    monkeypatch.setattr(api_main, "_SLACK_HIGH_PRIORITY_WEBHOOK_URLS", ["https://high.slack.test/services/high"])
    monkeypatch.setattr(api_main, "_SLACK_LOW_PRIORITY_WEBHOOK_URLS", ["https://low.slack.test/services/low"])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    api_main._emit_slack_decision(
        {
            "decision_verdict": "DENY",
            "overall_status": "NON-COMPLIANT",
            "overall_risk": "CRITICAL",
            "endpoint": "/evaluate",
            "details": {"source": "a", "destination": "b", "protocol": "tcp", "port": 443},
        }
    )
    api_main._emit_slack_decision(
        {
            "decision_verdict": "ACCEPTABLE",
            "overall_status": "COMPLIANT",
            "overall_risk": "LOW",
            "endpoint": "/evaluate",
            "details": {"source": "a", "destination": "b", "protocol": "tcp", "port": 443},
        }
    )

    assert "high.slack.test" in targets
    assert "low.slack.test" in targets
    assert "default.slack.test" not in targets


def test_slack_digest_mode_buffers_low_medium_and_emits_window_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []
    current_time = {"value": 5000.0}

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://low.slack.test/services/low"])
    monkeypatch.setattr(api_main, "_SLACK_LOW_PRIORITY_WEBHOOK_URLS", ["https://low.slack.test/services/low"])
    monkeypatch.setattr(api_main, "_SLACK_HIGH_PRIORITY_WEBHOOK_URLS", [])
    monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_MODE", True)
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_WINDOW_SECONDS", 60)
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_STATE", {"window_start": 0.0, "items": []})
    monkeypatch.setattr(api_main.time, "time", lambda: current_time["value"])
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    payload = {
        "decision_verdict": "ACCEPTABLE",
        "overall_status": "COMPLIANT",
        "overall_risk": "LOW",
        "endpoint": "/evaluate",
        "details": {"source": "10.1.1.1", "destination": "10.2.2.2", "protocol": "tcp", "port": 443},
    }

    api_main._emit_slack_decision(payload)
    assert len(sent_messages) == 0

    current_time["value"] = 5061.0
    api_main._emit_slack_decision(payload)
    assert len(sent_messages) == 1
    assert "Firewall low/medium digest" in sent_messages[0]["text"]


def test_slack_webhook_integration_payload_shape_with_local_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[dict] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            received.append(json.loads(body.decode("utf-8")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):  # noqa: A003
            return None

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()

    server = HTTPServer((host, port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", [f"http://127.0.0.1:{port}/webhook"])
        monkeypatch.setattr(api_main, "_SLACK_HIGH_PRIORITY_WEBHOOK_URLS", [])
        monkeypatch.setattr(api_main, "_SLACK_LOW_PRIORITY_WEBHOOK_URLS", [])
        monkeypatch.setattr(api_main, "_SLACK_DEDUP_WINDOW_SECONDS", 0)
        monkeypatch.setattr(api_main, "_SLACK_DIGEST_MODE", False)
        monkeypatch.setattr(api_main, "_SLACK_SEND_ONLY_DENY", False)

        api_main._emit_slack_decision(
            {
                "decision_verdict": "DENY",
                "overall_status": "NON-COMPLIANT",
                "overall_risk": "HIGH",
                "endpoint": "/evaluate",
                "decision_id": "int-1:evaluate",
                "details": {
                    "source": "10.1.1.1",
                    "destination": "10.2.2.2",
                    "protocol": "tcp",
                    "port": 443,
                    "reason": "Denied",
                    "remediations": ["Fix A", "Fix B", "Fix C", "Fix D"],
                },
            }
        )

        assert len(received) == 1
        payload = received[0]
        assert "text" in payload
        assert "blocks" in payload
        assert "Rule fingerprint:" in payload["text"]
        assert "- Fix D" not in payload["text"]
    finally:
        server.shutdown()
        server.server_close()


def test_slack_digest_flush_endpoint_forces_flush(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_messages: list[dict] = []

    class _FakeResponse:
        status = 200

        @staticmethod
        def read() -> bytes:
            return b"ok"

    class _FakeConnection:
        def __init__(self, netloc: str, timeout: int = 5) -> None:  # noqa: ARG002
            self.netloc = netloc

        def request(self, method: str, path: str, body: bytes, headers: dict) -> None:  # noqa: ARG002
            sent_messages.append(json.loads(body.decode("utf-8")))

        @staticmethod
        def getresponse() -> _FakeResponse:
            return _FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(api_main, "_SLACK_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_LOW_PRIORITY_WEBHOOK_URLS", ["https://hooks.slack.test/services/T1/B1/X1"])
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_MODE", True)
    monkeypatch.setattr(api_main, "_SLACK_DIGEST_WINDOW_SECONDS", 3600)
    monkeypatch.setattr(
        api_main,
        "_SLACK_DIGEST_STATE",
        {
            "window_start": api_main.time.time(),
            "items": [
                {
                    "endpoint": "/evaluate",
                    "source": "10.1.1.1",
                    "destination": "10.2.2.2",
                    "protocol": "tcp",
                    "port": "443",
                    "verdict": "ACCEPTABLE",
                    "risk": "LOW",
                }
            ],
        },
    )
    monkeypatch.setattr(api_main.http.client, "HTTPSConnection", _FakeConnection)

    resp = client.post("/notifications/slack/digest/flush")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["flushed"] is True
    assert len(sent_messages) == 1
    assert "Firewall low/medium digest" in sent_messages[0]["text"]
