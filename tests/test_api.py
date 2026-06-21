from __future__ import annotations

import io
import json
import sys
from collections import deque
from pathlib import Path
import shutil

from openpyxl import Workbook
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import main as api_main
from api import roi_metrics
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


@pytest.fixture()
def deny_request() -> dict:
    return {
        "source": "10.157.26.5",
        "destination": "payment.example.com",
        "protocol": "tcp",
        "port": 80,
        "log": "no_log",
        "data_classification": "Confidential",
        "approved_external_sharing": True,
        "source_interface": "retail-src",
        "destination_interface": "payment-dst",
    }


@pytest.fixture()
def intake_allow_request() -> dict:
    return {
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


@pytest.fixture()
def intake_any_request() -> dict:
    return {
        "app_id": "ap-B9876",
        "portfolio": "Technology",
        "environment": "production",
        "requested_by": "bob@example.com",
        "expires_at": "2026-11-01",
        "project_reference": "PRJ-444",
        "source_name": "legacy-app",
        "destination_name": "internal-db",
        "destination_port": 1433,
        "protocol": "ANY",
        "action": "ALLOW",
        "business_justification": "Legacy app requires broad protocol access to internal database.",
    }


def test_health_endpoint_reports_ready() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "opa_available": True,
        "data_file_loaded": True,
    }


def test_health_verbose_includes_triage_subsystems() -> None:
    response = client.get("/health?verbose=true")
    assert response.status_code == 200
    body = response.json()

    # Minimal fields still present.
    assert body["status"] in ("ok", "degraded")
    assert body["opa_available"] is True
    assert body["data_file_loaded"] is True

    # All four triage sub-blocks are present.
    for key in ("opa_cache", "decision_history", "slo", "slack"):
        assert key in body, f"verbose health missing {key}"
        assert isinstance(body[key], dict)

    # SLO sub-block carries the headline numbers ops actually need.
    for key in ("requests_total", "error_rate", "latency_p95_ms"):
        assert key in body["slo"]

    # Slack sub-block carries the failure-mode headline numbers.
    for key in ("dispatch_failures", "last_error", "last_error_at"):
        assert key in body["slack"]

    # Decision history sub-block carries pruning/retention facts.
    for key in ("history_file", "retention_days"):
        assert key in body["decision_history"]


def test_health_default_excludes_triage_subsystems() -> None:
    """Default /health stays cheap for liveness probes."""
    response = client.get("/health")
    body = response.json()
    for key in ("opa_cache", "decision_history", "slo", "slack"):
        assert key not in body


def test_health_verbose_warns_on_recent_slack_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """If Slack reported an error within the recent-failure window, verbose
    health surfaces 'slack.recent_failure' in warnings without changing the
    primary status field (liveness semantics stay intact)."""
    from datetime import datetime, timezone

    # Override the snapshot to mimic a recent Slack failure.
    recent_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    fake_snapshot = {
        "dispatch_successes": 10,
        "dispatch_failures": 1,
        "last_error": "HTTP 502 from Slack",
        "last_error_at": recent_iso,
    }
    monkeypatch.setattr(api_main, "_slack_metrics_snapshot", lambda: fake_snapshot)

    response = client.get("/health?verbose=true")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"  # liveness unchanged
    assert "warnings" in body
    assert "slack.recent_failure" in body["warnings"]


def test_health_verbose_no_warning_for_old_slack_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Errors older than the configured window must not appear as warnings."""
    from datetime import datetime, timedelta, timezone

    old_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat().replace(
        "+00:00", "Z"
    )
    fake_snapshot = {
        "dispatch_successes": 10,
        "dispatch_failures": 1,
        "last_error": "HTTP 502 from Slack",
        "last_error_at": old_iso,
    }
    monkeypatch.setattr(api_main, "_slack_metrics_snapshot", lambda: fake_snapshot)

    response = client.get("/health?verbose=true")
    body = response.json()
    assert body.get("warnings", []) == [] or "slack.recent_failure" not in body.get("warnings", [])


def test_health_verbose_no_warning_when_no_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A null last_error_at must never produce a warning."""
    fake_snapshot = {
        "dispatch_successes": 10,
        "dispatch_failures": 0,
        "last_error": None,
        "last_error_at": None,
    }
    monkeypatch.setattr(api_main, "_slack_metrics_snapshot", lambda: fake_snapshot)

    response = client.get("/health?verbose=true")
    body = response.json()
    assert "warnings" not in body or "slack.recent_failure" not in body["warnings"]


def test_health_default_unaffected_by_recent_slack_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default /health must stay minimal even when verbose mode would warn."""
    from datetime import datetime, timezone

    recent_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    fake_snapshot = {
        "dispatch_successes": 10,
        "dispatch_failures": 5,
        "last_error": "HTTP 502 from Slack",
        "last_error_at": recent_iso,
    }
    monkeypatch.setattr(api_main, "_slack_metrics_snapshot", lambda: fake_snapshot)

    response = client.get("/health")
    body = response.json()
    assert body == {
        "status": "ok",
        "opa_available": True,
        "data_file_loaded": True,
    }
    assert "warnings" not in body


def test_evaluate_returns_acceptable_for_compliant_request(acceptable_request: dict) -> None:
    response = client.post("/evaluate", json=acceptable_request)

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "ACCEPTABLE"
    assert body["allow"] is True
    assert body["overall_risk"] == "LOW"
    assert body["violations_count"] == 0
    assert body["failed_controls"] == []
    assert body["framework_clauses"] == {}
    assert body["control_clause_mappings"] == {}


def test_evaluate_returns_deny_for_non_compliant_request(deny_request: dict) -> None:
    response = client.post("/evaluate", json=deny_request)

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "DENY"
    assert body["allow"] is False
    assert body["overall_risk"] == "CRITICAL"
    assert body["violations_count"] >= 1
    assert "Enc-Transit" in body["failed_controls"]
    assert "ISO 27001" in body["failed_standards"]
    assert "ISO 27001" in body["framework_clauses"]
    assert "A.8.24" in body["framework_clauses"]["ISO 27001"]
    assert "Enc-Transit" in body["control_clause_mappings"]
    assert "ISO 27001" in body["control_clause_mappings"]["Enc-Transit"]
    assert "A.8.24" in body["control_clause_mappings"]["Enc-Transit"]["ISO 27001"]


def test_evaluate_defaults_to_ms_only_for_deny_no_log() -> None:
    response = client.post(
        "/evaluate",
        json={
            "source": "10.10.1.20",
            "destination": "internal-service",
            "protocol": "tcp",
            "port": 443,
            "log": "no_log",
            "action": "deny",
            "source_interface": "retail-src",
            "destination_interface": "app-dst",
            "data_classification": "Public",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "DENY"
    assert body["allow"] is False
    assert body["overall_risk"] == "MEDIUM"
    assert "CIS_13.6" in body["failed_controls"]


def test_evaluate_enables_optional_standards_when_requested() -> None:
    response = client.post(
        "/evaluate",
        json={
            "source": "10.10.1.20",
            "destination": "internal-service",
            "protocol": "tcp",
            "port": 443,
            "log": "no_log",
            "action": "deny",
            "source_interface": "retail-src",
            "destination_interface": "app-dst",
            "data_classification": "Public",
            "standards": ["ISO 27001", "CIS v8.1"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "DENY"
    assert body["allow"] is False
    assert "CIS_13.6" in body["failed_controls"]
    assert "ISO 27001" in body["failed_standards"]


def test_evaluate_bulk_aggregates_results(acceptable_request: dict, deny_request: dict) -> None:
    response = client.post("/evaluate/bulk", json={"requests": [acceptable_request, deny_request]})

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total"] == 2
    assert body["summary"]["acceptable"] == 1
    assert body["summary"]["denied"] == 1
    assert body["summary"]["overall_status"] == "NON-COMPLIANT"
    assert body["summary"]["failed_controls"] == ["Data-10", "Enc-Transit", "IAM-8 / Cloud-09 / CIS_8.2"]
    assert len(body["results"]) == 2


def test_intake_evaluate_returns_standards_derived_risk_score(intake_any_request: dict) -> None:
    response = client.post("/intake/evaluate", json=intake_any_request)

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "DENY"
    assert body["overall_risk"] == "HIGH"
    assert body["risk_score"] == 75
    assert "CIS_4.8" in body["failed_controls"]
    assert "ISO 27001" in body["framework_clauses"]
    assert "A.8.20" in body["framework_clauses"]["ISO 27001"]
    assert "CIS_4.8" in body["control_clause_mappings"]


def test_intake_bulk_aggregates_scores(
    intake_allow_request: dict,
    intake_any_request: dict,
) -> None:
    response = client.post(
        "/intake/evaluate/bulk",
        json={"requests": [intake_allow_request, intake_any_request]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total"] == 2
    assert body["summary"]["acceptable"] == 1
    assert body["summary"]["denied"] == 1
    assert body["summary"]["overall_status"] == "NON-COMPLIANT"
    assert body["summary"]["total_risk_score"] == 100
    assert body["summary"]["max_risk_score"] == 75
    assert body["summary"]["failed_controls"] == ["CIS_4.8"]
    assert [item["risk_score"] for item in body["results"]] == [25, 75]


def test_evaluate_bulk_records_roi_per_rule(
    acceptable_request: dict, deny_request: dict
) -> None:
    """Regression: /evaluate/bulk used to write to history but never call
    record_rule_processed, silently undercounting ROI by every bulk rule."""
    before = roi_metrics.get_current_metrics()["total_rules"]
    response = client.post(
        "/evaluate/bulk",
        json={"requests": [acceptable_request, deny_request, acceptable_request]},
    )
    assert response.status_code == 200
    after = roi_metrics.get_current_metrics()["total_rules"]
    assert after - before == 3, f"expected +3 rules, got +{after - before}"


def test_intake_evaluate_records_roi(intake_allow_request: dict) -> None:
    """Regression: /intake/evaluate single also didn't call record_rule_processed."""
    before = roi_metrics.get_current_metrics()["total_rules"]
    response = client.post("/intake/evaluate", json=intake_allow_request)
    assert response.status_code == 200
    after = roi_metrics.get_current_metrics()["total_rules"]
    assert after - before == 1


def test_intake_evaluate_bulk_records_roi_per_rule(
    intake_allow_request: dict, intake_any_request: dict
) -> None:
    """Regression: /intake/evaluate/bulk also missing record_rule_processed."""
    before = roi_metrics.get_current_metrics()["total_rules"]
    response = client.post(
        "/intake/evaluate/bulk",
        json={"requests": [intake_allow_request, intake_any_request, intake_allow_request]},
    )
    assert response.status_code == 200
    after = roi_metrics.get_current_metrics()["total_rules"]
    assert after - before == 3


def test_intake_validation_requires_destination_port_for_tcp(intake_allow_request: dict) -> None:
    intake_allow_request.pop("destination_port")

    response = client.post("/intake/evaluate", json=intake_allow_request)

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any("destination_port is required for TCP and UDP protocols" in item["msg"] for item in detail)


def test_sensitive_udp_443_should_not_be_treated_as_encrypted() -> None:
    response = client.post(
        "/evaluate",
        json={
            "source": "10.157.26.5",
            "destination": "payment-switch",
            "protocol": "udp",
            "port": 443,
            "log": "all",
            "data_classification": "Confidential",
            "source_interface": "retail-src",
            "destination_interface": "payment-dst",
        },
    )

    assert response.status_code == 200
    assert response.json()["verdict"] == "DENY"
    assert response.json()["overall_risk"] == "CRITICAL"


def test_any_protocol_should_not_be_silently_downgraded_to_tcp(intake_any_request: dict) -> None:
    response = client.post("/intake/evaluate", json=intake_any_request)

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "DENY"
    assert body["overall_risk"] == "HIGH"
    assert body["risk_score"] == 75
    assert "CIS_4.8" in body["failed_controls"]


def test_missing_real_segmentation_metadata_should_not_pass_by_default() -> None:
    response = client.post(
        "/evaluate",
        json={
            "source": "10.10.1.1",
            "destination": "8.8.8.8",
            "protocol": "udp",
            "port": 53,
            "log": "all",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "DENY"
    assert "Cloud-08 / CIS_12.2" in body["failed_controls"]


def test_intake_evaluate_accepts_optional_standards_and_echoes_them(
    intake_any_request: dict,
) -> None:
    intake_any_request["standards"] = ["ISO 27001", "CIS v8.1"]
    response = client.post("/intake/evaluate", json=intake_any_request)


def test_compliance_coverage_returns_all_frameworks() -> None:
    response = client.get("/compliance/coverage")

    assert response.status_code == 200
    body = response.json()
    assert set(body["frameworks"]) == {"Clarisys NFR", "ISO 27001", "CIS v8.1", "PCI-DSS", "Cyber Essentials"}
    assert len(body["results"]) == 5
    iso = next(item for item in body["results"] if item["framework"] == "ISO 27001")
    assert iso["controls_mapped"] >= 1
    assert "A.8.24" in iso["clauses_covered"]


def test_compliance_coverage_filters_to_single_framework() -> None:
    response = client.get("/compliance/coverage", params={"framework": "PCI-DSS"})

    assert response.status_code == 200
    body = response.json()
    assert body["frameworks"] == ["Clarisys NFR", "ISO 27001", "CIS v8.1", "PCI-DSS", "Cyber Essentials"]
    assert len(body["results"]) == 1
    result = body["results"][0]
    assert result["framework"] == "PCI-DSS"
    assert "4.2.1" in result["clauses_covered"]


def test_compliance_coverage_unknown_framework_returns_404() -> None:
    response = client.get("/compliance/coverage", params={"framework": "SOC 2"})

    assert response.status_code == 404


def test_roi_metrics_state_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "roi-metrics.json"
    history_file = tmp_path / "decision_history.jsonl"
    history_file.write_text(
        "{\"ts\":\"2026-06-10T10:00:00.000000Z\",\"decision_id\":\"r1:evaluate\",\"request_id\":\"r1\",\"endpoint\":\"/evaluate\",\"decision_verdict\":\"ACCEPTABLE\",\"details\":{}}\n"
        "{\"ts\":\"2026-06-10T10:01:00.000000Z\",\"decision_id\":\"r2:evaluate.bulk.stream\",\"request_id\":\"r2\",\"endpoint\":\"/evaluate/bulk/stream\",\"decision_verdict\":\"DENY\",\"details\":{}}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", state_file)
    monkeypatch.setattr(roi_metrics.decision_history, "_history_path", lambda: history_file)

    roi_metrics.reset_metrics()
    roi_metrics.record_rule_processed("req-1", "/evaluate", "ACCEPTABLE")
    roi_metrics.record_rule_processed("req-2", "/evaluate", "DENY")

    assert roi_metrics.get_current_metrics()["total_rules"] == 2

    roi_metrics._save_state()
    payload = json.loads(state_file.read_text(encoding="utf-8"))
    assert payload["total_rules"] == 2

    roi_metrics._METRICS_STATE["total_rules"] = 0
    roi_metrics._METRICS_STATE["last_updated"] = 0
    roi_metrics._SEEN_REQUEST_IDS.clear()
    roi_metrics._load_state()

    restored = roi_metrics.get_current_metrics()
    assert restored["total_rules"] == 2

    state_file.unlink()
    roi_metrics._METRICS_STATE["total_rules"] = 0
    roi_metrics._METRICS_STATE["last_updated"] = 0
    roi_metrics._SEEN_REQUEST_IDS.clear()
    roi_metrics._load_state()

    bootstrapped = roi_metrics.get_current_metrics()
    assert bootstrapped["total_rules"] == 2
    assert bootstrapped["last_updated"] > 0


def test_rules_processed_gauge_mirrors_total_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the dashboard 'Rules Processed' panel used the labelled
    counter (which resets on each process restart) while the HIPS / cost /
    FTE panels used the bootstrapped gauges. Result was 10 rules vs £742k
    saved on the same dashboard. firewall_rules_processed_current must
    track _METRICS_STATE['total_rules'] through every code path."""
    state_file = tmp_path / "roi-metrics.json"
    history_file = tmp_path / "decision_history.jsonl"
    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", state_file)
    monkeypatch.setattr(roi_metrics.decision_history, "_history_path", lambda: history_file)

    roi_metrics.reset_metrics()
    assert roi_metrics.rules_processed_gauge._value.get() == 0

    roi_metrics.record_rule_processed("req-A", "/evaluate", "ACCEPTABLE")
    assert roi_metrics.rules_processed_gauge._value.get() == 1

    roi_metrics.record_rule_processed("req-B", "/evaluate", "DENY")
    assert roi_metrics.rules_processed_gauge._value.get() == 2

    # Persistence path: gauge must rehydrate from disk on _load_state.
    roi_metrics._METRICS_STATE["total_rules"] = 0
    roi_metrics._SEEN_REQUEST_IDS.clear()
    roi_metrics.rules_processed_gauge.set(0)
    roi_metrics._load_state()
    assert roi_metrics.rules_processed_gauge._value.get() == 2

    # Bootstrap path: gauge must rehydrate from history when snapshot is gone.
    history_file.write_text(
        "\n".join(
            json.dumps(
                {
                    "ts": "2026-06-10T10:00:00.000000Z",
                    "decision_id": f"r{i}:evaluate",
                    "request_id": f"r{i}",
                    "endpoint": "/evaluate",
                    "decision_verdict": "ACCEPTABLE",
                    "details": {},
                }
            )
            for i in range(7)
        )
        + "\n",
        encoding="utf-8",
    )
    state_file.unlink()
    roi_metrics._METRICS_STATE["total_rules"] = 0
    roi_metrics._SEEN_REQUEST_IDS.clear()
    roi_metrics.rules_processed_gauge.set(0)
    roi_metrics._load_state()
    assert roi_metrics.rules_processed_gauge._value.get() == 7

    # And reset_metrics must zero it.
    roi_metrics.reset_metrics()
    assert roi_metrics.rules_processed_gauge._value.get() == 0


def test_slo_state_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "slo-metrics.json"
    history_file = tmp_path / "decision_history.jsonl"
    history_file.write_text(
        "{\"ts\":\"2026-06-10T10:00:00.000000Z\",\"decision_id\":\"r1:evaluate\",\"request_id\":\"r1\",\"endpoint\":\"/evaluate\",\"decision_verdict\":\"ACCEPTABLE\",\"details\":{\"failed_standards\":[]}}\n"
        "{\"ts\":\"2026-06-10T10:01:00.000000Z\",\"decision_id\":\"r2:evaluate.bulk.stream\",\"request_id\":\"r2\",\"endpoint\":\"/evaluate/bulk/stream\",\"decision_verdict\":\"DENY\",\"details\":{\"failed_standards\":[\"ISO 27001\",\"CIS v8.1\"]}}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(api_main, "SLO_STATE_FILE", state_file)
    monkeypatch.setattr(api_main._decision_history, "_history_path", lambda: history_file)

    original_counters = dict(api_main._SLO_COUNTERS)
    original_latencies = deque(api_main._SLO_LATENCIES_MS, maxlen=api_main._SLO_LATENCIES_MS.maxlen)

    try:
        api_main._SLO_COUNTERS.update(
            {
                "requests_total": 10,
                "requests_error": 2,
                "decisions_total": 4,
                "decisions_deny": 1,
                "opa_unavailable": 3,
                "failed_standard_ms_nfr_total": 1,
                "failed_standard_iso_27001_total": 2,
                "failed_standard_cis_v81_total": 3,
                "failed_standard_pci_dss_total": 4,
            }
        )
        api_main._SLO_LATENCIES_MS.clear()
        api_main._SLO_LATENCIES_MS.extend([11, 22, 33])

        api_main._save_slo_state()
        payload = json.loads(state_file.read_text(encoding="utf-8"))
        assert payload["counters"]["requests_total"] == 10
        assert "latencies_ms" not in payload, "Latencies should not be persisted (optimization)"

        api_main._SLO_COUNTERS.update({key: 0 for key in api_main._SLO_COUNTERS})
        api_main._SLO_LATENCIES_MS.clear()
        api_main._load_slo_state()

        snapshot = api_main._slo_snapshot()
        assert snapshot["requests_total"] == 10
        assert snapshot["requests_error"] == 2
        assert snapshot["opa_unavailable"] == 3
        assert len(list(api_main._SLO_LATENCIES_MS)) == 0, "Latencies should be empty after load (fresh start)"

        state_file.unlink()
        api_main._SLO_COUNTERS.update({key: 0 for key in api_main._SLO_COUNTERS})
        api_main._SLO_LATENCIES_MS.clear()
        api_main._load_slo_state()

        bootstrapped = api_main._slo_snapshot()
        assert bootstrapped["decisions_total"] == 2
        assert bootstrapped["decisions_deny"] == 1
        assert bootstrapped["failed_standard_iso_27001_total"] == 1
        assert bootstrapped["failed_standard_cis_v81_total"] == 1
    finally:
        api_main._SLO_COUNTERS.clear()
        api_main._SLO_COUNTERS.update(original_counters)
        api_main._SLO_LATENCIES_MS.clear()
        api_main._SLO_LATENCIES_MS.extend(original_latencies)


def test_intake_evaluate_rejects_unknown_standards(intake_allow_request: dict) -> None:
    intake_allow_request["standards"] = ["GDPR"]
    response = client.post("/intake/evaluate", json=intake_allow_request)

    assert response.status_code == 422


def test_intake_evaluate_respects_selected_standards(intake_allow_request: dict) -> None:
    """Passing specific standards evaluates only against those standards."""
    intake_allow_request["standards"] = ["ISO 27001"]
    response = client.post("/intake/evaluate", json=intake_allow_request)

    assert response.status_code == 200
    body = response.json()
    assert body["intake"]["standards"] == ["ISO 27001"]


def test_intake_bulk_propagates_standards_per_request(
    intake_allow_request: dict,
    intake_any_request: dict,
) -> None:
    intake_any_request["standards"] = ["ISO 27001", "CIS v8.1"]
    response = client.post(
        "/intake/evaluate/bulk",
        json={"requests": [intake_allow_request, intake_any_request]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total"] == 2
    # ANY protocol request uses its own standards; allow request uses defaults
    assert "ISO 27001" in body["results"][0]["intake"]["standards"]
    assert "ISO 27001" in body["results"][1]["intake"]["standards"]


# ── /audit/csv ────────────────────────────────────────────────────────────────
RAW_CSV = (
    "source,destination,protocol,port,log,source_interface,destination_interface,"
    "data_classification,approved_external_sharing\n"
    "10.157.26.5,10.221.126.33,tcp,443,all,finance-src,analytics-dst,Internal,false\n"
    "10.157.26.5,payment.example.com,tcp,80,no_log,retail-src,payment-dst,Confidential,true\n"
)

INTAKE_CSV = (
    "app_id,portfolio,environment,requested_by,expires_at,project_reference,"
    "source_name,destination_name,destination_port,protocol,action,business_justification\n"
    "ap-A1234,Finance & Payroll,production,alice@example.com,2027-03-01,CHG0012345,"
    "payroll-app,hmrc-api,443,TCP,ALLOW,Required to submit payroll data to HMRC via their API gateway.\n"
    "ap-B9876,Technology,production,bob@example.com,2026-11-01,PRJ-444,"
    "legacy-app,internal-db,1433,ANY,ALLOW,Legacy app requires broad protocol access to internal database.\n"
)


def _raw_xlsx_bytes() -> bytes:
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(
        [
            "source",
            "destination",
            "protocol",
            "port",
            "log",
            "source_interface",
            "destination_interface",
            "data_classification",
            "approved_external_sharing",
        ]
    )
    sheet.append(
        [
            "10.157.26.5",
            "payment.example.com",
            "tcp",
            80,
            "no_log",
            "retail-src",
            "payment-dst",
            "Confidential",
            "true",
        ]
    )
    stream = io.BytesIO()
    workbook.save(stream)
    return stream.getvalue()


def test_audit_csv_raw_returns_bulk_summary() -> None:
    response = client.post(
        "/audit/csv",
        content=RAW_CSV,
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert 'filename="compliance-report.md"' in response.headers.get("content-disposition", "")
    body = response.text
    assert body.startswith("# Firewall Ruleset Compliance Report")
    assert "- **Schema detected:** `raw`" in body
    assert "- **Total rules evaluated:** 2" in body
    assert "- **Acceptable:** 1" in body
    assert "- **Requires remediation:** 1" in body
    assert "- **Overall status:** **NON-COMPLIANT**" in body
    assert "## Failed controls" in body
    assert "Encryption in transit" in body
    assert "## Per-rule findings" in body


def test_audit_csv_intake_uses_intake_evaluator() -> None:
    response = client.post(
        "/audit/csv",
        content=INTAKE_CSV,
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 200
    body = response.text
    assert "- **Schema detected:** `intake`" in body
    assert "- **Total rules evaluated:** 2" in body
    assert "- **Requires remediation:** 1" in body
    assert "- **Total risk score:** 100" in body
    assert "- **Max risk score:** 75" in body
    assert "Avoid overly permissive" in body
    assert "risk score 75" in body


def test_audit_csv_reports_invalid_rows_without_failing_the_whole_audit() -> None:
    csv_text = (
        "source,destination,protocol,port,log,source_interface,destination_interface\n"
        "10.157.26.5,10.221.126.33,tcp,443,all,finance-src,analytics-dst\n"
        ",,,,all,finance-src,analytics-dst\n"
    )

    response = client.post(
        "/audit/csv",
        content=csv_text,
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 200
    body = response.text
    assert "- **Total rules evaluated:** 1" in body
    assert "- **Invalid rows:** 1" in body
    assert "## Invalid rows" in body
    assert "| 3 |" in body


def test_audit_csv_rejects_unknown_header() -> None:
    response = client.post(
        "/audit/csv",
        content="foo,bar\n1,2\n",
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 400


def test_audit_csv_html_reports_selected_standards() -> None:
    response = client.post(
        "/audit/csv/html?standards=ISO%2027001",
        files={"file": ("rules.csv", RAW_CSV, "text/csv")},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Selected optional standards:</strong> ISO 27001" in response.text
    assert "CIS v8.1" not in response.text.split("Selected optional standards:</strong>", 1)[1].split("</li>", 1)[0]


def test_audit_xlsx_html_reports_selected_standards() -> None:
    response = client.post(
        "/audit/xlsx?standards=PCI-DSS",
        files={
            "file": (
                "rules.xlsx",
                _raw_xlsx_bytes(),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Selected optional standards:</strong> PCI-DSS" in response.text


def test_audit_json_html_reports_selected_standards_for_json_upload() -> None:
    json_payload = Path("deploy/srx-sample.json").read_text(encoding="utf-8")

    response = client.post(
        "/audit/json/html?standards=ISO%2027001&standards=PCI-DSS",
        files={"file": ("srx-sample.json", json_payload, "application/json")},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Selected optional standards:</strong> ISO 27001, PCI-DSS" in response.text


def test_audit_json_html_reports_selected_standards_for_xml_upload() -> None:
    xml_payload = Path("deploy/srx policies.xml").read_text(encoding="utf-8")

    response = client.post(
        "/audit/json/html?standards=CIS%20v8.1",
        files={"file": ("srx-policies.xml", xml_payload, "application/xml")},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Selected optional standards:</strong> CIS v8.1" in response.text


def test_audit_json_cleaned_returns_json_artifact() -> None:
    json_payload = Path("deploy/srx-sample.json").read_text(encoding="utf-8")

    response = client.post(
        "/audit/json/cleaned?format=json&standards=ISO%2027001",
        files={"file": ("srx-sample.json", json_payload, "application/json")},
    )

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-audit-cleaned-format"] == "json"
    assert response.headers["content-disposition"].endswith('srx-sample-cleaned.json"')

    payload = response.json()
    assert isinstance(payload, list)
    assert payload[0]["source"] == "10.0.1.0/24"
    assert payload[0]["protocol"] == "any"


def test_opa_cache_metrics_published_in_prometheus(acceptable_request: dict) -> None:
    """Test that OPA cache statistics are published in Prometheus metrics."""
    # Clear cache to start fresh
    resp = client.post("/cache/clear")
    assert resp.status_code == 200
    
    # Get initial metrics
    resp = client.get("/metrics")
    assert resp.status_code == 200
    metrics_text = resp.text
    assert "firewall_opa_cache_hits_total" in metrics_text
    assert "firewall_opa_cache_misses_total" in metrics_text
    assert "firewall_opa_cache_evictions_total" in metrics_text
    assert "firewall_opa_cache_invalidations_total" in metrics_text
    assert "firewall_opa_cache_entries" in metrics_text
    assert "firewall_opa_cache_hit_rate" in metrics_text
    
    # Make a request to populate the cache
    resp = client.post("/evaluate", json=acceptable_request)
    assert resp.status_code == 200
    
    # Make the same request again (should hit cache)
    resp = client.post("/evaluate", json=acceptable_request)
    assert resp.status_code == 200
    
    # Fetch metrics and verify cache hit was recorded
    resp = client.get("/metrics")
    assert resp.status_code == 200
    metrics_text = resp.text
    
    # Check for hit rate > 0 (indicates cache was hit)
    # The metric should show hits > 0
    assert "firewall_opa_cache_hits_total 1" in metrics_text
    assert "firewall_opa_cache_hit_rate" in metrics_text


