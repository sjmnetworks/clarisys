"""Regression: tests must not mutate production state files.

Without the conftest reroute, /evaluate calls through TestClient append to
the live ~/.firewall-api/roi-metrics.json and policy/decision_history.jsonl,
inflating prod ROI counters with synthetic test traffic.

These tests assert the isolation is wired correctly so a future conftest
regression fails loudly instead of silently re-contaminating prod.
"""
from __future__ import annotations

import os
from pathlib import Path

from api import decision_history, roi_metrics


def test_roi_state_file_redirected_to_tmp(test_state_dir: Path) -> None:
    expected = test_state_dir / "roi-metrics.json"
    assert roi_metrics.ROI_METRICS_STATE_FILE == expected, (
        f"roi_metrics.ROI_METRICS_STATE_FILE = {roi_metrics.ROI_METRICS_STATE_FILE!r}, "
        f"expected {expected!r}. conftest.py must set the env var BEFORE the "
        "first `import api.roi_metrics`."
    )
    # Production path must NOT be the resolved target.
    prod = Path.home() / ".firewall-api" / "roi-metrics.json"
    assert roi_metrics.ROI_METRICS_STATE_FILE != prod


def test_decision_history_path_redirected_to_tmp(test_state_dir: Path) -> None:
    resolved = decision_history._history_path()
    assert resolved == test_state_dir / "decision_history.jsonl", (
        f"_history_path() = {resolved!r}; expected to land inside the test "
        "state dir."
    )


def test_audit_dir_env_points_at_tmp(test_state_dir: Path) -> None:
    assert os.environ["AUDIT_DIR"] == str(test_state_dir / "audit")


def test_evaluate_does_not_touch_prod_state_files(test_state_dir: Path) -> None:
    """Smoke test: a real /evaluate call hits the rerouted history file,
    not the prod one."""
    from starlette.testclient import TestClient

    from api.main import app

    history_file = test_state_dir / "decision_history.jsonl"
    before = history_file.stat().st_size if history_file.exists() else 0

    client = TestClient(app)
    response = client.post(
        "/evaluate",
        json={
            "source": "10.157.26.5",
            "destination": "10.221.126.33",
            "protocol": "tcp",
            "port": 443,
            "log": "all",
            "data_classification": "Internal",
            "source_interface": "finance-src",
            "destination_interface": "analytics-dst",
        },
    )
    assert response.status_code == 200, response.text

    after = history_file.stat().st_size if history_file.exists() else 0
    assert after > before, (
        "expected /evaluate to append to the rerouted decision_history.jsonl; "
        "if it didn't, the redirect is broken and prod history is being written"
    )

    # Hard guard: prod history file must not have been written by this test
    # run. We can't easily diff prod (other processes may write it) but we
    # can at least assert the resolved path differs.
    prod = Path(__file__).resolve().parents[1] / "policy" / "decision_history.jsonl"
    assert history_file != prod
