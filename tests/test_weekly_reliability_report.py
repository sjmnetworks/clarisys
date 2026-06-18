"""Contract tests for tools/weekly_reliability_report.py."""
from __future__ import annotations

import csv
import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path


_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "weekly_reliability_report.py"
_spec = importlib.util.spec_from_file_location("_weekly_reliability_report", _TOOL_PATH)
assert _spec is not None and _spec.loader is not None
weekly_reliability_report = importlib.util.module_from_spec(_spec)
sys.modules["_weekly_reliability_report"] = weekly_reliability_report
_spec.loader.exec_module(weekly_reliability_report)


def _sample_metrics() -> dict[str, float | str]:
    return {
        "service_up": 1.0,
        "error_budget_burn_fast": 0.1,
        "error_budget_burn_slow": 0.2,
        "api_latency_p95_ms": 31.0,
        "opa_latency_p95_ms": 18.0,
        "canary_pass": 1.0,
        "state_write_failures_15m": 0.0,
        "rate_limited_5m": 0.0,
        "requests_rps_5m": 12.5,
        "decisions_total": 1234.0,
        "deny_ratio_1h": 0.01,
        "oldest_enabled_pilot_key_days": 17.0,
        "pilot_key_exporter_age_hours": 2.0,
    }


def test_render_markdown_contract_contains_core_sections() -> None:
    ts = datetime(2026, 6, 12, 10, 11, 12, tzinfo=timezone.utc)
    body = weekly_reliability_report.render_markdown(ts, _sample_metrics(), "ok")

    assert "# Weekly Reliability Report - 2026-06-12 10:11:12 UTC" in body
    assert "Overall status: **OK**" in body
    assert "## Summary" in body
    assert "- Service up: 1.0" in body
    assert "- Request volume (RPS, 5m): 12.5" in body
    assert "## Notes" in body
    assert body.endswith("\n")


def test_append_csv_writes_header_once_and_appends_rows(tmp_path: Path) -> None:
    csv_path = tmp_path / "history.csv"
    ts1 = datetime(2026, 6, 12, 10, 0, 0, tzinfo=timezone.utc)
    ts2 = datetime(2026, 6, 12, 11, 0, 0, tzinfo=timezone.utc)
    metrics = _sample_metrics()

    weekly_reliability_report.append_csv(csv_path, ts1, "ok", metrics)
    weekly_reliability_report.append_csv(csv_path, ts2, "warning", metrics)

    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))

    assert rows[0] == ["generated_at", "status", *metrics.keys()]
    assert len(rows) == 3
    assert rows[1][1] == "ok"
    assert rows[2][1] == "warning"


def test_main_generates_dated_latest_and_csv_files(tmp_path: Path, monkeypatch) -> None:
    fixed_ts = datetime(2026, 6, 12, 12, 34, 56, tzinfo=timezone.utc)

    class _FixedDatetime:
        @staticmethod
        def now(tz: timezone) -> datetime:
            assert tz is timezone.utc
            return fixed_ts

    monkeypatch.setattr(weekly_reliability_report, "datetime", _FixedDatetime)
    monkeypatch.setattr(weekly_reliability_report, "prom_query", lambda *args, **kwargs: 1.0)

    def _status(metrics: dict[str, float | str]) -> str:
        assert set(metrics.keys()) == set(weekly_reliability_report.QUERIES.keys())
        return "ok"

    monkeypatch.setattr(weekly_reliability_report, "classify_status", _status)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "weekly_reliability_report.py",
            "--prom-url",
            "http://prometheus.local:9090",
            "--report-dir",
            str(tmp_path),
        ],
    )

    rc = weekly_reliability_report.main()
    assert rc == 0

    dated = tmp_path / "reliability-weekly-20260612T123456Z.md"
    latest = tmp_path / "reliability-weekly-latest.md"
    history = tmp_path / "reliability-weekly-history.csv"

    assert dated.exists()
    assert latest.exists()
    assert history.exists()

    dated_body = dated.read_text(encoding="utf-8")
    latest_body = latest.read_text(encoding="utf-8")
    assert "Overall status: **OK**" in dated_body
    assert dated_body == latest_body
