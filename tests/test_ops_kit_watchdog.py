"""Tests for the ops_kit watchdog Slack alerting + dedup logic."""
from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import ops_kit


def _make_args(**overrides) -> argparse.Namespace:
    defaults = dict(
        unit="opa-api-8001.service",
        since_minutes=15,
        failure_threshold=3,
        output_json=None,
        json=False,
        alert_slack=True,
        slack_webhook_url="https://hooks.slack.example/T/B/X",
        alert_cooldown_minutes=15,
        alert_state_file=None,
        alert_timeout=2.0,
        attach_forensics=True,
        forensics_dir=None,
        metrics_url="http://127.0.0.1:8001/metrics",
        textfile_collector_dir=None,  # disabled by default in tests (no node-exporter dir)
        no_textfile_metrics=True,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class _FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self):  # noqa: D401
        return self

    def __exit__(self, *_):  # noqa: D401
        return False


def _fake_run_factory(active="failed", substate="failed", restarts=12, status_code=1):
    show_out = (
        f"ActiveState={active}\n"
        f"SubState={substate}\n"
        f"NRestarts={restarts}\n"
        f"ExecMainStatus={status_code}\n"
        f"ExecMainCode=exited\n"
        f"MainPID=0\n"
        f"FragmentPath=/etc/systemd/system/opa-api-8001.service\n"
    )

    def _fake_run(cmd):
        if "show" in cmd:
            return 0, show_out, ""
        if cmd[0] == "journalctl":
            return 0, "journal line A\njournal line B", ""
        return 0, "", ""

    return _fake_run


def test_watchdog_healthy_does_not_post(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    args = _make_args(alert_state_file=str(tmp_path / "state.json"))
    fake_run = _fake_run_factory(active="active", substate="running", restarts=0, status_code=0)
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit.urllib.request, "urlopen"
    ) as fake_urlopen:
        rc = ops_kit.watchdog_command(args)
    assert rc == 0
    fake_urlopen.assert_not_called()
    out = capsys.readouterr().out
    assert "no restart-loop signal detected" in out


def test_watchdog_unhealthy_posts_slack_and_dedups(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    state_file = tmp_path / "state.json"
    forensics_dir = tmp_path / "forensics"
    args = _make_args(alert_state_file=str(state_file), forensics_dir=str(forensics_dir))
    fake_run = _fake_run_factory()
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", return_value="# HELP fake metrics\nfake_metric 1\n"
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ) as fake_urlopen:
        rc = ops_kit.watchdog_command(args)
    assert rc == 2
    assert fake_urlopen.call_count == 1
    posted_request = fake_urlopen.call_args.args[0]
    body = json.loads(posted_request.data.decode("utf-8"))
    assert "Watchdog" in body["text"]
    # Forensics path must be inlined in the Slack message.
    assert "Forensics:" in body["text"]
    assert state_file.exists()
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert args.unit in persisted
    assert persisted[args.unit]["signature"]
    capsys.readouterr()  # drain

    # Second run with identical diagnosis must dedup within cooldown.
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", return_value="fake"
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ) as fake_urlopen_2:
        rc2 = ops_kit.watchdog_command(args)
    assert rc2 == 2
    fake_urlopen_2.assert_not_called()
    out = capsys.readouterr().out
    assert "deduped" in out


def test_watchdog_dedup_breaks_on_diagnosis_change(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    args = _make_args(
        alert_state_file=str(state_file),
        forensics_dir=str(tmp_path / "forensics"),
    )

    fake_run_1 = _fake_run_factory(active="failed", substate="failed", restarts=12, status_code=1)
    fake_run_2 = _fake_run_factory(active="failed", substate="failed", restarts=99, status_code=0)

    with patch.object(ops_kit, "_run", fake_run_1), patch.object(
        ops_kit, "_http_text", return_value="fake"
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ) as first:
        ops_kit.watchdog_command(args)
    assert first.call_count == 1

    # Different status code → different diagnosis → different signature → re-alert.
    with patch.object(ops_kit, "_run", fake_run_2), patch.object(
        ops_kit, "_http_text", return_value="fake"
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ) as second:
        ops_kit.watchdog_command(args)
    assert second.call_count == 1


def test_watchdog_no_webhook_url_skips_post(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    args = _make_args(slack_webhook_url=None, alert_state_file=str(tmp_path / "state.json"))
    fake_run = _fake_run_factory()
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit.urllib.request, "urlopen"
    ) as fake_urlopen, patch.dict("os.environ", {}, clear=False):
        # Defensive: ensure env var is not set in CI shell.
        ops_kit.os.environ.pop("OPS_KIT_SLACK_WEBHOOK_URL", None)
        rc = ops_kit.watchdog_command(args)
    assert rc == 2
    fake_urlopen.assert_not_called()
    out = capsys.readouterr().out
    assert "skipped" in out


def test_watchdog_post_failure_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    args = _make_args(alert_state_file=str(tmp_path / "state.json"))
    fake_run = _fake_run_factory()

    def boom(*a, **kw):
        raise OSError("connection refused")

    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit.urllib.request, "urlopen", side_effect=boom
    ):
        rc = ops_kit.watchdog_command(args)
    assert rc == 2
    out = capsys.readouterr().out
    assert "post_failed" in out


def test_watchdog_signature_stable_under_diagnosis_order() -> None:
    sig1 = ops_kit._watchdog_signature("u.service", ["A", "B", "C"])
    sig2 = ops_kit._watchdog_signature("u.service", ["C", "A", "B"])
    assert sig1 == sig2

    sig3 = ops_kit._watchdog_signature("u.service", ["A", "B"])
    assert sig1 != sig3


def test_watchdog_json_payload_includes_alert(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        forensics_dir=str(tmp_path / "forensics"),
        json=True,
    )
    fake_run = _fake_run_factory()
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", return_value="fake"
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ):
        ops_kit.watchdog_command(args)
    body = json.loads(capsys.readouterr().out)
    assert body["healthy"] is False
    assert body["alert"]["action"] == "posted"
    assert "signature" in body["alert"]
    assert body["alert"]["forensics_path"]


def test_watchdog_forensics_bundle_written_with_metrics(tmp_path: Path) -> None:
    forensics_dir = tmp_path / "forensics"
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        forensics_dir=str(forensics_dir),
    )
    fake_run = _fake_run_factory()
    metrics_payload = "# HELP foo\nfoo_total 42\n"
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", return_value=metrics_payload
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ):
        ops_kit.watchdog_command(args)

    bundles = sorted(forensics_dir.glob("watchdog-*.json"))
    assert len(bundles) == 1
    bundle = json.loads(bundles[0].read_text(encoding="utf-8"))
    assert bundle["unit"] == args.unit
    assert bundle["systemd_properties"]["ActiveState"] == "failed"
    assert bundle["journal_tail"]
    assert bundle["metrics"] == metrics_payload
    assert bundle["metrics_error"] is None
    assert bundle["diagnosis"]


def test_watchdog_forensics_records_metrics_error_when_endpoint_down(
    tmp_path: Path,
) -> None:
    forensics_dir = tmp_path / "forensics"
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        forensics_dir=str(forensics_dir),
    )
    fake_run = _fake_run_factory()

    def boom(*_a, **_kw):
        raise OSError("connection refused")

    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", side_effect=boom
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ):
        ops_kit.watchdog_command(args)

    bundles = sorted(forensics_dir.glob("watchdog-*.json"))
    assert len(bundles) == 1
    bundle = json.loads(bundles[0].read_text(encoding="utf-8"))
    assert bundle["metrics"] is None
    assert "connection refused" in (bundle["metrics_error"] or "")


def test_watchdog_forensics_skipped_on_dedup(tmp_path: Path) -> None:
    forensics_dir = tmp_path / "forensics"
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        forensics_dir=str(forensics_dir),
    )
    fake_run = _fake_run_factory()
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", return_value="fake"
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ):
        ops_kit.watchdog_command(args)
    first_bundles = sorted(forensics_dir.glob("watchdog-*.json"))
    assert len(first_bundles) == 1

    # Second run with identical diagnosis must dedup AND not write a new bundle
    # (we only forensics-capture when we're about to actually post).
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", return_value="fake"
    ), patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ):
        ops_kit.watchdog_command(args)
    second_bundles = sorted(forensics_dir.glob("watchdog-*.json"))
    assert second_bundles == first_bundles


def test_watchdog_forensics_disabled_via_no_attach_flag(tmp_path: Path) -> None:
    forensics_dir = tmp_path / "forensics"
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        forensics_dir=str(forensics_dir),
        attach_forensics=False,
    )
    fake_run = _fake_run_factory()
    with patch.object(ops_kit, "_run", fake_run), patch.object(
        ops_kit, "_http_text", return_value="fake"
    ) as fake_http, patch.object(
        ops_kit.urllib.request, "urlopen", return_value=_FakeResponse(200)
    ) as fake_urlopen:
        ops_kit.watchdog_command(args)

    # Slack still posted.
    assert fake_urlopen.call_count == 1
    posted = json.loads(fake_urlopen.call_args.args[0].data.decode("utf-8"))
    assert "Forensics:" not in posted["text"]
    # No bundle on disk and no metrics fetch attempted.
    assert not forensics_dir.exists() or list(forensics_dir.iterdir()) == []
    fake_http.assert_not_called()


def test_watchdog_writes_textfile_metrics_on_healthy_run(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Healthy run still emits last_run_timestamp/last_run_healthy=1 so the
    staleness alert can detect a stuck timer even when nothing is wrong."""
    textfile_dir = tmp_path / "node-exporter"
    textfile_dir.mkdir()
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        textfile_collector_dir=str(textfile_dir),
        no_textfile_metrics=False,
    )
    fake_run = _fake_run_factory(active="active", substate="running", restarts=0, status_code=0)
    with patch.object(ops_kit, "_run", fake_run):
        rc = ops_kit.watchdog_command(args)
    capsys.readouterr()
    assert rc == 0

    metric_files = list(textfile_dir.glob("firewall-watchdog-*.prom"))
    assert len(metric_files) == 1
    body = metric_files[0].read_text(encoding="utf-8")
    assert 'firewall_watchdog_last_run_healthy{unit="opa-api-8001.service"} 1' in body
    assert 'firewall_watchdog_restarts{unit="opa-api-8001.service"} 0' in body
    assert "firewall_watchdog_last_run_timestamp_seconds" in body


def test_watchdog_textfile_marks_unhealthy(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Unhealthy run sets last_run_healthy=0 and records the restart count
    so an alert can fire on either the gauge value or staleness."""
    textfile_dir = tmp_path / "node-exporter"
    textfile_dir.mkdir()
    args = _make_args(
        alert_slack=False,  # don't bother with Slack here
        alert_state_file=str(tmp_path / "state.json"),
        textfile_collector_dir=str(textfile_dir),
        no_textfile_metrics=False,
    )
    fake_run = _fake_run_factory()  # default: failed/failed, restarts=12
    with patch.object(ops_kit, "_run", fake_run):
        rc = ops_kit.watchdog_command(args)
    capsys.readouterr()
    assert rc == 2

    body = (textfile_dir / "firewall-watchdog-opa-api-8001_service.prom").read_text(encoding="utf-8")
    assert 'firewall_watchdog_last_run_healthy{unit="opa-api-8001.service"} 0' in body
    assert 'firewall_watchdog_restarts{unit="opa-api-8001.service"} 12' in body


def test_watchdog_textfile_skipped_when_dir_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Missing textfile dir is a soft failure — watchdog must still run."""
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        textfile_collector_dir=str(tmp_path / "does-not-exist"),
        no_textfile_metrics=False,
    )
    fake_run = _fake_run_factory(active="active", substate="running", restarts=0, status_code=0)
    with patch.object(ops_kit, "_run", fake_run):
        rc = ops_kit.watchdog_command(args)
    capsys.readouterr()
    assert rc == 0
    # No metric file written, no exception raised.
    assert not (tmp_path / "does-not-exist").exists()


def test_watchdog_textfile_disabled_via_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """--no-textfile-metrics suppresses the file even when dir exists."""
    textfile_dir = tmp_path / "node-exporter"
    textfile_dir.mkdir()
    args = _make_args(
        alert_state_file=str(tmp_path / "state.json"),
        textfile_collector_dir=str(textfile_dir),
        no_textfile_metrics=True,
    )
    fake_run = _fake_run_factory(active="active", substate="running", restarts=0, status_code=0)
    with patch.object(ops_kit, "_run", fake_run):
        ops_kit.watchdog_command(args)
    capsys.readouterr()
    assert list(textfile_dir.iterdir()) == []
