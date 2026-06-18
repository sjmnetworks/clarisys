"""Tests for ROI state-drift reconciliation at startup.

When the on-disk snapshot disagrees materially with the decision-history
file, _load_state() must log a structured warning and increment the
firewall_roi_state_drift_total counter. Reproduces the 2026-06-10 incident
where total_rules drifted 50 → 22 on restart.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import roi_metrics


def _read_drift_counter(direction: str) -> float:
    """Return the current value of the drift counter for a given direction."""
    metric = roi_metrics.roi_state_drift_counter.labels(direction=direction)
    # prometheus_client Counter stores the value on _value.get()
    return metric._value.get()


def _read_autocorrect_counter(direction: str) -> float:
    metric = roi_metrics.roi_state_drift_autocorrect_counter.labels(direction=direction)
    return metric._value.get()


def _write_history(path: Path, count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"request_id": f"req-{i}", "ts": "2026-06-10T12:00:00Z"})
        for i in range(count)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_snapshot(path: Path, total_rules: int, seen_ids: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "total_rules": total_rules,
        "last_updated": 1781100000,
        "seen_request_ids": seen_ids or [],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_count_rules_in_history_returns_minus_one_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    history_path = tmp_path / "decision_history.jsonl"
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )
    assert roi_metrics._count_rules_in_history() == -1


def test_count_rules_in_history_counts_valid_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    history_path = tmp_path / "decision_history.jsonl"
    _write_history(history_path, 22)
    # Add one blank line and one malformed row to verify they are skipped.
    with history_path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
        fh.write("not valid json\n")
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )
    assert roi_metrics._count_rules_in_history() == 22


def test_drift_check_no_history_does_not_increment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    history_path = tmp_path / "decision_history.jsonl"  # absent
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )
    before_high = _read_drift_counter("snapshot_high")
    before_low = _read_drift_counter("snapshot_low")
    roi_metrics._check_state_drift(disk_total=99)
    assert _read_drift_counter("snapshot_high") == before_high
    assert _read_drift_counter("snapshot_low") == before_low


def test_drift_check_within_threshold_does_not_increment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    history_path = tmp_path / "decision_history.jsonl"
    _write_history(history_path, 100)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )
    before_high = _read_drift_counter("snapshot_high")
    # Threshold is max(5, 10% of 100) = 10. Delta of 4 is below threshold.
    roi_metrics._check_state_drift(disk_total=104)
    assert _read_drift_counter("snapshot_high") == before_high


def test_drift_check_snapshot_high_increments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Reproduces the 2026-06-10 incident: in-memory snapshot held 50,
    history truth was 22. delta=+28 vs threshold=max(5, 2)=5. Must fire."""
    history_path = tmp_path / "decision_history.jsonl"
    _write_history(history_path, 22)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )
    before = _read_drift_counter("snapshot_high")
    with caplog.at_level("WARNING"):
        roi_metrics._check_state_drift(disk_total=50)
    after = _read_drift_counter("snapshot_high")
    assert after == before + 1


def test_drift_check_snapshot_low_increments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    history_path = tmp_path / "decision_history.jsonl"
    _write_history(history_path, 100)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )
    before = _read_drift_counter("snapshot_low")
    # disk_total=80, history=100, delta=-20, threshold=max(5,10)=10. Must fire.
    roi_metrics._check_state_drift(disk_total=80)
    after = _read_drift_counter("snapshot_low")
    assert after == before + 1


def test_load_state_calls_drift_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bootstrap path: when _load_state finds a snapshot, drift check
    must run against the history-derived count.

    Note: drift of 50 vs 22 (~127% relative) is above the auto-correct
    threshold, so we expect _load_state to discard the snapshot and
    rebuild from history. _METRICS_STATE should end up at 22, not 50."""
    history_path = tmp_path / "decision_history.jsonl"
    snapshot_path = tmp_path / "roi-metrics.json"
    _write_history(history_path, 22)
    _write_snapshot(snapshot_path, total_rules=50)

    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", snapshot_path)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )

    before_drift = _read_drift_counter("snapshot_high")
    before_auto = _read_autocorrect_counter("snapshot_high")
    roi_metrics._load_state()
    assert _read_drift_counter("snapshot_high") == before_drift + 1
    assert _read_autocorrect_counter("snapshot_high") == before_auto + 1
    # State now reflects history truth, not the bad snapshot.
    assert roi_metrics._METRICS_STATE["total_rules"] == 22


def test_load_state_drift_below_autocorrect_keeps_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drift triggers warning but stays below auto-correct threshold:
    snapshot must be preserved (caller's bookkeeping is still valid)."""
    history_path = tmp_path / "decision_history.jsonl"
    snapshot_path = tmp_path / "roi-metrics.json"
    _write_history(history_path, 100)
    # delta=+15 (15%), threshold=max(5, 10) = 10 → warns,
    # but rel = 15/100 = 0.15 < 0.5 → no auto-correct.
    _write_snapshot(snapshot_path, total_rules=115)

    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", snapshot_path)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )

    before_drift = _read_drift_counter("snapshot_high")
    before_auto = _read_autocorrect_counter("snapshot_high")
    roi_metrics._load_state()
    assert _read_drift_counter("snapshot_high") == before_drift + 1
    assert _read_autocorrect_counter("snapshot_high") == before_auto  # NOT incremented
    assert roi_metrics._METRICS_STATE["total_rules"] == 115  # snapshot retained


def test_load_state_extreme_drift_rebuilds_and_persists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reproduces the 2026-06-11 incident: snapshot=22 vs history=505.
    Auto-correct must rebuild from history AND re-write the snapshot
    so the next restart starts clean."""
    history_path = tmp_path / "decision_history.jsonl"
    snapshot_path = tmp_path / "roi-metrics.json"
    _write_history(history_path, 505)
    _write_snapshot(snapshot_path, total_rules=22)

    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", snapshot_path)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )

    before_auto = _read_autocorrect_counter("snapshot_low")
    roi_metrics._load_state()

    # In-memory state corrected.
    assert roi_metrics._METRICS_STATE["total_rules"] == 505
    # Auto-correct counter incremented.
    assert _read_autocorrect_counter("snapshot_low") == before_auto + 1
    # On-disk snapshot rewritten with the corrected total.
    persisted = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert persisted["total_rules"] == 505


def test_load_state_no_drift_when_aligned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    history_path = tmp_path / "decision_history.jsonl"
    snapshot_path = tmp_path / "roi-metrics.json"
    _write_history(history_path, 25)
    _write_snapshot(snapshot_path, total_rules=26)  # 1-row skew = within threshold

    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", snapshot_path)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )

    before_high = _read_drift_counter("snapshot_high")
    before_low = _read_drift_counter("snapshot_low")
    roi_metrics._load_state()
    assert _read_drift_counter("snapshot_high") == before_high
    assert _read_drift_counter("snapshot_low") == before_low


def test_bootstrap_from_history_clears_stale_dedup_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bug 2 (2026-06-10): when the snapshot was rebuilt from history we
    kept the old _SEEN_REQUEST_IDS, leaving the dedup set permanently out
    of sync with total_rules. Composite bulk/stream keys can't be
    reconstructed from history so the safe move is to drop them and let
    new traffic repopulate the set."""
    history_path = tmp_path / "decision_history.jsonl"
    snapshot_path = tmp_path / "roi-metrics.json"
    _write_history(history_path, 100)
    # Snapshot has 20 stale dedup keys from yesterday's run.
    # delta=80 > 50% threshold → triggers autocorrect → bootstrap path.
    stale_keys = [f"stale-req-{i}" for i in range(20)]
    _write_snapshot(snapshot_path, total_rules=20, seen_ids=stale_keys)

    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", snapshot_path)
    monkeypatch.setattr(
        roi_metrics.decision_history, "_history_path", lambda: history_path
    )

    roi_metrics._load_state()

    # Counter rebuilt from history.
    assert roi_metrics._METRICS_STATE["total_rules"] == 100
    # Stale dedup keys must be gone — otherwise the next request that
    # collides with one would silently fail to count.
    assert len(roi_metrics._SEEN_REQUEST_IDS) == 0
