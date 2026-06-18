"""Tests for crash-safe JSON state-file writes.

The pattern (temp-file + fsync + os.replace) must guarantee that the
target path always either reflects the previous good snapshot or the new
payload in full, never a truncated/half-written file.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.atomic_io import atomic_write_json


def test_atomic_write_creates_target_file(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    payload = {"k": "v", "n": 1}
    atomic_write_json(target, payload)
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8")) == payload


def test_atomic_write_creates_parent_dir(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "deeply" / "state.json"
    atomic_write_json(target, {"ok": True})
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}


def test_atomic_write_uses_tmp_then_replace(tmp_path: Path) -> None:
    """After a successful write no writer-owned temp files must linger."""
    target = tmp_path / "state.json"
    atomic_write_json(target, {"a": 1})
    tmp_candidates = list(target.parent.glob(target.name + ".*.tmp"))
    assert not tmp_candidates, "writer-owned temp files should be replaced atomically"


def test_atomic_write_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    atomic_write_json(target, {"v": 1})
    atomic_write_json(target, {"v": 2})
    assert json.loads(target.read_text(encoding="utf-8")) == {"v": 2}


def test_partial_tmp_file_does_not_corrupt_target(tmp_path: Path) -> None:
    """If a crash leaves a truncated .tmp file, the target snapshot must
    still be the last good payload (loaders never read .tmp)."""
    target = tmp_path / "state.json"
    atomic_write_json(target, {"good": True})

    # Simulate a crash mid-write: a half-written .tmp sidecar appears.
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text('{"truncated": tr', encoding="utf-8")

    # Target must still hold the last good payload.
    assert json.loads(target.read_text(encoding="utf-8")) == {"good": True}

    # The next successful write must replace target cleanly.
    atomic_write_json(target, {"good": "again"})
    assert json.loads(target.read_text(encoding="utf-8")) == {"good": "again"}


def test_serialization_failure_preserves_target(tmp_path: Path) -> None:
    """If json.dumps raises (non-serialisable payload), the existing
    target file must remain untouched and no partial tmp must remain."""
    target = tmp_path / "state.json"
    atomic_write_json(target, {"keep": "me"})

    class NotSerialisable:
        pass

    with pytest.raises(TypeError):
        atomic_write_json(target, {"bad": NotSerialisable()})

    # Target unchanged.
    assert json.loads(target.read_text(encoding="utf-8")) == {"keep": "me"}
    # No stray tmp (json.dumps fails before the file is opened).
    assert not target.with_name(target.name + ".tmp").exists()


def test_indent_and_separators_passthrough(tmp_path: Path) -> None:
    target = tmp_path / "pretty.json"
    atomic_write_json(target, {"a": 1, "b": 2}, indent=2)
    content = target.read_text(encoding="utf-8")
    assert "\n  " in content  # indent applied

    compact = tmp_path / "compact.json"
    atomic_write_json(compact, {"a": 1, "b": 2}, separators=(",", ":"))
    assert compact.read_text(encoding="utf-8") == '{"a":1,"b":2}'


def test_roi_save_state_uses_atomic_write(tmp_path: Path, monkeypatch) -> None:
    """ROI save_state must go through atomic_write_json (no .tmp lingering,
    target reflects the in-memory payload)."""
    from api import roi_metrics

    state_file = tmp_path / "roi-metrics.json"
    monkeypatch.setattr(roi_metrics, "ROI_METRICS_STATE_FILE", state_file)
    monkeypatch.setattr(roi_metrics, "_METRICS_STATE", {"total_rules": 7, "last_updated": 123})
    monkeypatch.setattr(roi_metrics, "_SEEN_REQUEST_IDS", {"a", "b"})

    roi_metrics._save_state()
    assert state_file.exists()
    payload = json.loads(state_file.read_text(encoding="utf-8"))
    assert payload["total_rules"] == 7
    assert payload["last_updated"] == 123
    assert sorted(payload["seen_request_ids"]) == ["a", "b"]
    assert not list(state_file.parent.glob(state_file.name + ".*.tmp"))


def test_atomic_write_same_target_concurrent_writers(tmp_path: Path) -> None:
    """Concurrent writes to the same target must not trip over a shared temp path."""
    target = tmp_path / "state.json"

    def _write(i: int) -> None:
        atomic_write_json(target, {"value": i})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_write, range(40)))

    payload = json.loads(target.read_text(encoding="utf-8"))
    assert isinstance(payload.get("value"), int)
    assert 0 <= payload["value"] < 40
    assert not list(target.parent.glob(target.name + ".*.tmp"))
