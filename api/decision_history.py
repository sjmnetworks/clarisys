"""Lightweight persisted decision history for accept/decline verdicts."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from api.atomic_io import atomic_write_json

_lock = threading.Lock()
_MAX_RETENTION_DAYS = 548  # 18 months max retention cap.

# Pruning cadence: avoid O(n²) behavior of pruning on every append.
# Default: prune at most once per hour OR after 1000 appends, whichever comes first.
_PRUNE_INTERVAL_SECONDS = float(os.environ.get("DECISION_HISTORY_PRUNE_INTERVAL_SECONDS", "3600"))
_PRUNE_APPEND_THRESHOLD = int(os.environ.get("DECISION_HISTORY_PRUNE_APPEND_THRESHOLD", "1000"))

# Internal state for prune cadence tracking
_PRUNE_STATE = {
    "last_prune_monotonic": 0.0,
    "appends_since_prune": 0,
}
_PRUNE_STATE_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _history_path() -> Path:
    configured = os.environ.get("DECISION_HISTORY_FILE", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).parent.parent / "policy" / "decision_history.jsonl"


def _lifecycle_path() -> Path:
    configured = os.environ.get("DECISION_LIFECYCLE_FILE", "").strip()
    if configured:
        return Path(configured)
    return Path(__file__).parent.parent / "policy" / "decision_lifecycle.json"


def _retention_days() -> int:
    """Resolve retention with a hard maximum of 18 months."""
    raw = os.environ.get("DECISION_HISTORY_RETENTION_DAYS", "").strip()
    if not raw:
        return _MAX_RETENTION_DAYS
    try:
        requested = int(raw)
    except ValueError:
        return _MAX_RETENTION_DAYS
    if requested < 1:
        return 1
    return min(requested, _MAX_RETENTION_DAYS)


def _prune_expired_entries(path: Path) -> None:
    """Drop records older than configured retention window.

    Malformed lines are discarded during pruning to guarantee retention bounds.
    """
    if not path.exists():
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=_retention_days())
    kept: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            ts_text = row.get("ts")
            if not isinstance(ts_text, str):
                continue
            ts = datetime.fromisoformat(ts_text.replace("Z", "+00:00"))
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        if ts >= cutoff:
            kept.append(line)

    rewritten = "\n".join(kept)
    if rewritten:
        rewritten += "\n"
    path.write_text(rewritten, encoding="utf-8")


def _should_prune_now() -> bool:
    """Return True if pruning should run based on time or append count thresholds.

    Pruning is expensive (full file read+rewrite). To avoid O(n²) behavior when
    appending many entries, we only prune when:
    - First call in the process (bootstrap prune to clean any stale entries), OR
    - At least _PRUNE_INTERVAL_SECONDS have elapsed since last prune, OR
    - At least _PRUNE_APPEND_THRESHOLD appends have occurred since last prune
    """
    now = time.monotonic()
    with _PRUNE_STATE_LOCK:
        last_prune = _PRUNE_STATE["last_prune_monotonic"]
        appends = _PRUNE_STATE["appends_since_prune"]
        elapsed = now - last_prune

        # First call: prune once to ensure clean state, then start tracking
        if last_prune == 0.0:
            _PRUNE_STATE["last_prune_monotonic"] = now
            _PRUNE_STATE["appends_since_prune"] = 0
            return True

        time_threshold_met = elapsed >= _PRUNE_INTERVAL_SECONDS
        append_threshold_met = appends >= _PRUNE_APPEND_THRESHOLD

        if time_threshold_met or append_threshold_met:
            _PRUNE_STATE["last_prune_monotonic"] = now
            _PRUNE_STATE["appends_since_prune"] = 0
            return True

        _PRUNE_STATE["appends_since_prune"] = appends + 1
        return False


def force_prune() -> dict[str, Any]:
    """Force an immediate prune. Returns metrics about the prune operation."""
    path = _history_path()
    start_time = time.monotonic()
    initial_size_bytes = path.stat().st_size if path.exists() else 0

    with _lock:
        _prune_expired_entries(path)
        with _PRUNE_STATE_LOCK:
            _PRUNE_STATE["last_prune_monotonic"] = time.monotonic()
            _PRUNE_STATE["appends_since_prune"] = 0

    final_size_bytes = path.stat().st_size if path.exists() else 0
    return {
        "pruned": True,
        "initial_size_bytes": initial_size_bytes,
        "final_size_bytes": final_size_bytes,
        "bytes_freed": initial_size_bytes - final_size_bytes,
        "duration_ms": round((time.monotonic() - start_time) * 1000, 3),
    }


def prune_stats() -> dict[str, Any]:
    """Return current pruning state metrics."""
    path = _history_path()
    with _PRUNE_STATE_LOCK:
        last_prune = _PRUNE_STATE["last_prune_monotonic"]
        appends = _PRUNE_STATE["appends_since_prune"]

    now = time.monotonic()
    seconds_since_prune = (now - last_prune) if last_prune > 0 else None

    return {
        "history_file": str(path),
        "history_size_bytes": path.stat().st_size if path.exists() else 0,
        "prune_interval_seconds": _PRUNE_INTERVAL_SECONDS,
        "prune_append_threshold": _PRUNE_APPEND_THRESHOLD,
        "appends_since_last_prune": appends,
        "seconds_since_last_prune": seconds_since_prune,
        "retention_days": _retention_days(),
    }


def append_decision_history(entry: dict[str, Any]) -> None:
    """Append one decision entry to the JSONL history file.

    Pruning is deferred — only runs when time/append thresholds are met,
    avoiding O(n²) cost of full-file rewrite on every append.
    """
    payload = {"ts": _utc_now_iso(), **entry}
    line = json.dumps(payload, separators=(",", ":"), default=str) + "\n"

    path = _history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        if _should_prune_now():
            _prune_expired_entries(path)
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()


def list_recent_decisions(limit: int = 100, caller_sub: str | None = None, tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Return the most recent history entries first.

    If tenant_id is provided, only entries for that tenant are returned.
    Falls back to caller_sub filtering for backward compatibility.
    """
    path = _history_path()
    if not path.exists():
        return []

    with _lock:
        lines = path.read_text(encoding="utf-8").splitlines()

    rows: list[dict[str, Any]] = []
    for line in reversed(lines):
        if len(rows) >= limit:
            break
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if tenant_id:
            if entry.get("tenant_id") != tenant_id:
                continue
        elif caller_sub is not None and entry.get("caller_sub") != caller_sub:
            continue
        rows.append(entry)
    return rows


def set_decision_lifecycle(
    *,
    decision_id: str,
    status: str,
    actor: str,
    notes: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Create or update lifecycle state for a decision id."""
    path = _lifecycle_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        if path.exists():
            try:
                current = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                current = {}
        else:
            current = {}

        lifecycle = current.get(decision_id, {})
        lifecycle.update(
            {
                "decision_id": decision_id,
                "status": status,
                "actor": actor,
                "notes": notes,
                "expires_at": expires_at,
                "updated_at": _utc_now_iso(),
            }
        )
        current[decision_id] = lifecycle
        atomic_write_json(path, current, indent=2)
        return lifecycle


def get_decision_lifecycle(decision_id: str) -> dict[str, Any] | None:
    path = _lifecycle_path()
    if not path.exists():
        return None
    with _lock:
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    value = current.get(decision_id)
    return value if isinstance(value, dict) else None
