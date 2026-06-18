"""Tests for tools/pilot_key_age.py — exporter + rotation.

Both modes are exercised against a temporary pilot_users.json so the
prod store at policy/pilot_users.json is never touched.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


# Load the tool as a module — it isn't packaged.
_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "pilot_key_age.py"
_spec = importlib.util.spec_from_file_location("_pilot_key_age", _TOOL_PATH)
assert _spec is not None and _spec.loader is not None
pilot_key_age = importlib.util.module_from_spec(_spec)
sys.modules["_pilot_key_age"] = pilot_key_age
_spec.loader.exec_module(pilot_key_age)


def _make_store(tmp_path: Path, users: list[dict]) -> Path:
    p = tmp_path / "pilot_users.json"
    p.write_text(json.dumps({"users": users}, indent=2))
    return p


# ── exporter ─────────────────────────────────────────────────────────────────
def test_exporter_writes_textfile_with_age(tmp_path: Path) -> None:
    """Exporter renders age in days and the per-user gauge line."""
    created = (datetime.now(timezone.utc) - timedelta(days=42)).isoformat()
    store = _make_store(tmp_path, [
        {"username": "alice", "email": "a@x", "key_hash": "x" * 64,
         "scopes": [], "created_at": created, "enabled": True},
    ])
    textfile_dir = tmp_path / "textfile"
    textfile_dir.mkdir()
    rc = pilot_key_age.export_metrics(store, textfile_dir)
    assert rc == 0
    body = (textfile_dir / pilot_key_age.TEXTFILE_NAME).read_text()
    assert "firewall_pilot_key_age_days" in body
    assert 'username="alice"' in body
    assert 'enabled="true"' in body
    # Age should be ~42 days (allow drift for clock + scheduler).
    line = next(l for l in body.splitlines() if l.startswith("firewall_pilot_key_age_days{"))
    age = float(line.rsplit(" ", 1)[-1])
    assert 41.5 < age < 42.5


def test_exporter_prefers_rotated_at_over_created_at(tmp_path: Path) -> None:
    """rotated_at is the source of truth; created_at is a fallback only."""
    created = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    rotated = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    store = _make_store(tmp_path, [
        {"username": "bob", "key_hash": "y" * 64, "scopes": [],
         "created_at": created, "rotated_at": rotated, "enabled": True},
    ])
    textfile_dir = tmp_path / "textfile"
    textfile_dir.mkdir()
    pilot_key_age.export_metrics(store, textfile_dir)
    body = (textfile_dir / pilot_key_age.TEXTFILE_NAME).read_text()
    line = next(l for l in body.splitlines() if l.startswith("firewall_pilot_key_age_days{"))
    age = float(line.rsplit(" ", 1)[-1])
    assert 9.5 < age < 10.5, "must use rotated_at, not created_at, when both present"


def test_exporter_skips_users_without_birth_timestamp(tmp_path: Path) -> None:
    """No created_at AND no rotated_at => no metric emitted (no -1 sentinel
    that would silently dodge the > 90-day alert)."""
    store = _make_store(tmp_path, [
        {"username": "ghost", "key_hash": "z" * 64, "scopes": [], "enabled": True},
    ])
    textfile_dir = tmp_path / "textfile"
    textfile_dir.mkdir()
    pilot_key_age.export_metrics(store, textfile_dir)
    body = (textfile_dir / pilot_key_age.TEXTFILE_NAME).read_text()
    assert "firewall_pilot_key_age_days{" not in body
    # But the count metric still appears.
    assert "firewall_pilot_key_count" in body


def test_exporter_emits_enabled_disabled_counts(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    store = _make_store(tmp_path, [
        {"username": "a", "key_hash": "a" * 64, "scopes": [], "created_at": now, "enabled": True},
        {"username": "b", "key_hash": "b" * 64, "scopes": [], "created_at": now, "enabled": True},
        {"username": "c", "key_hash": "c" * 64, "scopes": [], "created_at": now, "enabled": False},
    ])
    textfile_dir = tmp_path / "textfile"
    textfile_dir.mkdir()
    pilot_key_age.export_metrics(store, textfile_dir)
    body = (textfile_dir / pilot_key_age.TEXTFILE_NAME).read_text()
    assert 'firewall_pilot_key_count{enabled="true"} 2' in body
    assert 'firewall_pilot_key_count{enabled="false"} 1' in body


def test_exporter_escapes_dangerous_chars_in_username(tmp_path: Path) -> None:
    """Label values must escape \\, \", and newlines (Prom textformat rule)."""
    now = datetime.now(timezone.utc).isoformat()
    store = _make_store(tmp_path, [
        {"username": 'evil"name\\here', "key_hash": "x" * 64,
         "scopes": [], "created_at": now, "enabled": True},
    ])
    textfile_dir = tmp_path / "textfile"
    textfile_dir.mkdir()
    pilot_key_age.export_metrics(store, textfile_dir)
    body = (textfile_dir / pilot_key_age.TEXTFILE_NAME).read_text()
    # Should contain the escaped form, not the raw quote (which would
    # terminate the label early and break parsing).
    assert 'username="evil\\"name\\\\here"' in body


# ── rotation ─────────────────────────────────────────────────────────────────
def test_rotate_key_replaces_hash_and_sets_rotated_at(tmp_path: Path) -> None:
    """Rotation updates key_hash, sets rotated_at, leaves created_at intact,
    and returns a fresh raw key whose hash matches the new key_hash."""
    created = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    old_hash = "0" * 64
    store = _make_store(tmp_path, [
        {"username": "alice", "key_hash": old_hash, "scopes": ["firewall.read"],
         "created_at": created, "enabled": True},
    ])
    rc, raw = pilot_key_age.rotate_key(store, "alice")
    assert rc == 0
    assert raw is not None
    assert hashlib.sha256(raw.encode()).hexdigest() != old_hash
    data = json.loads(store.read_text())
    user = data["users"][0]
    assert user["key_hash"] == hashlib.sha256(raw.encode()).hexdigest()
    assert user["created_at"] == created  # untouched
    assert user.get("rotated_at"), "rotated_at must be set"
    # rotated_at must be parseable + recent
    rotated = datetime.fromisoformat(user["rotated_at"].replace("Z", "+00:00"))
    assert (datetime.now(timezone.utc) - rotated).total_seconds() < 5


def test_rotate_key_unknown_user_fails_without_writing(tmp_path: Path) -> None:
    """Unknown username must error out and leave the file byte-identical."""
    now = datetime.now(timezone.utc).isoformat()
    store = _make_store(tmp_path, [
        {"username": "alice", "key_hash": "a" * 64, "scopes": [], "created_at": now, "enabled": True},
    ])
    before = store.read_bytes()
    rc, raw = pilot_key_age.rotate_key(store, "nobody")
    assert rc == 1 and raw is None
    assert store.read_bytes() == before
