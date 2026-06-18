"""Tests for audit-store path resilience (dev/test friendliness)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import audit_store


def _clear_audit_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("AUDIT_BACKEND", "AUDIT_DIR", "AUDIT_S3_BUCKET"):
        monkeypatch.delenv(key, raising=False)


def test_local_store_normal_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _clear_audit_env(monkeypatch)
    monkeypatch.setenv("AUDIT_DIR", str(tmp_path / "audit"))
    store = audit_store._build_from_env()
    assert isinstance(store, audit_store.LocalJsonlAuditStore)
    assert store.base_dir == tmp_path / "audit"
    assert store.base_dir.exists()


def test_default_path_falls_back_when_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """When AUDIT_DIR is not set and the default /var/log path is unwritable,
    the store must fall back to ~/.firewall-api/audit/ instead of crashing."""
    _clear_audit_env(monkeypatch)

    # Force LocalJsonlAuditStore's mkdir to fail on the default system path
    # but succeed on the user-home fallback.
    real_mkdir = Path.mkdir
    default_path = Path("/var/log/firewall-audit")
    fallback_root = tmp_path / "fake-home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fallback_root))

    def fake_mkdir(self, *args, **kwargs):
        if self == default_path or default_path in self.parents:
            raise PermissionError(13, "Permission denied", str(self))
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)

    store = audit_store._build_from_env()
    assert isinstance(store, audit_store.LocalJsonlAuditStore)
    assert store.base_dir == fallback_root / ".firewall-api" / "audit"
    assert store.base_dir.exists()
    captured = capsys.readouterr()
    assert "falling back" in captured.err


def test_explicit_path_raises_when_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If the operator explicitly set AUDIT_DIR and it isn't writable, we
    must fail loudly — silent fallback would split the audit trail."""
    _clear_audit_env(monkeypatch)
    explicit_path = tmp_path / "operator-chosen" / "audit"
    monkeypatch.setenv("AUDIT_DIR", str(explicit_path))

    real_mkdir = Path.mkdir

    def fake_mkdir(self, *args, **kwargs):
        if str(self).startswith(str(tmp_path / "operator-chosen")):
            raise PermissionError(13, "Permission denied", str(self))
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)

    with pytest.raises(PermissionError):
        audit_store._build_from_env()


def test_noop_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_audit_env(monkeypatch)
    monkeypatch.setenv("AUDIT_BACKEND", "noop")
    store = audit_store._build_from_env()
    assert isinstance(store, audit_store.NoopAuditStore)


def test_local_store_records_jsonl(tmp_path: Path) -> None:
    store = audit_store.LocalJsonlAuditStore(base_dir=tmp_path)
    store.record({"a": 1, "b": "two"})
    store.record({"a": 2, "b": "three"})
    files = list(tmp_path.glob("audit-*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
