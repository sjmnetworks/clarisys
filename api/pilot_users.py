"""
Pilot-phase local user store.

Users are stored in a JSON file (default: policy/pilot_users.json).
API keys are never stored in plaintext — only their SHA-256 hex digest is persisted.

File format:
    {
      "users": [
        {
          "username": "alice",
          "email": "alice@example.com",
          "key_hash": "<sha256-hex>",
          "scopes": ["firewall.evaluate", "firewall.read"],
          "created_at": "2026-05-18T10:00:00Z",
          "enabled": true
        }
      ]
    }

Environment variables:
    PILOT_USERS_FILE   Path to the JSON store (default: policy/pilot_users.json)
    PILOT_AUTH_ENABLED "true" | "false"  (default: "true" when file exists)
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from api.atomic_io import atomic_write_json

_LOCK = threading.Lock()

_DEFAULT_FILE = Path(__file__).parent.parent / "policy" / "pilot_users.json"

VALID_SCOPES = frozenset(
    {"firewall.evaluate", "firewall.audit", "firewall.read", "firewall.admin"}
)


def _store_path() -> Path:
    return Path(os.environ.get("PILOT_USERS_FILE", str(_DEFAULT_FILE)))


def hash_key(raw_key: str) -> str:
    """Return the SHA-256 hex digest of a raw API key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _load() -> dict:
    p = _store_path()
    if not p.exists():
        return {"users": []}
    with open(p) as f:
        return json.load(f)


def _save(data: dict) -> None:
    p = _store_path()
    # atomic_write_json handles parent mkdir + temp-file + fsync + os.replace.
    atomic_write_json(p, data, indent=2)


@dataclass(frozen=True)
class PilotUser:
    username: str
    email: str
    scopes: frozenset[str]
    tenant_id: str


def lookup_by_key(raw_key: str) -> PilotUser | None:
    """Return the PilotUser matching the raw API key, or None."""
    digest = hash_key(raw_key)
    data = _load()
    for entry in data.get("users", []):
        if entry.get("enabled", True) and entry.get("key_hash") == digest:
            return PilotUser(
                username=entry["username"],
                email=entry.get("email", ""),
                scopes=frozenset(entry.get("scopes", [])),
                tenant_id=entry.get("tenant_id", ""),
            )
    return None


def add_user(
    username: str,
    email: str,
    raw_key: str,
    scopes: list[str],
) -> None:
    """Add or replace a user in the store (thread-safe)."""
    unknown = set(scopes) - VALID_SCOPES
    if unknown:
        raise ValueError(f"Unknown scopes: {unknown}. Valid: {sorted(VALID_SCOPES)}")
    with _LOCK:
        data = _load()
        # Remove any existing entry with the same username
        data["users"] = [u for u in data["users"] if u["username"] != username]
        from datetime import datetime, timezone
        data["users"].append(
            {
                "username": username,
                "email": email,
                "key_hash": hash_key(raw_key),
                "scopes": sorted(scopes),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "enabled": True,
            }
        )
        _save(data)


def disable_user(username: str) -> bool:
    """Disable a user by username. Returns True if found."""
    with _LOCK:
        data = _load()
        found = False
        for entry in data["users"]:
            if entry["username"] == username:
                entry["enabled"] = False
                found = True
        if found:
            _save(data)
        return found


def list_users() -> list[dict]:
    """Return all user records (key hashes included, never raw keys)."""
    return _load().get("users", [])
