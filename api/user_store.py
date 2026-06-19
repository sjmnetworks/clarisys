"""
Local user store for email/password and Google SSO authentication.

Users are stored in a JSON file (default: policy/users.json).
Passwords are hashed with bcrypt.

File format:
    {
      "tenants": [
        {
          "id": "t_<hex8>",
          "name": "Acme Corp",
          "created_at": "2026-06-19T10:00:00Z"
        }
      ],
      "users": [
        {
          "id": "u_<hex8>",
          "tenant_id": "t_<hex8>",
          "email": "alice@example.com",
          "username": "alice",
          "password_hash": "$2b$12$...",
          "provider": "email" | "google",
          "role": "owner" | "member",
          "scopes": ["firewall.evaluate", "firewall.read"],
          "created_at": "2026-06-19T10:00:00Z",
          "enabled": true
        }
      ]
    }
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import bcrypt

from api.atomic_io import atomic_write_json

_LOCK = threading.Lock()
_DEFAULT_FILE = Path(__file__).parent.parent / "policy" / "users.json"

DEFAULT_SCOPES = frozenset({"firewall.evaluate", "firewall.read"})
OWNER_SCOPES = frozenset({"firewall.evaluate", "firewall.read", "firewall.audit", "firewall.admin"})


@dataclass
class StoredUser:
    id: str
    tenant_id: str
    email: str
    username: str
    password_hash: str | None
    provider: str
    role: str  # "owner" or "member"
    scopes: frozenset[str]
    created_at: str
    enabled: bool


@dataclass
class Tenant:
    id: str
    name: str
    created_at: str


def _store_path() -> Path:
    return Path(os.environ.get("USERS_FILE", str(_DEFAULT_FILE)))


def _load_all() -> dict:
    p = _store_path()
    if not p.exists():
        return {"tenants": [], "users": []}
    with open(p) as f:
        data = json.load(f)
    if "tenants" not in data:
        data["tenants"] = []
    if "users" not in data:
        data["users"] = []
    return data


def _save_all(data: dict) -> None:
    atomic_write_json(_store_path(), data)


def _to_stored(rec: dict) -> StoredUser:
    return StoredUser(
        id=rec.get("id", ""),
        tenant_id=rec.get("tenant_id", ""),
        email=rec.get("email", ""),
        username=rec.get("username", ""),
        password_hash=rec.get("password_hash"),
        provider=rec.get("provider", "email"),
        role=rec.get("role", "member"),
        scopes=frozenset(rec.get("scopes", list(DEFAULT_SCOPES))),
        created_at=rec.get("created_at", ""),
        enabled=rec.get("enabled", True),
    )


def _to_tenant(rec: dict) -> Tenant:
    return Tenant(
        id=rec.get("id", ""),
        name=rec.get("name", ""),
        created_at=rec.get("created_at", ""),
    )


def lookup_by_email(email: str) -> StoredUser | None:
    email_lower = email.lower().strip()
    with _LOCK:
        data = _load_all()
        for rec in data["users"]:
            if rec.get("email", "").lower().strip() == email_lower and rec.get("enabled", True):
                return _to_stored(rec)
    return None


def lookup_by_id(user_id: str) -> StoredUser | None:
    with _LOCK:
        data = _load_all()
        for rec in data["users"]:
            if rec.get("id") == user_id and rec.get("enabled", True):
                return _to_stored(rec)
    return None


def get_tenant(tenant_id: str) -> Tenant | None:
    with _LOCK:
        data = _load_all()
        for rec in data["tenants"]:
            if rec.get("id") == tenant_id:
                return _to_tenant(rec)
    return None


def list_tenant_users(tenant_id: str) -> list[StoredUser]:
    with _LOCK:
        data = _load_all()
        return [
            _to_stored(rec) for rec in data["users"]
            if rec.get("tenant_id") == tenant_id and rec.get("enabled", True)
        ]


def register_email_user(email: str, username: str, password: str, tenant_name: str | None = None) -> StoredUser:
    """Register a new user with email/password. Creates a new tenant automatically."""
    email_lower = email.lower().strip()
    with _LOCK:
        data = _load_all()
        for rec in data["users"]:
            if rec.get("email", "").lower().strip() == email_lower:
                raise ValueError("An account with this email already exists.")

        tenant_id = f"t_{uuid.uuid4().hex[:8]}"
        t_name = (tenant_name or username).strip()
        data["tenants"].append({
            "id": tenant_id,
            "name": t_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

        user_id = f"u_{uuid.uuid4().hex[:8]}"
        rec = {
            "id": user_id,
            "tenant_id": tenant_id,
            "email": email_lower,
            "username": username.strip(),
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "provider": "email",
            "role": "owner",
            "scopes": sorted(OWNER_SCOPES),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "enabled": True,
        }
        data["users"].append(rec)
        _save_all(data)
        return _to_stored(rec)


def invite_user_to_tenant(tenant_id: str, email: str, username: str, password: str) -> StoredUser:
    """Add a user to an existing tenant. Raises ValueError if email exists."""
    email_lower = email.lower().strip()
    with _LOCK:
        data = _load_all()
        if not any(t.get("id") == tenant_id for t in data["tenants"]):
            raise ValueError("Tenant not found.")
        for rec in data["users"]:
            if rec.get("email", "").lower().strip() == email_lower:
                raise ValueError("An account with this email already exists.")
        user_id = f"u_{uuid.uuid4().hex[:8]}"
        rec = {
            "id": user_id,
            "tenant_id": tenant_id,
            "email": email_lower,
            "username": username.strip(),
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "provider": "email",
            "role": "member",
            "scopes": sorted(DEFAULT_SCOPES),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "enabled": True,
        }
        data["users"].append(rec)
        _save_all(data)
        return _to_stored(rec)


def get_or_create_google_user(email: str, name: str) -> StoredUser:
    """Find or create a user from Google SSO. New users get their own tenant."""
    email_lower = email.lower().strip()
    with _LOCK:
        data = _load_all()
        for rec in data["users"]:
            if rec.get("email", "").lower().strip() == email_lower:
                return _to_stored(rec)

        tenant_id = f"t_{uuid.uuid4().hex[:8]}"
        t_name = name.strip() or email_lower.split("@")[0]
        data["tenants"].append({
            "id": tenant_id,
            "name": t_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

        user_id = f"u_{uuid.uuid4().hex[:8]}"
        rec = {
            "id": user_id,
            "tenant_id": tenant_id,
            "email": email_lower,
            "username": t_name,
            "password_hash": None,
            "provider": "google",
            "role": "owner",
            "scopes": sorted(OWNER_SCOPES),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "enabled": True,
        }
        data["users"].append(rec)
        _save_all(data)
        return _to_stored(rec)


def verify_password(stored: StoredUser, password: str) -> bool:
    if stored.password_hash is None:
        return False
    return bcrypt.checkpw(password.encode(), stored.password_hash.encode())


def update_user(user_id: str, tenant_id: str, *, role: str | None = None,
                scopes: list[str] | None = None, password: str | None = None,
                username: str | None = None) -> StoredUser:
    """Update a user within the same tenant. Raises ValueError if not found."""
    with _LOCK:
        data = _load_all()
        for rec in data["users"]:
            if rec.get("id") == user_id and rec.get("tenant_id") == tenant_id:
                if role is not None:
                    rec["role"] = role
                if scopes is not None:
                    rec["scopes"] = sorted(scopes)
                if password is not None and len(password) >= 8:
                    rec["password_hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                if username is not None and len(username.strip()) >= 2:
                    rec["username"] = username.strip()
                _save_all(data)
                return _to_stored(rec)
    raise ValueError("User not found in this tenant.")


def disable_user(user_id: str, tenant_id: str) -> None:
    """Disable (soft-delete) a user. Raises ValueError if not found."""
    with _LOCK:
        data = _load_all()
        for rec in data["users"]:
            if rec.get("id") == user_id and rec.get("tenant_id") == tenant_id:
                rec["enabled"] = False
                _save_all(data)
                return
    raise ValueError("User not found in this tenant.")
