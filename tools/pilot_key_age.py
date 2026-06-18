#!/usr/bin/env python3
"""Pilot API key age exporter + rotation CLI.

Two responsibilities:

1. **Exporter mode** (``--export``, default for the systemd timer):
   Read ``policy/pilot_users.json`` and write a node-exporter
   textfile-collector ``.prom`` exposing per-user key age in days.
   Prometheus alerts on stale keys (> 90d default) and disabled-but-
   still-present keys.

2. **Rotation mode** (``--rotate USERNAME``):
   Generate a new 32-byte URL-safe API key for the given user, update
   the SHA-256 hash + ``rotated_at`` field in the store atomically,
   and print the raw key to stdout *exactly once* (caller must capture
   it — there is no recovery path).

Why this exists
---------------
``policy/pilot_users.json`` is the only authentication artifact actually
in production today. Keys are never expiring, never rotating, and have
no age tracking. A leaked key is therefore valid forever.

The ``rotated_at`` field is added on first rotation; users without it
fall back to ``created_at``. The exporter only runs against the local
JSON store — it does not import the API package, so it cannot poison
prod ROI state.

Exit codes
----------
0  success
1  fatal error (file missing, write failed, unknown user)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STORE = REPO_ROOT / "policy" / "pilot_users.json"
DEFAULT_TEXTFILE_DIR = "/var/lib/prometheus/node-exporter"
TEXTFILE_NAME = "firewall-pilot-key-age.prom"
DEFAULT_KEY_BYTES = 32  # 256 bits


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _atomic_write_json(path: Path, data: dict, *, mode: int = 0o600) -> None:
    """Same temp + fsync + os.replace pattern as api/atomic_io.py.

    Reimplemented here so the exporter can run with ``ProtectSystem=strict``
    and not need to import the API package (which would resolve module-level
    constants that touch prod paths).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    body = json.dumps(data, indent=2, separators=(",", ": "))
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(body)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        # Python 3.11+ handles 'Z' suffix; 3.10 doesn't. Replace defensively.
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _key_birth(entry: dict[str, Any]) -> datetime | None:
    """When was this key actually created? rotated_at wins, else created_at."""
    return _parse_iso(entry.get("rotated_at")) or _parse_iso(entry.get("created_at"))


def _age_days(entry: dict[str, Any], *, now: datetime | None = None) -> float | None:
    birth = _key_birth(entry)
    if birth is None:
        return None
    if now is None:
        now = datetime.now(timezone.utc)
    return (now - birth).total_seconds() / 86400.0


# ── exporter ──────────────────────────────────────────────────────────────────
def render_textfile(users: list[dict[str, Any]], *, now: datetime | None = None) -> str:
    """Build the textfile-collector body (no I/O)."""
    if now is None:
        now = datetime.now(timezone.utc)
    lines: list[str] = []
    lines.append(
        "# HELP firewall_pilot_key_age_days Days since the pilot API key was created or last rotated.\n"
        "# TYPE firewall_pilot_key_age_days gauge"
    )
    enabled_count = 0
    for entry in users:
        username = entry.get("username")
        if not username:
            continue
        enabled = bool(entry.get("enabled", True))
        if enabled:
            enabled_count += 1
        age = _age_days(entry, now=now)
        # Escape username for label safety (prom textformat: backslash, quote, newline).
        safe = username.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        if age is not None:
            lines.append(
                f'firewall_pilot_key_age_days{{username="{safe}",enabled="{str(enabled).lower()}"}} {age:.6f}'
            )
        # If age is None (no created_at AND no rotated_at), skip — there's no
        # truthful number to emit and a sentinel like -1 would silently bypass
        # the > 90 alert.
    lines.append(
        "# HELP firewall_pilot_key_count Total pilot users in the store.\n"
        "# TYPE firewall_pilot_key_count gauge\n"
        f"firewall_pilot_key_count{{enabled=\"true\"}} {enabled_count}\n"
        f"firewall_pilot_key_count{{enabled=\"false\"}} {len(users) - enabled_count}"
    )
    lines.append(
        "# HELP firewall_pilot_key_exporter_last_run_timestamp_seconds Unix epoch of last successful exporter run.\n"
        "# TYPE firewall_pilot_key_exporter_last_run_timestamp_seconds gauge\n"
        f"firewall_pilot_key_exporter_last_run_timestamp_seconds {time.time():.0f}"
    )
    return "\n".join(lines) + "\n"


def export_metrics(store: Path, textfile_dir: Path) -> int:
    if not store.is_file():
        print(f"ERROR: pilot user store not found: {store}", file=sys.stderr)
        return 1
    try:
        data = json.loads(store.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read {store}: {exc}", file=sys.stderr)
        return 1
    users = data.get("users", []) or []
    body = render_textfile(users)
    if not textfile_dir.is_dir():
        print(f"ERROR: textfile dir not found: {textfile_dir}", file=sys.stderr)
        return 1
    target = textfile_dir / TEXTFILE_NAME
    tmp = target.with_name(target.name + ".tmp")
    try:
        tmp.write_text(body, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except OSError as exc:
        print(f"ERROR: cannot write {target}: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {target} ({len(users)} users)")
    return 0


# ── rotation ──────────────────────────────────────────────────────────────────
def rotate_key(store: Path, username: str, *, key_bytes: int = DEFAULT_KEY_BYTES) -> tuple[int, str | None]:
    """Generate a new key, update the store, return (exit_code, raw_key).

    The raw key is returned exactly once. Caller must print it; nothing else
    in the system holds it after this function returns.
    """
    if not store.is_file():
        print(f"ERROR: pilot user store not found: {store}", file=sys.stderr)
        return 1, None
    try:
        data = json.loads(store.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read {store}: {exc}", file=sys.stderr)
        return 1, None

    users = data.get("users", []) or []
    found = False
    raw_key = secrets.token_urlsafe(key_bytes)
    new_hash = _hash_key(raw_key)
    now_iso = datetime.now(timezone.utc).isoformat()
    for entry in users:
        if entry.get("username") == username:
            entry["key_hash"] = new_hash
            entry["rotated_at"] = now_iso
            found = True
            break
    if not found:
        print(f"ERROR: user not found: {username}", file=sys.stderr)
        return 1, None

    data["users"] = users
    try:
        _atomic_write_json(store, data)
    except OSError as exc:
        print(f"ERROR: cannot write {store}: {exc}", file=sys.stderr)
        return 1, None
    return 0, raw_key


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE,
        help=f"Path to pilot_users.json (default: {DEFAULT_STORE})",
    )
    ap.add_argument(
        "--textfile-dir",
        type=Path,
        default=Path(DEFAULT_TEXTFILE_DIR),
        help=f"node-exporter textfile dir (default: {DEFAULT_TEXTFILE_DIR})",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--export",
        action="store_true",
        help="Write the textfile-collector .prom file and exit (default action).",
    )
    mode.add_argument(
        "--rotate",
        metavar="USERNAME",
        help="Rotate the API key for USERNAME. The new raw key is printed once "
             "to stdout — capture it immediately.",
    )
    ap.add_argument(
        "--key-bytes",
        type=int,
        default=DEFAULT_KEY_BYTES,
        help="Number of random bytes for the new key (default: 32 = 256 bits).",
    )
    args = ap.parse_args()

    if args.rotate:
        code, raw = rotate_key(args.store, args.rotate, key_bytes=args.key_bytes)
        if code == 0 and raw:
            sys.stderr.write(
                f"Rotated key for {args.rotate}. The raw key below is shown ONCE.\n"
            )
            sys.stderr.write("Capture it now — it is not stored anywhere else.\n\n")
            print(raw)
        return code

    # default: --export
    return export_metrics(args.store, args.textfile_dir)


if __name__ == "__main__":
    sys.exit(main())
