"""
Append-only audit-trail sink for the M&S Firewall Policy Compliance API.

Every evaluation (single, bulk, intake, audit/csv) is recorded as a single JSON
record so the security team has a defensible, replayable evidence trail.

Backends (selected via AUDIT_BACKEND):

    "local" (default)  — append to a JSONL file at AUDIT_DIR/<UTC-date>.jsonl
    "s3"               — write each record as an S3 object with object-lock;
                         requires boto3 and is lazy-imported.
    "noop"             — disable the trail (only sensible for unit tests).

Notes
-----
* All payloads are written verbatim — sanitisation is the caller's
  responsibility (the API only persists the request fields it has already
  validated and the verdict it has already returned).
* Local files must live on a path with retention controls applied at the OS /
  filesystem level (e.g. mounted from an immutable volume). The local backend
  is intended for dev / on-prem; the S3 backend with Object Lock is the
  recommended production sink.
"""
from __future__ import annotations

import abc
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditStore(abc.ABC):
    """Abstract append-only sink. Implementations must be thread-safe."""

    @abc.abstractmethod
    def record(self, event: dict[str, Any]) -> None: ...

    def close(self) -> None:  # pragma: no cover - default no-op
        return None


class NoopAuditStore(AuditStore):
    def record(self, event: dict[str, Any]) -> None:
        return None


class LocalJsonlAuditStore(AuditStore):
    """Append JSONL records to AUDIT_DIR/<UTC-date>.jsonl.

    Files are opened in append mode, line-buffered, and flushed per write.
    A lock guards interleaved writes from worker threads inside one process;
    cross-process safety is provided by the OS append-mode guarantee on POSIX.
    """

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path_for_today(self) -> Path:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.base_dir / f"audit-{date}.jsonl"

    def record(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), default=str) + "\n"
        path = self._path_for_today()
        with self._lock:
            with path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.flush()


class S3AuditStore(AuditStore):
    """Write each record as an S3 object with optional Object Lock.

    Object key layout: <prefix>/<UTC-date>/<request_id>.json. boto3 is imported
    lazily so the local/dev workflow stays free of cloud dependencies.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        object_lock_mode: str | None = None,
        retain_until_iso: str | None = None,
        region_name: str | None = None,
    ):
        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover — only hit when misconfigured
            raise RuntimeError(
                "AUDIT_BACKEND=s3 requires boto3 to be installed."
            ) from exc

        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._object_lock_mode = object_lock_mode
        self._retain_until_iso = retain_until_iso
        self._client = boto3.client("s3", region_name=region_name)

    def record(self, event: dict[str, Any]) -> None:
        request_id = event.get("request_id", "unknown")
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        key_parts = [p for p in (self._prefix, date, f"{request_id}.json") if p]
        key = "/".join(key_parts)

        body = json.dumps(event, separators=(",", ":"), default=str).encode("utf-8")
        kwargs: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": body,
            "ContentType": "application/json",
        }
        if self._object_lock_mode:
            kwargs["ObjectLockMode"] = self._object_lock_mode
            if self._retain_until_iso:
                kwargs["ObjectLockRetainUntilDate"] = self._retain_until_iso
        self._client.put_object(**kwargs)


_singleton: AuditStore | None = None
_singleton_lock = threading.Lock()


def get_audit_store() -> AuditStore:
    """Return the process-wide audit store, configured from the environment."""
    global _singleton
    if _singleton is not None:
        return _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = _build_from_env()
    return _singleton


def reset_for_tests(store: AuditStore | None = None) -> None:
    """Test-only helper: replace the singleton (or rebuild from env)."""
    global _singleton
    with _singleton_lock:
        _singleton = store


def _build_from_env() -> AuditStore:
    backend = os.environ.get("AUDIT_BACKEND", "local").strip().lower()
    if backend == "noop":
        return NoopAuditStore()
    if backend == "s3":
        bucket = os.environ.get("AUDIT_S3_BUCKET")
        if not bucket:
            raise RuntimeError("AUDIT_BACKEND=s3 requires AUDIT_S3_BUCKET.")
        return S3AuditStore(
            bucket=bucket,
            prefix=os.environ.get("AUDIT_S3_PREFIX", "firewall-audit"),
            object_lock_mode=os.environ.get("AUDIT_S3_OBJECT_LOCK_MODE") or None,
            retain_until_iso=os.environ.get("AUDIT_S3_RETAIN_UNTIL") or None,
            region_name=os.environ.get("AWS_REGION") or None,
        )
    explicit = "AUDIT_DIR" in os.environ
    base = Path(os.environ.get("AUDIT_DIR", "/var/log/firewall-audit"))
    try:
        return LocalJsonlAuditStore(base_dir=base)
    except PermissionError:
        # If the caller explicitly opted into AUDIT_DIR, fail loud — they
        # asked for a specific path and silently changing it would corrupt
        # the audit trail. Only fall back when the default system path is
        # unwritable (typical of dev/test environments without /var/log
        # privileges).
        if explicit:
            raise
        fallback = Path.home() / ".firewall-api" / "audit"
        import sys
        print(
            f"audit_store: default audit dir {base} not writable; "
            f"falling back to {fallback}. Set AUDIT_DIR to silence this warning.",
            file=sys.stderr,
        )
        return LocalJsonlAuditStore(base_dir=fallback)


# ── Helpers used by main.py ───────────────────────────────────────────────────
def make_event(
    *,
    request_id: str,
    endpoint: str,
    caller_sub: str | None,
    payload_summary: dict[str, Any],
    verdict_summary: dict[str, Any],
    elapsed_ms: int,
) -> dict[str, Any]:
    """Shape a single audit record. Keep keys stable — downstream tooling depends on them."""
    return {
        "ts": _utc_now_iso(),
        "request_id": request_id,
        "endpoint": endpoint,
        "caller_sub": caller_sub or "anonymous",
        "payload": payload_summary,
        "verdict": verdict_summary,
        "elapsed_ms": elapsed_ms,
    }
