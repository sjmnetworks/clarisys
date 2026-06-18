#!/usr/bin/env python3
"""Daily backup of policy/decision_history.jsonl with gzip + retention.

Why this exists
---------------
``decision_history.jsonl`` is the source of truth for ROI bootstrap and
state-drift autocorrect. If that file is truncated or lost, the API
silently flatlines: ``_bootstrap_from_history`` returns False and the
ROI gauges drop to zero. There is no replication and no off-host copy.

This tool produces a timestamped gzip snapshot of the file each time
it runs, prunes anything older than the retention horizon, and writes
a Prometheus textfile-collector ``.prom`` so a stale-backup alert can
fire if the timer stops.

Defaults
--------
- Source: ``$REPO/policy/decision_history.jsonl``
- Backup dir: ``~/.firewall-api/backups/decision-history``
- Retention: 14 days
- Textfile dir: ``/var/lib/prometheus/node-exporter`` (set
  ``--no-textfile-metrics`` on hosts without node-exporter)

Exit codes
----------
0  successful backup (or no-op when source is unchanged AND a recent
   backup already exists)
1  fatal error (source missing, target unwritable, etc.)
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPO_ROOT / "policy" / "decision_history.jsonl"
DEFAULT_BACKUP_DIR = Path.home() / ".firewall-api" / "backups" / "decision-history"
DEFAULT_RETENTION_DAYS = 14
DEFAULT_TEXTFILE_DIR = "/var/lib/prometheus/node-exporter"
BACKUP_PREFIX = "decision_history-"
BACKUP_SUFFIX = ".jsonl.gz"


def _sha256_of(path: Path) -> str:
    """Return the SHA-256 of *path*. Used for the dedup-on-no-change path."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _existing_backups(backup_dir: Path) -> list[Path]:
    if not backup_dir.is_dir():
        return []
    return sorted(backup_dir.glob(f"{BACKUP_PREFIX}*{BACKUP_SUFFIX}"))


def _latest_backup_sha(backup_dir: Path) -> str | None:
    """Return the SHA of the newest existing backup, decompressing it.

    Used to skip a redundant snapshot when the source file is byte-for-byte
    identical to the latest backup. Decision history is append-only so a
    no-change run usually means the API was idle since the last backup.
    """
    backups = _existing_backups(backup_dir)
    if not backups:
        return None
    latest = backups[-1]
    h = hashlib.sha256()
    try:
        with gzip.open(latest, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _gzip_copy(source: Path, target: Path) -> None:
    """Compress *source* into *target* atomically (temp + os.replace)."""
    tmp = target.with_name(target.name + ".tmp")
    with source.open("rb") as src, gzip.open(tmp, "wb", compresslevel=6) as dst:
        shutil.copyfileobj(src, dst, length=1 << 20)
    os.replace(tmp, target)


def _prune(backup_dir: Path, retention_days: int) -> list[Path]:
    """Delete backups older than retention_days. Return list of removed paths."""
    if retention_days <= 0:
        return []
    cutoff = time.time() - retention_days * 86400
    removed: list[Path] = []
    for path in _existing_backups(backup_dir):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed.append(path)
        except OSError:
            continue
    return removed


def _emit_textfile(
    textfile_dir: Path,
    last_backup_ts: float,
    last_backup_size: int,
    last_backup_status: int,
    backup_count: int,
) -> Path | None:
    """Write a node-exporter textfile-collector snippet for staleness alerts."""
    if not textfile_dir.is_dir():
        return None
    target = textfile_dir / "firewall-decision-history-backup.prom"
    body = (
        "# HELP firewall_decision_history_backup_last_run_timestamp_seconds Unix epoch of last backup attempt.\n"
        "# TYPE firewall_decision_history_backup_last_run_timestamp_seconds gauge\n"
        f"firewall_decision_history_backup_last_run_timestamp_seconds {time.time()}\n"
        "# HELP firewall_decision_history_backup_last_success_timestamp_seconds Unix epoch of last successful backup.\n"
        "# TYPE firewall_decision_history_backup_last_success_timestamp_seconds gauge\n"
        f"firewall_decision_history_backup_last_success_timestamp_seconds {last_backup_ts}\n"
        "# HELP firewall_decision_history_backup_last_size_bytes Size of the most recent backup file.\n"
        "# TYPE firewall_decision_history_backup_last_size_bytes gauge\n"
        f"firewall_decision_history_backup_last_size_bytes {last_backup_size}\n"
        "# HELP firewall_decision_history_backup_last_status 0=success, 1=skipped (no change), 2=failure.\n"
        "# TYPE firewall_decision_history_backup_last_status gauge\n"
        f"firewall_decision_history_backup_last_status {last_backup_status}\n"
        "# HELP firewall_decision_history_backup_count Number of retained backup files.\n"
        "# TYPE firewall_decision_history_backup_count gauge\n"
        f"firewall_decision_history_backup_count {backup_count}\n"
    )
    try:
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(body, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except OSError:
        return None
    return target


def run_backup(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    if not source.is_file():
        print(f"ERROR: source not found: {source}", file=sys.stderr)
        return 1

    backup_dir = Path(args.backup_dir).expanduser()
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: cannot create backup dir {backup_dir}: {exc}", file=sys.stderr)
        return 1

    src_sha = _sha256_of(source)
    latest_sha = _latest_backup_sha(backup_dir)

    backup_status = 0
    skipped = False
    if latest_sha == src_sha and not args.force:
        # Append-only file unchanged since last run → no point re-snapshotting.
        skipped = True
        backup_status = 1
        latest_path = _existing_backups(backup_dir)[-1]
        last_ts = latest_path.stat().st_mtime
        last_size = latest_path.stat().st_size
        kept_path = latest_path
    else:
        # Subsecond precision so two runs in the same second (e.g. an
        # ad-hoc --force after the daily timer) don't overwrite each other.
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        target = backup_dir / f"{BACKUP_PREFIX}{ts}{BACKUP_SUFFIX}"
        try:
            _gzip_copy(source, target)
        except OSError as exc:
            print(f"ERROR: backup failed: {exc}", file=sys.stderr)
            if not args.no_textfile_metrics:
                _emit_textfile(
                    Path(args.textfile_collector_dir),
                    last_backup_ts=0,
                    last_backup_size=0,
                    last_backup_status=2,
                    backup_count=len(_existing_backups(backup_dir)),
                )
            return 1
        last_ts = target.stat().st_mtime
        last_size = target.stat().st_size
        kept_path = target

    removed = _prune(backup_dir, args.retention_days)
    backups = _existing_backups(backup_dir)

    if not args.no_textfile_metrics:
        _emit_textfile(
            Path(args.textfile_collector_dir),
            last_backup_ts=last_ts,
            last_backup_size=last_size,
            last_backup_status=backup_status,
            backup_count=len(backups),
        )

    report = {
        "source": str(source),
        "source_sha256": src_sha,
        "backup_dir": str(backup_dir),
        "skipped": skipped,
        "kept_path": str(kept_path),
        "size_bytes": last_size,
        "retained_count": len(backups),
        "removed": [str(p) for p in removed],
    }
    print(json.dumps(report, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--source", default=str(DEFAULT_SOURCE), help="Path to decision_history.jsonl")
    p.add_argument("--backup-dir", default=str(DEFAULT_BACKUP_DIR), help="Directory to write backups into")
    p.add_argument(
        "--retention-days",
        type=int,
        default=DEFAULT_RETENTION_DAYS,
        help="Delete backups older than this many days (set 0 to disable pruning)",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Always create a new backup even if the source SHA matches the latest backup",
    )
    p.add_argument(
        "--textfile-collector-dir",
        default=DEFAULT_TEXTFILE_DIR,
        help="node-exporter textfile collector dir (a .prom file is written here)",
    )
    p.add_argument(
        "--no-textfile-metrics",
        action="store_true",
        help="Skip writing the Prometheus textfile snippet",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_backup(args)


if __name__ == "__main__":
    raise SystemExit(main())
