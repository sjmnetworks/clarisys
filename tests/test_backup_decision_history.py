"""Tests for tools/backup_decision_history.py."""
from __future__ import annotations

import gzip
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import backup_decision_history as bdh


def _write_history(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_args(
    source: Path,
    backup_dir: Path,
    *,
    retention_days: int = 14,
    force: bool = False,
    textfile_dir: Path | None = None,
    no_textfile_metrics: bool = True,
) -> object:
    return bdh.build_parser().parse_args(
        [
            "--source",
            str(source),
            "--backup-dir",
            str(backup_dir),
            "--retention-days",
            str(retention_days),
            *(["--force"] if force else []),
            "--textfile-collector-dir",
            str(textfile_dir or backup_dir),
            *(["--no-textfile-metrics"] if no_textfile_metrics else []),
        ]
    )


def test_first_backup_creates_gzip_with_full_contents(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": 1}', '{"row": 2}'])
    backup_dir = tmp_path / "backups"

    rc = bdh.run_backup(_make_args(source, backup_dir))
    out = capsys.readouterr().out
    assert rc == 0
    report = json.loads(out)

    assert report["skipped"] is False
    assert report["retained_count"] == 1
    backups = list(backup_dir.glob("decision_history-*.jsonl.gz"))
    assert len(backups) == 1
    with gzip.open(backups[0], "rb") as fh:
        assert fh.read().decode("utf-8") == source.read_text(encoding="utf-8")


def test_unchanged_source_skips_redundant_backup(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Append-only file unchanged since last run → no second snapshot."""
    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": 1}'])
    backup_dir = tmp_path / "backups"

    bdh.run_backup(_make_args(source, backup_dir))
    capsys.readouterr()
    bdh.run_backup(_make_args(source, backup_dir))
    out = capsys.readouterr().out
    report = json.loads(out)

    assert report["skipped"] is True
    assert len(list(backup_dir.glob("decision_history-*.jsonl.gz"))) == 1


def test_changed_source_creates_new_backup(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": 1}'])
    backup_dir = tmp_path / "backups"

    bdh.run_backup(_make_args(source, backup_dir))
    capsys.readouterr()

    # Append a new row → SHA changes → new snapshot.
    with source.open("a", encoding="utf-8") as fh:
        fh.write('{"row": 2}\n')

    bdh.run_backup(_make_args(source, backup_dir))
    capsys.readouterr()
    backups = list(backup_dir.glob("decision_history-*.jsonl.gz"))
    assert len(backups) == 2


def test_force_creates_new_backup_even_when_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": 1}'])
    backup_dir = tmp_path / "backups"

    bdh.run_backup(_make_args(source, backup_dir))
    capsys.readouterr()
    bdh.run_backup(_make_args(source, backup_dir, force=True))
    capsys.readouterr()

    backups = list(backup_dir.glob("decision_history-*.jsonl.gz"))
    assert len(backups) == 2


def test_retention_prunes_old_backups(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    # Plant an "old" backup with mtime 30 days ago.
    old = backup_dir / "decision_history-20260512T000000Z.jsonl.gz"
    with gzip.open(old, "wb") as fh:
        fh.write(b'{"row": "old"}\n')
    old_age = time.time() - 30 * 86400
    os.utime(old, (old_age, old_age))

    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": "fresh"}'])

    bdh.run_backup(_make_args(source, backup_dir, retention_days=14))
    capsys.readouterr()

    survivors = sorted(backup_dir.glob("decision_history-*.jsonl.gz"))
    assert len(survivors) == 1
    assert old not in survivors


def test_retention_zero_disables_pruning(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    old = backup_dir / "decision_history-20260101T000000Z.jsonl.gz"
    with gzip.open(old, "wb") as fh:
        fh.write(b'{"row": "old"}\n')
    old_age = time.time() - 365 * 86400
    os.utime(old, (old_age, old_age))

    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": "new"}'])

    bdh.run_backup(_make_args(source, backup_dir, retention_days=0))
    capsys.readouterr()

    survivors = sorted(backup_dir.glob("decision_history-*.jsonl.gz"))
    assert old in survivors
    assert len(survivors) == 2


def test_missing_source_returns_error(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    rc = bdh.run_backup(
        _make_args(tmp_path / "nope.jsonl", tmp_path / "backups")
    )
    capsys.readouterr()
    assert rc == 1


def test_textfile_metrics_emitted_on_success(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": 1}'])
    backup_dir = tmp_path / "backups"
    textfile_dir = tmp_path / "node-exporter"
    textfile_dir.mkdir()

    rc = bdh.run_backup(
        _make_args(
            source,
            backup_dir,
            textfile_dir=textfile_dir,
            no_textfile_metrics=False,
        )
    )
    capsys.readouterr()
    assert rc == 0

    prom = textfile_dir / "firewall-decision-history-backup.prom"
    assert prom.exists()
    body = prom.read_text(encoding="utf-8")
    assert "firewall_decision_history_backup_last_success_timestamp_seconds" in body
    assert "firewall_decision_history_backup_last_status 0" in body
    assert "firewall_decision_history_backup_count 1" in body


def test_textfile_metrics_skipped_when_dir_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Missing textfile dir is a soft failure — backup still succeeds."""
    source = tmp_path / "history.jsonl"
    _write_history(source, ['{"row": 1}'])
    backup_dir = tmp_path / "backups"
    textfile_dir = tmp_path / "no-such-dir"

    rc = bdh.run_backup(
        _make_args(
            source,
            backup_dir,
            textfile_dir=textfile_dir,
            no_textfile_metrics=False,
        )
    )
    capsys.readouterr()
    assert rc == 0
    assert not textfile_dir.exists()
    # Backup itself still landed.
    assert list(backup_dir.glob("decision_history-*.jsonl.gz"))
