"""Tests for tools/validate_grafana_dashboards.py."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "validate_grafana_dashboards.py"
_spec = importlib.util.spec_from_file_location("_validate_grafana_dashboards", _TOOL_PATH)
assert _spec is not None and _spec.loader is not None
validate_grafana_dashboards = importlib.util.module_from_spec(_spec)
sys.modules["_validate_grafana_dashboards"] = validate_grafana_dashboards
_spec.loader.exec_module(validate_grafana_dashboards)


def _write_dashboard(path: Path, *, title: str = "Dash", uid: str = "dash-uid", expr: str = "up") -> None:
    payload = {
        "title": title,
        "uid": uid,
        "panels": [
            {
                "id": 1,
                "targets": [{"refId": "A", "expr": expr}],
            }
        ],
        "templating": {"list": []},
        "annotations": {"list": []},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_validate_dashboards_accepts_repo_dashboards() -> None:
    dashboard_dir = Path(__file__).resolve().parents[1] / "deploy" / "monitoring" / "grafana"
    errors, count = validate_grafana_dashboards.validate_dashboards(dashboard_dir)
    assert errors == []
    assert count > 0


def test_validate_dashboards_rejects_missing_required_key(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_dashboard(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.pop("annotations")
    path.write_text(json.dumps(payload), encoding="utf-8")

    errors, _ = validate_grafana_dashboards.validate_dashboards(tmp_path)
    assert any("missing required top-level key 'annotations'" in e for e in errors)


def test_validate_dashboards_rejects_duplicate_uid(tmp_path: Path) -> None:
    _write_dashboard(tmp_path / "a.json", title="A", uid="same")
    _write_dashboard(tmp_path / "b.json", title="B", uid="same")

    errors, _ = validate_grafana_dashboards.validate_dashboards(tmp_path)
    assert any("duplicate uid 'same'" in e for e in errors)


def test_validate_dashboards_rejects_empty_target_query(tmp_path: Path) -> None:
    _write_dashboard(tmp_path / "bad_query.json", expr="   ")

    errors, _ = validate_grafana_dashboards.validate_dashboards(tmp_path)
    assert any("has empty query text" in e for e in errors)
