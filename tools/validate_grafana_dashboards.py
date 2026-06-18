#!/usr/bin/env python3
"""Validate Grafana dashboard JSON artifacts.

Checks performed:
- JSON is parseable and top-level object is a dict.
- Required top-level keys exist.
- `title` and `uid` are non-empty strings.
- `uid` and `title` are unique across dashboard files.
- Panel targets with query fields have non-empty query text.

Usage:
  python3 tools/validate_grafana_dashboards.py
  python3 tools/validate_grafana_dashboards.py --dir deploy/monitoring/grafana
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REQUIRED_TOP_LEVEL_KEYS = (
    "title",
    "uid",
    "panels",
    "templating",
    "annotations",
)
QUERY_FIELD_KEYS = ("expr", "query", "rawSql", "definition")


def _iter_dashboard_files(dashboard_dir: Path) -> list[Path]:
    return sorted(p for p in dashboard_dir.glob("*.json") if p.is_file())


def _iter_panels(panel_list: list) -> list[dict]:
    out: list[dict] = []
    for panel in panel_list:
        if not isinstance(panel, dict):
            continue
        out.append(panel)
        nested = panel.get("panels")
        if isinstance(nested, list):
            out.extend(_iter_panels(nested))
    return out


def _validate_targets(path: Path, dashboard_obj: dict) -> list[str]:
    errors: list[str] = []
    panels = dashboard_obj.get("panels", [])
    if not isinstance(panels, list):
        return [f"{path}: top-level 'panels' must be a list"]

    for panel in _iter_panels(panels):
        panel_id = panel.get("id", "?")
        targets = panel.get("targets", [])
        if targets is None:
            continue
        if not isinstance(targets, list):
            errors.append(f"{path}: panel id={panel_id} has non-list 'targets'")
            continue

        for idx, target in enumerate(targets):
            if not isinstance(target, dict):
                errors.append(f"{path}: panel id={panel_id} target[{idx}] is not an object")
                continue

            present_fields = [k for k in QUERY_FIELD_KEYS if k in target]
            if not present_fields:
                continue

            if not any(str(target.get(k, "")).strip() for k in present_fields):
                errors.append(
                    f"{path}: panel id={panel_id} target[{idx}] has empty query text "
                    f"in fields {present_fields}"
                )
    return errors


def validate_dashboards(dashboard_dir: Path) -> tuple[list[str], int]:
    errors: list[str] = []
    files = _iter_dashboard_files(dashboard_dir)

    if not files:
        return [f"{dashboard_dir}: no dashboard JSON files found"], 0

    seen_uids: dict[str, Path] = {}
    seen_titles: dict[str, Path] = {}

    for path in files:
        try:
            dashboard_obj = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path}: invalid JSON: {exc}")
            continue

        if not isinstance(dashboard_obj, dict):
            errors.append(f"{path}: top-level JSON must be an object")
            continue

        for key in REQUIRED_TOP_LEVEL_KEYS:
            if key not in dashboard_obj:
                errors.append(f"{path}: missing required top-level key '{key}'")

        title = dashboard_obj.get("title")
        uid = dashboard_obj.get("uid")
        if not isinstance(title, str) or not title.strip():
            errors.append(f"{path}: 'title' must be a non-empty string")
        if not isinstance(uid, str) or not uid.strip():
            errors.append(f"{path}: 'uid' must be a non-empty string")

        if isinstance(uid, str) and uid.strip():
            prior = seen_uids.get(uid)
            if prior is not None:
                errors.append(f"{path}: duplicate uid '{uid}' (already used by {prior})")
            else:
                seen_uids[uid] = path

        if isinstance(title, str) and title.strip():
            prior = seen_titles.get(title)
            if prior is not None:
                errors.append(f"{path}: duplicate title '{title}' (already used by {prior})")
            else:
                seen_titles[title] = path

        errors.extend(_validate_targets(path, dashboard_obj))

    return errors, len(files)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Grafana dashboard JSON files")
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path("deploy/monitoring/grafana"),
        help="Directory containing Grafana dashboard JSON files",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    errors, count = validate_dashboards(args.dir)
    if errors:
        print(f"dashboard validation failed: {len(errors)} error(s) across {count} file(s)", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1

    print(f"dashboard validation passed: {count} file(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
