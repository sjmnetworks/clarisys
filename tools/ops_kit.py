#!/usr/bin/env python3
"""Operator helper CLI for incident response and monitoring drift.

Subcommands:
- snapshot: one-shot incident bundle
- watchdog: restart-loop / startup health check
- verify-drift: compare repo monitoring assets to provisioned host files
- runbook: generate alert-driven operator steps
- timeline: merge journal, decisions, lifecycle, and alert state into one view
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.decision_history import list_recent_decisions


DEFAULT_UNIT = "opa-api-8001.service"
DEFAULT_API_BASE_URL = "http://127.0.0.1:8001"
DEFAULT_PROMETHEUS_BASE_URL = "http://127.0.0.1:9090"
DEFAULT_TEXTFILE_COLLECTOR_DIR = "/var/lib/prometheus/node-exporter"
DEFAULT_LOKI_BASE_URL = "http://127.0.0.1:3100"
DEFAULT_PROMTAIL_BASE_URL = "http://127.0.0.1:9080"
SYNTHETIC_HEADER = "x-monitoring-synthetic"
SYNTHETIC_HEADER_VALUE = "true"

DRIFT_ASSETS = [
    ("deploy/monitoring/alertmanager.yml", "/etc/alertmanager/alertmanager.yml"),
    ("deploy/monitoring/loki-config.yml", "/etc/loki/config.yml"),
    ("deploy/monitoring/promtail-config.yml", "/etc/promtail/config.yml"),
    ("deploy/monitoring/grafana/loki-datasource.yml", "/etc/grafana/provisioning/datasources/loki.yaml"),
    ("deploy/monitoring/grafana/firewall-api-observability-dashboard.json", "/var/lib/grafana/dashboards/firewall-api-core-monitoring.json"),
    ("deploy/monitoring/grafana/opa-roi-live-dashboard.json", "/var/lib/grafana/dashboards/opa-roi-live-dashboard.json"),
]

RUNBOOKS = {
    "api-crash": [
        "systemctl status opa-api-8001.service --no-pager -l",
        "journalctl -u opa-api-8001.service -n 200 --no-pager",
        "python3 tools/ops_kit.py watchdog --unit opa-api-8001.service",
    ],
    "latency": [
        "curl -s http://127.0.0.1:8001/metrics/slo | jq",
        "uptime",
        "free -m",
    ],
    "opa-unavailable": [
        "systemctl status opa-api-8001.service --no-pager -l",
        "journalctl -u opa-api-8001.service -n 120 --no-pager",
        "curl -s http://127.0.0.1:8181/health",
    ],
    "slack-failures": [
        "curl -s http://127.0.0.1:8001/notifications/slack/metrics | jq",
        "curl -s http://127.0.0.1:8001/metrics/alerts | jq",
    ],
    "drift": [
        "python3 tools/ops_kit.py verify-drift",
        "bash deploy/monitoring/sync_monitoring_bundle.sh --dry-run",
    ],
    "digest-backlog": [
        "curl -s http://127.0.0.1:8001/notifications/slack/metrics | jq",
        "curl -s -X POST http://127.0.0.1:8001/notifications/slack/digest/flush | jq",
    ],
}


@dataclass(order=True)
class TimelineItem:
    sort_key: datetime
    ts: str
    source: str
    message: str


def _run(command: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def _http_json(url: str, timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(url, method="GET")
    req.add_header(SYNTHETIC_HEADER, SYNTHETIC_HEADER_VALUE)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_text(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, method="GET")
    req.add_header(SYNTHETIC_HEADER, SYNTHETIC_HEADER_VALUE)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _write_json(path: str | None, payload: dict[str, Any]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")


def _tail_journal(unit: str, since_minutes: int, lines: int) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
    code, stdout, stderr = _run(
        [
            "journalctl",
            "-u",
            unit,
            "--since",
            since.isoformat(),
            "--no-pager",
            "-n",
            str(lines),
            "-o",
            "short-iso",
        ]
    )
    return {"returncode": code, "stdout": stdout, "stderr": stderr}


def _incident_section(title: str, content: str) -> str:
    return f"## {title}\n\n{content.strip() or '(no output)'}\n"


def _json_or_text(args: argparse.Namespace, payload: dict[str, Any], markdown: str) -> int:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(markdown, end="")
    return 0


def snapshot_command(args: argparse.Namespace) -> int:
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "units": args.unit,
        "sections": {},
        "errors": [],
    }

    for unit in args.unit:
        status_rc, status_out, status_err = _run(["systemctl", "status", unit, "--no-pager", "-l"])
        report["sections"][f"systemctl:{unit}"] = {
            "returncode": status_rc,
            "stdout": status_out,
            "stderr": status_err,
        }
        report["sections"][f"journal:{unit}"] = _tail_journal(unit, args.since_minutes, args.tail_lines)

    for label, url in (
        ("health", args.base_url.rstrip("/") + "/health"),
        ("slo", args.base_url.rstrip("/") + "/metrics/slo"),
        ("alerts", args.base_url.rstrip("/") + "/metrics/alerts"),
    ):
        try:
            report["sections"][f"api:{label}"] = _http_json(url, args.timeout)
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(f"{label}: {exc}")

    for label, url in (
        ("prometheus:targets", args.prometheus_base_url.rstrip("/") + "/api/v1/targets"),
        ("loki:ready", args.loki_base_url.rstrip("/") + "/ready"),
        ("promtail:ready", args.promtail_base_url.rstrip("/") + "/ready"),
    ):
        try:
            if label.endswith(":ready"):
                report["sections"][label] = _http_text(url, args.timeout).strip()
            else:
                report["sections"][label] = _http_json(url, args.timeout)
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(f"{label}: {exc}")

    _write_json(args.output_json, report)

    lines = [
        "# Incident Snapshot",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Units: {', '.join(report['units'])}",
        "",
    ]
    for name, section in report["sections"].items():
        if name.startswith("systemctl:") or name.startswith("journal:"):
            lines.append(_incident_section(name, section.get("stdout", "")))
            if section.get("stderr"):
                lines.append("```text")
                lines.append(section["stderr"])
                lines.append("```")
                lines.append("")
            continue
        lines.append(f"## {name}")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(section, indent=2, sort_keys=True, default=str))
        lines.append("```")
        lines.append("")

    if report["errors"]:
        lines.append("## Collection errors")
        lines.append("")
        for error in report["errors"]:
            lines.append(f"- {error}")

    rendered = "\n".join(lines).rstrip() + "\n"
    return _json_or_text(args, report, rendered) or (0 if not report["errors"] else 2)


def watchdog_command(args: argparse.Namespace) -> int:
    code, show_out, _ = _run(
        [
            "systemctl",
            "show",
            args.unit,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "NRestarts",
            "-p",
            "ExecMainStatus",
            "-p",
            "ExecMainCode",
            "-p",
            "MainPID",
            "-p",
            "FragmentPath",
        ]
    )
    properties: dict[str, str] = {}
    for line in show_out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value

    restarts = int(properties.get("NRestarts", "0") or 0)
    active = properties.get("ActiveState", "unknown")
    substate = properties.get("SubState", "unknown")
    status = int(properties.get("ExecMainStatus", "0") or 0)
    healthy = code == 0 and active == "active" and substate == "running" and restarts <= args.failure_threshold and status == 0

    since = datetime.now(timezone.utc) - timedelta(minutes=args.since_minutes)
    _, journal, _ = _run([
        "journalctl",
        "-u",
        args.unit,
        "--since",
        since.isoformat(),
        "--no-pager",
        "-n",
        "80",
    ])

    diagnosis = []
    if active != "active" or substate != "running":
        diagnosis.append(f"unit is {active}/{substate}")
    if restarts > args.failure_threshold:
        diagnosis.append(f"restart count {restarts} exceeds threshold {args.failure_threshold}")
    if status != 0:
        diagnosis.append(f"last main process exited with status {status}")
    if not diagnosis:
        diagnosis.append("no restart-loop signal detected")

    alert_result: dict[str, Any] | None = None
    if not healthy and getattr(args, "alert_slack", False):
        alert_result = _maybe_post_watchdog_alert(args, diagnosis, properties, journal)

    textfile_path = _emit_watchdog_textfile(args, healthy, restarts, properties)

    payload = {
        "healthy": healthy,
        "unit": args.unit,
        "properties": properties,
        "diagnosis": diagnosis,
        "journal": journal,
    }
    if alert_result is not None:
        payload["alert"] = alert_result
    if textfile_path is not None:
        payload["textfile_metrics"] = textfile_path
    _write_json(args.output_json, payload)

    markdown = (
        f"Unit: {args.unit}\n"
        f"Active: {active}/{substate}\n"
        f"Restarts: {restarts}\n"
        f"Main exit status: {status}\n"
        f"Main PID: {properties.get('MainPID', '0')}\n"
        f"Fragment: {properties.get('FragmentPath', '')}\n\n"
        f"Diagnosis: {'; '.join(diagnosis)}\n\n"
        f"Recent journal:\n{journal or '(no recent journal output)'}\n"
    )
    if alert_result is not None:
        markdown += f"\nAlert: {alert_result.get('action', 'unknown')}"
        if alert_result.get("reason"):
            markdown += f" ({alert_result['reason']})"
        markdown += "\n"
    return _json_or_text(args, payload, markdown) or (0 if healthy else 2)


def _watchdog_signature(unit: str, diagnosis: list[str]) -> str:
    """Stable hash of (unit, sorted diagnosis) used for alert dedup."""
    raw = unit + "|" + "|".join(sorted(diagnosis))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _emit_watchdog_textfile(
    args: argparse.Namespace,
    healthy: bool,
    restarts: int,
    properties: dict[str, str],
) -> str | None:
    """Write a Prometheus textfile-collector metric file for this run.

    The watchdog runs as a one-shot timer, not a long-lived scrape target,
    so we publish via node-exporter's textfile collector. Three metrics
    are emitted (all labelled by unit):

      firewall_watchdog_last_run_timestamp_seconds  — for staleness alerts
      firewall_watchdog_last_run_healthy            — 1 healthy / 0 unhealthy
      firewall_watchdog_restarts                    — current NRestarts gauge

    Atomic write (temp + os.replace) so node-exporter never reads a
    partial file. Returns the file path on success, None on failure
    (missing/unwritable dir is a soft failure — the watchdog still runs).
    """
    if getattr(args, "no_textfile_metrics", False):
        return None
    base = Path(getattr(args, "textfile_collector_dir", None) or DEFAULT_TEXTFILE_COLLECTOR_DIR)
    if not base.is_dir():
        return None

    unit_label = args.unit.replace('"', '\\"')
    safe_filename = args.unit.replace("/", "_").replace(".", "_")
    target = base / f"firewall-watchdog-{safe_filename}.prom"
    now_ts = time.time()
    body = (
        "# HELP firewall_watchdog_last_run_timestamp_seconds Unix epoch when the watchdog last completed.\n"
        "# TYPE firewall_watchdog_last_run_timestamp_seconds gauge\n"
        f'firewall_watchdog_last_run_timestamp_seconds{{unit="{unit_label}"}} {now_ts}\n'
        "# HELP firewall_watchdog_last_run_healthy 1 if the unit was healthy on the last run, 0 otherwise.\n"
        "# TYPE firewall_watchdog_last_run_healthy gauge\n"
        f'firewall_watchdog_last_run_healthy{{unit="{unit_label}"}} {1 if healthy else 0}\n'
        "# HELP firewall_watchdog_restarts NRestarts reported by systemd at watchdog run time.\n"
        "# TYPE firewall_watchdog_restarts gauge\n"
        f'firewall_watchdog_restarts{{unit="{unit_label}"}} {restarts}\n'
    )
    try:
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(body, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except Exception:
        return None
    return str(target)


def _capture_watchdog_forensics(
    args: argparse.Namespace,
    diagnosis: list[str],
    properties: dict[str, str],
    journal_text: str,
) -> str | None:
    """Write a JSON forensics bundle to disk and return its path.

    Captures everything the on-call needs to triage without SSH-ing into
    the box: systemd properties, watchdog diagnosis, journal tail, and a
    /metrics dump (best-effort — may be unreachable if the unit is down).
    Returns None if the bundle could not be written.
    """
    base = Path(
        getattr(args, "forensics_dir", None)
        or (Path.home() / ".firewall-api" / "forensics")
    )
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_path = base / f"watchdog-{ts}-{args.unit.replace('.', '_')}.json"

    metrics_text: str | None = None
    metrics_error: str | None = None
    try:
        metrics_text = _http_text(
            getattr(args, "metrics_url", None) or "http://127.0.0.1:8001/metrics",
            timeout=getattr(args, "alert_timeout", 5.0),
        )
    except Exception as exc:  # noqa: BLE001
        metrics_error = str(exc)

    bundle = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "unit": args.unit,
        "diagnosis": diagnosis,
        "systemd_properties": properties,
        "journal_tail": journal_text,
        "metrics": metrics_text,
        "metrics_error": metrics_error,
        "host": os.uname().nodename if hasattr(os, "uname") else "unknown",
    }
    try:
        # Atomic write: temp file + rename, mirroring api/atomic_io.
        tmp = bundle_path.with_name(bundle_path.name + ".tmp")
        tmp.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, bundle_path)
    except Exception:
        return None
    return str(bundle_path)


def _maybe_post_watchdog_alert(
    args: argparse.Namespace,
    diagnosis: list[str],
    properties: dict[str, str],
    journal_text: str = "",
) -> dict[str, Any]:
    """Post a Slack alert when an unhealthy verdict is fresh.

    Dedup rule: skip if the same (unit, diagnosis) signature was alerted
    within --alert-cooldown-minutes. State is persisted to a small JSON
    file so multiple timer-fired runs don't spam the channel.
    """
    url = args.slack_webhook_url or os.environ.get("OPS_KIT_SLACK_WEBHOOK_URL", "")
    if not url:
        return {"action": "skipped", "reason": "no webhook URL configured"}

    state_path = Path(args.alert_state_file or (Path.home() / ".firewall-api" / "ops-kit-watchdog-state.json"))
    signature = _watchdog_signature(args.unit, diagnosis)
    now = time.time()
    cooldown = max(0, int(args.alert_cooldown_minutes)) * 60

    state: dict[str, Any] = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            state = {}

    last = state.get(args.unit, {})
    if (
        isinstance(last, dict)
        and last.get("signature") == signature
        and (now - float(last.get("last_alert_at", 0))) < cooldown
    ):
        return {
            "action": "deduped",
            "reason": f"same signature within cooldown ({args.alert_cooldown_minutes}m)",
            "signature": signature,
        }

    # Capture forensics bundle BEFORE posting so the operator sees a
    # filesystem path in the Slack message even if the API is down.
    bundle_path: str | None = None
    if getattr(args, "attach_forensics", True):
        bundle_path = _capture_watchdog_forensics(args, diagnosis, properties, journal_text)

    text = (
        f":rotating_light: Watchdog: {args.unit} unhealthy\n"
        f"• Diagnosis: {'; '.join(diagnosis)}\n"
        f"• Restarts: {properties.get('NRestarts', '?')}\n"
        f"• Active: {properties.get('ActiveState', '?')}/{properties.get('SubState', '?')}\n"
        f"• Main exit status: {properties.get('ExecMainStatus', '?')}\n"
        f"• Host: {os.uname().nodename if hasattr(os, 'uname') else 'unknown'}"
    )
    if bundle_path:
        text += f"\n• Forensics: `{bundle_path}`"
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=args.alert_timeout) as resp:
            posted = 200 <= resp.status < 300
    except Exception as exc:  # noqa: BLE001
        return {
            "action": "post_failed",
            "reason": str(exc),
            "signature": signature,
            "forensics_path": bundle_path,
        }

    if not posted:
        return {
            "action": "post_failed",
            "reason": "non-2xx response",
            "signature": signature,
            "forensics_path": bundle_path,
        }

    state[args.unit] = {"signature": signature, "last_alert_at": now}
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write so a crashed cron run never corrupts dedup state.
        tmp = state_path.with_name(state_path.name + ".tmp")
        tmp.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, state_path)
    except Exception as exc:  # noqa: BLE001
        return {
            "action": "posted",
            "reason": f"state save failed: {exc}",
            "signature": signature,
            "forensics_path": bundle_path,
        }

    return {"action": "posted", "signature": signature, "forensics_path": bundle_path}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_drift_command(args: argparse.Namespace) -> int:
    items: list[dict[str, str]] = []
    for source_rel, target_abs in DRIFT_ASSETS:
        source = REPO_ROOT / source_rel
        target = Path(target_abs)
        row = {
            "source": str(source),
            "target": str(target),
            "status": "ok",
            "source_sha256": "missing",
            "target_sha256": "missing",
        }
        if not source.exists():
            row["status"] = "source-missing"
            items.append(row)
            continue
        row["source_sha256"] = _sha256(source)
        if not target.exists():
            row["status"] = "target-missing"
            items.append(row)
            continue
        row["target_sha256"] = _sha256(target)
        if row["source_sha256"] != row["target_sha256"]:
            row["status"] = "drifted"
        items.append(row)

    payload = {"drifted": sum(1 for item in items if item["status"] != "ok"), "items": items}
    _write_json(args.output_json, payload)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for item in items:
            print(f"[{item['status'].upper()}] {item['source']} -> {item['target']}")
            if item["status"] != "ok":
                print(f"  source_sha256={item['source_sha256']} target_sha256={item['target_sha256']}")
        print(f"\nDrifted items: {payload['drifted']}")

    return 0 if payload["drifted"] == 0 else 1


def _infer_topic(snapshot: dict[str, Any]) -> str:
    status = str(snapshot.get("status", "ok")).lower()
    if status == "critical":
        return "api-crash"
    if int(snapshot.get("opa_unavailable", 0) or 0) > 0:
        return "opa-unavailable"
    if int(snapshot.get("slack_dispatch_failures", 0) or 0) > 0:
        return "slack-failures"
    if float(snapshot.get("latency_p95_ms", 0) or 0) >= 1500:
        return "latency"
    return "drift"


def runbook_command(args: argparse.Namespace) -> int:
    snapshot: dict[str, Any] = {}
    topic = args.topic
    if topic == "auto":
        try:
            snapshot = _http_json(args.base_url.rstrip("/") + "/metrics/alerts", args.timeout)
        except Exception:
            snapshot = {}
        topic = _infer_topic(snapshot)

    commands = RUNBOOKS.get(topic, RUNBOOKS["drift"])
    payload = {"topic": topic, "source": args.base_url, "alert_snapshot": snapshot, "commands": commands}
    _write_json(args.output_json, payload)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(f"# Operator Runbook: {topic}\n")
        if snapshot:
            print("## Alert snapshot\n")
            print(json.dumps(snapshot, indent=2, sort_keys=True))
            print()
        print("## First commands\n")
        for command in commands:
            print(f"- {command}")
        print()
    return 0


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _journal_items(unit: str, since_hours: int) -> list[TimelineItem]:
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    completed = subprocess.run(
        ["journalctl", "-u", unit, "--since", since.isoformat(), "--no-pager", "-o", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    items: list[TimelineItem] = []
    for line in completed.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = str(row.get("MESSAGE", ""))
        if not any(token in message.lower() for token in ("start", "restart", "fail", "error", "panic", "killed")):
            continue
        timestamp = row.get("__REALTIME_TIMESTAMP")
        if timestamp is None:
            continue
        try:
            ts = datetime.fromtimestamp(int(timestamp) / 1_000_000, tz=timezone.utc)
        except (TypeError, ValueError):
            continue
        items.append(TimelineItem(ts, ts.isoformat(), f"journal:{unit}", message))
    return items


def _decision_items(limit: int) -> list[TimelineItem]:
    items: list[TimelineItem] = []
    for row in list_recent_decisions(limit=limit):
        ts = _parse_dt(str(row.get("ts", "")))
        if not ts:
            continue
        message = f"decision {row.get('decision_verdict', 'unknown')} on {row.get('endpoint', 'unknown endpoint')}"
        items.append(TimelineItem(ts, ts.isoformat(), "decision-history", message))
    return items


def _lifecycle_items() -> list[TimelineItem]:
    lifecycle_file = REPO_ROOT / "policy" / "decision_lifecycle.json"
    if not lifecycle_file.exists():
        return []
    try:
        payload = json.loads(lifecycle_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    items: list[TimelineItem] = []
    for decision_id, row in payload.items():
        if not isinstance(row, dict):
            continue
        ts = _parse_dt(str(row.get("updated_at", "")))
        if not ts:
            continue
        items.append(TimelineItem(ts, ts.isoformat(), "decision-lifecycle", f"{decision_id} -> {row.get('status', 'unknown')}"))
    return items


def _alert_item(base_url: str, timeout: float) -> TimelineItem | None:
    try:
        snapshot = _http_json(base_url.rstrip("/") + "/metrics/alerts", timeout)
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    return TimelineItem(
        now,
        now.isoformat(),
        "alerts",
        f"status={snapshot.get('status', 'unknown')} active_alerts={snapshot.get('active_alerts_count', 0)}",
    )


def timeline_command(args: argparse.Namespace) -> int:
    items: list[TimelineItem] = []
    items.extend(_decision_items(args.limit))
    items.extend(_lifecycle_items())
    items.extend(_journal_items(args.unit, args.since_hours))
    alert_item = _alert_item(args.base_url, args.timeout)
    if alert_item:
        items.append(alert_item)
    items.sort()

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "items": [item.__dict__ for item in items],
    }
    _write_json(args.output_json, payload)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print("# Incident Timeline\n")
        for item in items:
            print(f"- {item.ts} [{item.source}] {item.message}")
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Operator helper CLI for incident response and monitoring drift")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot", help="Capture a one-shot incident snapshot")
    snapshot.add_argument("--unit", action="append", default=[DEFAULT_UNIT], help="systemd unit to inspect (repeatable)")
    snapshot.add_argument("--base-url", default=DEFAULT_API_BASE_URL, help="API base URL")
    snapshot.add_argument("--prometheus-base-url", default=DEFAULT_PROMETHEUS_BASE_URL, help="Prometheus base URL")
    snapshot.add_argument("--loki-base-url", default=DEFAULT_LOKI_BASE_URL, help="Loki base URL")
    snapshot.add_argument("--promtail-base-url", default=DEFAULT_PROMTAIL_BASE_URL, help="Promtail base URL")
    snapshot.add_argument("--since-minutes", type=int, default=15, help="Lookback window for journalctl output")
    snapshot.add_argument("--tail-lines", type=int, default=120, help="Recent journal lines to include")
    snapshot.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    snapshot.add_argument("--output-json", default=None, help="Optional path to write the raw JSON report")
    snapshot.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    snapshot.set_defaults(func=snapshot_command)

    watchdog = subparsers.add_parser("watchdog", help="Check for startup failures and restart loops")
    watchdog.add_argument("--unit", default=DEFAULT_UNIT, help="systemd unit to inspect")
    watchdog.add_argument("--since-minutes", type=int, default=15, help="Lookback window for recent journal lines")
    watchdog.add_argument("--failure-threshold", type=int, default=3, help="Restart count before flagging the unit")
    watchdog.add_argument("--output-json", default=None, help="Optional path to write the raw JSON report")
    watchdog.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    watchdog.add_argument(
        "--alert-slack",
        action="store_true",
        help="Post a Slack alert when the unit is unhealthy (dedup-aware)",
    )
    watchdog.add_argument(
        "--slack-webhook-url",
        default=None,
        help="Slack webhook URL (default: env OPS_KIT_SLACK_WEBHOOK_URL)",
    )
    watchdog.add_argument(
        "--alert-cooldown-minutes",
        type=int,
        default=15,
        help="Suppress duplicate alerts with the same diagnosis for this many minutes",
    )
    watchdog.add_argument(
        "--alert-state-file",
        default=None,
        help="Path to dedup state file (default: ~/.firewall-api/ops-kit-watchdog-state.json)",
    )
    watchdog.add_argument("--alert-timeout", type=float, default=5.0, help="Slack POST timeout in seconds")
    watchdog.add_argument(
        "--no-attach-forensics",
        dest="attach_forensics",
        action="store_false",
        default=True,
        help="Do not write a forensics bundle when posting an alert",
    )
    watchdog.add_argument(
        "--forensics-dir",
        default=None,
        help="Where to write forensics bundles (default: ~/.firewall-api/forensics/)",
    )
    watchdog.add_argument(
        "--metrics-url",
        default="http://127.0.0.1:8001/metrics",
        help="Prometheus /metrics URL captured into the forensics bundle (best-effort)",
    )
    watchdog.add_argument(
        "--textfile-collector-dir",
        default=DEFAULT_TEXTFILE_COLLECTOR_DIR,
        help=(
            "node-exporter textfile collector directory; a "
            "firewall-watchdog-<unit>.prom file is written here on every run"
        ),
    )
    watchdog.add_argument(
        "--no-textfile-metrics",
        action="store_true",
        default=False,
        help="Disable writing watchdog metrics to the textfile collector",
    )
    watchdog.set_defaults(func=watchdog_command)

    drift = subparsers.add_parser("verify-drift", help="Check repo monitoring assets against host files")
    drift.add_argument("--output-json", default=None, help="Optional path to write the raw JSON report")
    drift.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    drift.set_defaults(func=verify_drift_command)

    runbook = subparsers.add_parser("runbook", help="Generate alert-driven operator commands")
    runbook.add_argument("--base-url", default=DEFAULT_API_BASE_URL, help="API base URL")
    runbook.add_argument("--topic", default="auto", help="Runbook topic (or auto)")
    runbook.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds")
    runbook.add_argument("--output-json", default=None, help="Optional path to write the raw JSON report")
    runbook.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    runbook.set_defaults(func=runbook_command)

    timeline = subparsers.add_parser("timeline", help="Merge journal, decisions, lifecycle, and alert state")
    timeline.add_argument("--base-url", default=DEFAULT_API_BASE_URL, help="API base URL")
    timeline.add_argument("--unit", default=DEFAULT_UNIT, help="systemd unit to inspect")
    timeline.add_argument("--since-hours", type=int, default=24, help="Journal lookback window")
    timeline.add_argument("--limit", type=int, default=200, help="Decision history entries to include")
    timeline.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds")
    timeline.add_argument("--output-json", default=None, help="Optional path to write the raw JSON report")
    timeline.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    timeline.set_defaults(func=timeline_command)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())