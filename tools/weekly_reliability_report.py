#!/usr/bin/env python3
"""Generate a weekly reliability report from Prometheus.

Outputs:
- Markdown summary: latest + dated file
- CSV row snapshot: append-only history

Default output dir: ~/.firewall-api/reports/

This is designed to run non-interactively from systemd.
"""
from __future__ import annotations

import argparse
import csv
import http.client
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

PROM_DEFAULT = os.environ.get("PROMETHEUS_URL", "http://127.0.0.1:9090")
REPORT_DIR_DEFAULT = Path.home() / ".firewall-api" / "reports"

QUERIES = {
    "service_up": "firewall:service_up",
    "error_budget_burn_fast": "clamp_min(max(firewall:error_budget_burn_rate_5m), max(firewall:error_budget_burn_rate_1h))",
    "error_budget_burn_slow": "clamp_min(max(firewall:error_budget_burn_rate_30m), max(firewall:error_budget_burn_rate_6h))",
    "api_latency_p95_ms": "firewall:latency_p95_ms_5m_max",
    "opa_latency_p95_ms": "max(firewall:opa_latency_p95_ms_5m)",
    "canary_pass": "min(firewall_canary_pass)",
    "state_write_failures_15m": "sum(increase(firewall_state_write_total{outcome=\"failure\"}[15m]))",
    "rate_limited_5m": "firewall:rate_limited_5m",
    "requests_rps_5m": "firewall:request_volume_rps_5m",
    "decisions_total": "sum(firewall_decisions_total)",
    "deny_ratio_1h": "sum(increase(firewall_decisions_deny[1h])) / clamp_min(sum(increase(firewall_decisions_total[1h])), 1)",
    "oldest_enabled_pilot_key_days": "max(firewall_pilot_key_age_days{enabled=\"true\"})",
    "pilot_key_exporter_age_hours": "(time() - firewall_pilot_key_exporter_last_run_timestamp_seconds) / 3600",
}


def prom_query(base_url: str, query: str) -> float | str:
    parsed = urlparse(base_url)
    host = parsed.netloc or parsed.path
    path = f"/api/v1/query?query={quote(query, safe='')}"
    conn = http.client.HTTPConnection(host, timeout=10)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        data = json.loads(resp.read())
    finally:
        conn.close()
    result = data.get("data", {}).get("result", [])
    if not result:
        return "NO DATA"
    value = result[0].get("value", [None, "NO DATA"])[1]
    try:
        return float(value)
    except (TypeError, ValueError):
        return str(value)


def classify_status(metrics: dict[str, float | str]) -> str:
    if metrics.get("service_up") != 1.0:
        return "critical"
    if isinstance(metrics.get("canary_pass"), float) and metrics["canary_pass"] < 1.0:
        return "critical"
    if isinstance(metrics.get("error_budget_burn_fast"), float) and metrics["error_budget_burn_fast"] >= 14.4:
        return "critical"
    if isinstance(metrics.get("state_write_failures_15m"), float) and metrics["state_write_failures_15m"] > 0:
        return "warning"
    if isinstance(metrics.get("rate_limited_5m"), float) and metrics["rate_limited_5m"] >= 5:
        return "warning"
    return "ok"


def render_markdown(ts: datetime, metrics: dict[str, float | str], status: str) -> str:
    lines = [
        f"# Weekly Reliability Report - {ts.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        "",
        f"Overall status: **{status.upper()}**",
        "",
        "## Summary",
        f"- Service up: {metrics['service_up']}",
        f"- Fast error-budget burn: {metrics['error_budget_burn_fast']}",
        f"- Slow error-budget burn: {metrics['error_budget_burn_slow']}",
        f"- API p95 latency (ms): {metrics['api_latency_p95_ms']}",
        f"- OPA p95 latency (ms): {metrics['opa_latency_p95_ms']}",
        f"- Canary pass: {metrics['canary_pass']}",
        f"- State write failures (15m): {metrics['state_write_failures_15m']}",
        f"- Rate-limited requests (5m): {metrics['rate_limited_5m']}",
        f"- Request volume (RPS, 5m): {metrics['requests_rps_5m']}",
        f"- Decisions total: {metrics['decisions_total']}",
        f"- Deny ratio (1h): {metrics['deny_ratio_1h']}",
        f"- Oldest enabled pilot key (days): {metrics['oldest_enabled_pilot_key_days']}",
        f"- Pilot key exporter age (hours): {metrics['pilot_key_exporter_age_hours']}",
        "",
        "## Notes",
        "- Generated from live Prometheus query snapshots.",
        "- NO DATA means the source series is absent or has not been populated yet.",
    ]
    return "\n".join(lines) + "\n"


def append_csv(path: Path, ts: datetime, status: str, metrics: dict[str, float | str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists()
    with path.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        if write_header:
            writer.writerow(["generated_at", "status", *metrics.keys()])
        writer.writerow([ts.isoformat(), status, *metrics.values()])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prom-url", default=PROM_DEFAULT, help="Prometheus base URL")
    ap.add_argument("--report-dir", type=Path, default=REPORT_DIR_DEFAULT, help="Output directory")
    args = ap.parse_args()

    ts = datetime.now(timezone.utc)
    metrics = {name: prom_query(args.prom_url, q) for name, q in QUERIES.items()}
    status = classify_status(metrics)

    args.report_dir.mkdir(parents=True, exist_ok=True)
    dated_md = args.report_dir / f"reliability-weekly-{ts.strftime('%Y%m%dT%H%M%SZ')}.md"
    latest_md = args.report_dir / "reliability-weekly-latest.md"
    csv_path = args.report_dir / "reliability-weekly-history.csv"

    content = render_markdown(ts, metrics, status)
    dated_md.write_text(content, encoding="utf-8")
    latest_md.write_text(content, encoding="utf-8")
    append_csv(csv_path, ts, status, metrics)

    print(f"wrote {dated_md}")
    print(f"updated {latest_md}")
    print(f"appended {csv_path}")
    print(f"status={status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
