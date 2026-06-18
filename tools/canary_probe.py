#!/usr/bin/env python3
"""
Synthetic canary probe for the Firewall Policy API.

Sends two HTTP requests on every run:
  - Known-good: should return ACCEPTABLE
  - Known-deny: should return DENY

Writes results to a Prometheus textfile-collector .prom file so
Prometheus can alert on probe failures or staleness.

Usage:
  python3 tools/canary_probe.py
  python3 tools/canary_probe.py --url http://127.0.0.1:8001 --prom-out /var/lib/prometheus/node-exporter/firewall-canary.prom

Metrics emitted:
  firewall_canary_last_run_timestamp_seconds  -- Unix epoch of last successful run
  firewall_canary_pass{probe}                 -- 1 if probe returned expected verdict, else 0
  firewall_canary_latency_seconds{probe}      -- Round-trip time in seconds
  firewall_canary_errors_total                -- Cumulative connection/JSON errors (not verdict mismatches)
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# ── Probe definitions ─────────────────────────────────────────────────────────
# Each entry: (name, payload, expected_verdict)
_PROBES: list[tuple[str, dict, str]] = [
    (
        "known_good",
        {
            "source": "10.0.0.1",
            "destination": "10.0.0.2",
            "protocol": "tcp",
            "port": 443,
            "log": "all",
            "action": "accept",
            "encryption_required": True,
            "tls_version_minimum": "1.2",
            "source_interface": "VLAN-INTERNAL",
            "destination_interface": "VLAN-INTERNAL",
            "standards": ["M&S NFR"],
        },
        "ACCEPTABLE",
    ),
    (
        "known_deny",
        {
            "source": "10.0.0.1",
            "destination": "8.8.8.8",
            "protocol": "udp",
            "port": 53,
            "log": "all",
            "action": "accept",
            "standards": ["M&S NFR"],
        },
        "DENY",
    ),
]

_PROM_DEFAULT = "/var/lib/prometheus/node-exporter/firewall-canary.prom"
_SYNTHETIC_HEADER = "x-monitoring-synthetic"
_SYNTHETIC_HEADER_VALUE = "true"


def _post(host: str, port: int, path: str, payload: dict, timeout: float) -> tuple[dict, float]:
    """POST JSON to host:port/path. Returns (response_dict, elapsed_seconds)."""
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        _SYNTHETIC_HEADER: _SYNTHETIC_HEADER_VALUE,
    }
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    t0 = time.perf_counter()
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        elapsed = time.perf_counter() - t0
        return json.loads(data), elapsed
    finally:
        conn.close()


def _write_prom(path: Path, results: list[dict]) -> None:
    """Atomically write Prometheus textfile-collector output."""
    lines = [
        "# HELP firewall_canary_last_run_timestamp_seconds Unix epoch of last canary run.",
        "# TYPE firewall_canary_last_run_timestamp_seconds gauge",
        f"firewall_canary_last_run_timestamp_seconds {time.time():.3f}",
        "# HELP firewall_canary_pass 1 if the probe returned the expected verdict.",
        "# TYPE firewall_canary_pass gauge",
    ]
    for r in results:
        lines.append(f'firewall_canary_pass{{probe="{r["name"]}"}} {1 if r["pass"] else 0}')
    lines += [
        "# HELP firewall_canary_latency_seconds Canary probe round-trip time in seconds.",
        "# TYPE firewall_canary_latency_seconds gauge",
    ]
    for r in results:
        lines.append(
            f'firewall_canary_latency_seconds{{probe="{r["name"]}"}} {r["latency"]:.6f}'
        )
    lines += [
        "# HELP firewall_canary_errors_total Cumulative canary connection/parse errors.",
        "# TYPE firewall_canary_errors_total counter",
        f"firewall_canary_errors_total {sum(1 for r in results if r.get('error'))}",
    ]
    content = "\n".join(lines) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Firewall API synthetic canary probe.")
    parser.add_argument(
        "--url",
        default=os.environ.get("CANARY_API_URL", "http://127.0.0.1:8001"),
        help="API base URL (CANARY_API_URL env, default: http://127.0.0.1:8001)",
    )
    parser.add_argument(
        "--prom-out",
        default=os.environ.get("CANARY_PROM_OUT", _PROM_DEFAULT),
        help="Textfile-collector output path",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request HTTP timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    from urllib.parse import urlparse
    parsed = urlparse(args.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8001

    results = []
    all_pass = True

    for name, payload, expected in _PROBES:
        try:
            response, elapsed = _post(host, port, "/evaluate", payload, args.timeout)
            verdict = response.get("verdict", "UNKNOWN")
            probe_pass = verdict == expected
            if not probe_pass:
                print(
                    f"FAIL {name}: expected={expected} got={verdict}",
                    file=sys.stderr,
                )
                all_pass = False
            else:
                print(f"OK   {name}: {verdict} ({elapsed*1000:.0f}ms)")
            results.append({"name": name, "pass": probe_pass, "latency": elapsed, "error": False})
        except Exception as exc:
            print(f"ERROR {name}: {exc}", file=sys.stderr)
            results.append({"name": name, "pass": False, "latency": 0.0, "error": True})
            all_pass = False

    _write_prom(Path(args.prom_out), results)

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
