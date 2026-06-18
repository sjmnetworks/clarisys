#!/usr/bin/env python3
"""Run a non-prod monitoring drill for the Firewall Policy API.

This script does not change server configuration. It validates health and metrics
surfaces and can optionally generate a small burst of evaluation traffic so
Prometheus and Grafana panels visibly move during a drill.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_SYNTHETIC_HEADER = "x-monitoring-synthetic"
_SYNTHETIC_HEADER_VALUE = "true"


def _request_json(base_url: str, path: str, token: str | None = None, timeout: float = 10.0):
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    req = urllib.request.Request(url, method="GET")
    req.add_header(_SYNTHETIC_HEADER, _SYNTHETIC_HEADER_VALUE)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body)


def _request_text(base_url: str, path: str, token: str | None = None, timeout: float = 10.0):
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    req = urllib.request.Request(url, method="GET")
    req.add_header(_SYNTHETIC_HEADER, _SYNTHETIC_HEADER_VALUE)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8")


def _post_json(
    base_url: str,
    path: str,
    payload: dict,
    token: str | None = None,
    timeout: float = 10.0,
):
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header(_SYNTHETIC_HEADER, _SYNTHETIC_HEADER_VALUE)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body)


def _check(condition: bool, message: str, failures: list[str]) -> None:
    if condition:
        print(f"[PASS] {message}")
        return
    print(f"[FAIL] {message}")
    failures.append(message)


def _sample_request(index: int) -> dict:
    if index % 2 == 0:
        return {
            "source": "10.157.26.5",
            "destination": "10.221.126.33",
            "protocol": "tcp",
            "port": 443,
            "log": "all",
            "action": "allow",
            "source_interface": "finance-src",
            "destination_interface": "analytics-dst",
        }
    return {
        "source": "10.157.26.5",
        "destination": "payment.example.com",
        "protocol": "tcp",
        "port": 80,
        "log": "no_log",
        "action": "allow",
        "source_interface": "retail-src",
        "destination_interface": "payment-dst",
        "data_classification": "Confidential",
        "approved_external_sharing": True,
    }


def run_drill(args: argparse.Namespace) -> int:
    failures: list[str] = []
    base_url = args.base_url
    token = args.token

    print("== Firewall API Monitoring Drill ==")
    print(f"Base URL: {base_url}")

    try:
        health_status, health = _request_json(base_url, "/health", token=token, timeout=args.timeout)
        _check(health_status == 200, "GET /health returns 200", failures)
        _check(health.get("status") in {"ok", "degraded"}, "health payload has expected status", failures)

        slo_status, slo = _request_json(base_url, "/metrics/slo", token=token, timeout=args.timeout)
        _check(slo_status == 200, "GET /metrics/slo returns 200", failures)
        _check("requests_total" in slo, "SLO payload includes requests_total", failures)
        _check("active_alerts_count" in slo, "SLO payload includes active_alerts_count", failures)

        alerts_status, alerts = _request_json(base_url, "/metrics/alerts", token=token, timeout=args.timeout)
        _check(alerts_status == 200, "GET /metrics/alerts returns 200", failures)
        _check(alerts.get("status") in {"ok", "warn", "critical"}, "Alert status is valid", failures)
        _check(isinstance(alerts.get("active_alerts", []), list), "Alert payload includes active_alerts list", failures)

        slo_prom_status, slo_prom = _request_text(
            base_url,
            "/metrics/slo?format=prometheus",
            token=token,
            timeout=args.timeout,
        )
        _check(slo_prom_status == 200, "GET /metrics/slo?format=prometheus returns 200", failures)
        _check("firewall_requests_total" in slo_prom, "SLO Prometheus text includes firewall_requests_total", failures)

        alerts_prom_status, alerts_prom = _request_text(
            base_url,
            "/metrics/alerts?format=prometheus",
            token=token,
            timeout=args.timeout,
        )
        _check(alerts_prom_status == 200, "GET /metrics/alerts?format=prometheus returns 200", failures)
        _check("firewall_alerts_active_count" in alerts_prom, "Alerts Prometheus text includes firewall_alerts_active_count", failures)
    except urllib.error.HTTPError as exc:
        print(f"[ERROR] HTTP error during baseline checks: {exc.code} {exc.reason}")
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Baseline checks failed: {exc}")
        return 2

    if args.generate_traffic > 0:
        print(f"Generating {args.generate_traffic} synthetic evaluate requests...")
        for i in range(args.generate_traffic):
            try:
                code, payload = _post_json(
                    base_url,
                    "/evaluate",
                    _sample_request(i),
                    token=token,
                    timeout=args.timeout,
                )
                _check(code == 200, f"Traffic request {i + 1} accepted", failures)
                _check(payload.get("verdict") in {"ACCEPTABLE", "DENY"}, f"Traffic request {i + 1} returned verdict", failures)
            except urllib.error.HTTPError as exc:
                failures.append(f"Traffic request {i + 1} failed with HTTP {exc.code}")
                print(f"[FAIL] Traffic request {i + 1} failed with HTTP {exc.code}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"Traffic request {i + 1} failed: {exc}")
                print(f"[FAIL] Traffic request {i + 1} failed: {exc}")

        if args.wait_after_traffic > 0:
            print(f"Waiting {args.wait_after_traffic}s for scrape/evaluation windows...")
            time.sleep(args.wait_after_traffic)

    try:
        final_status, final_slo = _request_json(base_url, "/metrics/slo", token=token, timeout=args.timeout)
        _check(final_status == 200, "Final GET /metrics/slo returns 200", failures)
        _check(final_slo.get("requests_total", 0) >= 0, "Final SLO payload readable", failures)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"Final SLO check failed: {exc}")
        print(f"[FAIL] Final SLO check failed: {exc}")

    if failures:
        print("\nDrill completed with failures:")
        for item in failures:
            print(f"- {item}")
        return 1

    print("\nDrill completed successfully.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a non-prod monitoring drill against Firewall Policy API")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument("--token", default=None, help="Optional bearer token for protected endpoints")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    parser.add_argument(
        "--generate-traffic",
        type=int,
        default=10,
        help="Number of synthetic /evaluate requests to send during drill",
    )
    parser.add_argument(
        "--wait-after-traffic",
        type=int,
        default=10,
        help="Seconds to wait after traffic generation for scrape windows",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_drill(args)


if __name__ == "__main__":
    sys.exit(main())
