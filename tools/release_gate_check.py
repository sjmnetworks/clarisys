#!/usr/bin/env python3
"""Production release gate checks for Firewall Policy API.

Runs a deterministic set of probes against the API and exits non-zero when any
required gate fails.
"""

from __future__ import annotations

import argparse
import json
import time
import sys
import ssl
import urllib.error
import urllib.parse
import urllib.request

_SYNTHETIC_HEADER = "x-monitoring-synthetic"
_SYNTHETIC_HEADER_VALUE = "true"


def _join(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _get_json(base_url: str, path: str, token: str | None, timeout: float) -> tuple[int, dict]:
    req = urllib.request.Request(_join(base_url, path), method="GET")
    req.add_header(_SYNTHETIC_HEADER, _SYNTHETIC_HEADER_VALUE)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body)


def _get_text(base_url: str, path: str, token: str | None, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(_join(base_url, path), method="GET")
    req.add_header(_SYNTHETIC_HEADER, _SYNTHETIC_HEADER_VALUE)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8")


def _get_text_url(url: str, timeout: float, headers: dict[str, str] | None = None, insecure_tls: bool = False) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    merged_headers = {_SYNTHETIC_HEADER: _SYNTHETIC_HEADER_VALUE}
    merged_headers.update(headers or {})
    for key, value in merged_headers.items():
        req.add_header(key, value)

    context = ssl._create_unverified_context() if insecure_tls else None
    with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
        return resp.status, resp.read().decode("utf-8")


def _get_json_url(url: str, timeout: float, headers: dict[str, str] | None = None, insecure_tls: bool = False) -> tuple[int, dict]:
    status, body = _get_text_url(url, timeout, headers=headers, insecure_tls=insecure_tls)
    return status, json.loads(body)


def _post_json(base_url: str, path: str, payload: dict, token: str | None, timeout: float) -> tuple[int, dict, dict]:
    req = urllib.request.Request(
        _join(base_url, path),
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header(_SYNTHETIC_HEADER, _SYNTHETIC_HEADER_VALUE)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body), dict(resp.headers.items())


def _check(ok: bool, message: str, failures: list[str]) -> None:
    if ok:
        print(f"[PASS] {message}")
    else:
        print(f"[FAIL] {message}")
        failures.append(message)


def _recommendation_for_failure(message: str) -> str | None:
    text = message.lower()
    if "health" in text and "200" in text:
        return "Check the API service and recent journal entries, then restart the service if it is stuck."
    if "ingress /health" in text or "grafana/login" in text:
        return "Verify nginx routing, host header handling, and upstream service reachability."
    if "prometheus target" in text:
        return "Check Prometheus scrape config and confirm the monitored 8001 target is still listening."
    if "error rate" in text:
        return "Pull recent API logs, identify the failing endpoint, and compare the latest deploy to the baseline."
    if "latency p95" in text:
        return "Check host pressure, OPA responsiveness, and recent bulk traffic spikes."
    if "opa unavailable" in text:
        return "Verify the OPA process and policy file paths, then restart the policy service if needed."
    if "slack dispatch failures" in text:
        return "Inspect Slack webhook configuration, recent delivery errors, and dedup/digest backlog state."
    if "alert status" in text:
        return "Review the current alert snapshot and clear only after the underlying metric recovers."
    if "evidence" in text:
        return "Confirm history storage is writable and the evidence archive path is healthy."
    return None


def _sample_allow_request() -> dict:
    return {
        "source": "10.157.26.5",
        "destination": "10.221.126.33",
        "protocol": "tcp",
        "port": 443,
        "log": "all",
        "data_classification": "Internal",
        "source_interface": "finance-src",
        "destination_interface": "analytics-dst",
    }


def _to_serializable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _to_serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_serializable(v) for v in value]
    return str(value)


def _write_report(path: str | None, report: dict) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(_to_serializable(report), handle, indent=2, sort_keys=True)
        handle.write("\n")


def _request_with_retries(
    fn,
    *,
    args: tuple,
    retries: int,
    initial_backoff: float,
):
    attempt = 0
    while True:
        try:
            return fn(*args)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            if attempt >= retries:
                raise
            time.sleep(initial_backoff * (2 ** attempt))
            attempt += 1


def run(args: argparse.Namespace) -> int:
    base_url = args.base_url
    token = args.token
    failures: list[str] = []
    report: dict = {
        "base_url": base_url,
        "started_at_epoch": time.time(),
        "status": "running",
        "checks": [],
        "failures": [],
        "recommendations": [],
    }

    def gate_check(ok: bool, message: str) -> None:
        _check(ok, message, failures)
        report["checks"].append({"ok": ok, "message": message})
        if not ok:
            recommendation = _recommendation_for_failure(message)
            if recommendation and recommendation not in report["recommendations"]:
                report["recommendations"].append(recommendation)

    print("== Firewall Policy API Release Gate ==")
    print(f"Base URL: {base_url}")

    try:
        status, health = _request_with_retries(
            _get_json,
            args=(base_url, "/health", token, args.timeout),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "GET /health returns 200")
        gate_check(health.get("status") == "ok", "Health status is ok")

        if not args.skip_ingress_checks:
            ingress_health_url = _join(args.ingress_base_url, "/health")
            ingress_grafana_url = _join(args.ingress_base_url, "/grafana/login")
            ingress_headers = {"Host": args.ingress_host} if args.ingress_host else {}

            status, _ = _request_with_retries(
                _get_text_url,
                args=(ingress_health_url, args.timeout, ingress_headers, args.ingress_insecure_tls),
                retries=args.retries,
                initial_backoff=args.initial_backoff_seconds,
            )
            gate_check(status == 200, f"Ingress /health returns 200 ({ingress_health_url}, Host={args.ingress_host})")

            status, grafana_login_html = _request_with_retries(
                _get_text_url,
                args=(ingress_grafana_url, args.timeout, ingress_headers, args.ingress_insecure_tls),
                retries=args.retries,
                initial_backoff=args.initial_backoff_seconds,
            )
            gate_check(status == 200, f"Ingress /grafana/login returns 200 ({ingress_grafana_url}, Host={args.ingress_host})")
            gate_check("<!DOCTYPE html>" in grafana_login_html, "Grafana login response contains HTML doctype")

            prom_targets_url = _join(args.prometheus_base_url, "/api/v1/targets")
            status, targets = _request_with_retries(
                _get_json_url,
                args=(prom_targets_url, args.timeout, None, False),
                retries=args.retries,
                initial_backoff=args.initial_backoff_seconds,
            )
            gate_check(status == 200, f"Prometheus targets endpoint returns 200 ({prom_targets_url})")

            active_targets = targets.get("data", {}).get("activeTargets", [])
            roi_target_up = any(
                t.get("labels", {}).get("job") == "firewall-api-roi" and t.get("health") == "up"
                for t in active_targets
            )
            gate_check(roi_target_up, "Prometheus target firewall-api-roi is up")

        status, slo = _request_with_retries(
            _get_json,
            args=(base_url, "/metrics/slo", token, args.timeout),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "GET /metrics/slo returns 200")
        gate_check("error_rate" in slo, "SLO payload includes error_rate")
        gate_check("latency_p95_ms" in slo, "SLO payload includes latency_p95_ms")

        error_rate = float(slo.get("error_rate", 1.0))
        latency_p95 = float(slo.get("latency_p95_ms", 999999))
        opa_unavailable = int(slo.get("opa_unavailable", 1))

        gate_check(
            error_rate < args.max_error_rate,
            f"Error rate {error_rate:.6f} < {args.max_error_rate}",
        )
        gate_check(
            latency_p95 <= args.max_latency_p95_ms,
            f"Latency p95 {latency_p95:.2f}ms <= {args.max_latency_p95_ms}ms",
        )
        gate_check(
            opa_unavailable <= args.max_opa_unavailable,
            f"OPA unavailable {opa_unavailable} <= {args.max_opa_unavailable}",
        )

        status, alerts = _request_with_retries(
            _get_json,
            args=(base_url, "/metrics/alerts", token, args.timeout),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "GET /metrics/alerts returns 200")
        alert_status = str(alerts.get("status", "unknown"))
        gate_check(
            alert_status in args.allowed_alert_status,
            f"Alert status '{alert_status}' in allowed set {sorted(args.allowed_alert_status)}",
        )

        status, slo_prom = _request_with_retries(
            _get_text,
            args=(base_url, "/metrics/slo?format=prometheus", token, args.timeout),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "GET /metrics/slo?format=prometheus returns 200")
        gate_check("firewall_requests_total" in slo_prom, "SLO Prometheus payload has firewall_requests_total")

        status, alerts_prom = _request_with_retries(
            _get_text,
            args=(base_url, "/metrics/alerts?format=prometheus", token, args.timeout),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "GET /metrics/alerts?format=prometheus returns 200")
        gate_check("firewall_alerts_active_count" in alerts_prom, "Alerts Prometheus payload has firewall_alerts_active_count")

        status, slack_metrics = _request_with_retries(
            _get_json,
            args=(base_url, "/notifications/slack/metrics", token, args.timeout),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "GET /notifications/slack/metrics returns 200")
        dispatch_failures = int(slack_metrics.get("dispatch_failures", 0))
        gate_check(
            dispatch_failures <= args.max_slack_dispatch_failures,
            f"Slack dispatch failures {dispatch_failures} <= {args.max_slack_dispatch_failures}",
        )

        status, eval_payload, _ = _request_with_retries(
            _post_json,
            args=(base_url, "/evaluate", _sample_allow_request(), token, args.timeout),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "POST /evaluate smoke returns 200")
        gate_check(eval_payload.get("verdict") in {"ACCEPTABLE", "DENY"}, "POST /evaluate smoke returns verdict")

        status, evidence_payload = _request_with_retries(
            _get_json,
            args=(
                base_url,
                "/compliance/evidence?format=json&days=1&persist=true",
                token,
                args.timeout,
            ),
            retries=args.retries,
            initial_backoff=args.initial_backoff_seconds,
        )
        gate_check(status == 200, "GET /compliance/evidence persist returns 200")
        report_id = str(evidence_payload.get("report_id", ""))
        gate_check(bool(report_id), "Evidence response contains report_id")

        if report_id:
            status, archive = _request_with_retries(
                _get_json,
                args=(
                    base_url,
                    f"/compliance/evidence/archive/{report_id}",
                    token,
                    args.timeout,
                ),
                retries=args.retries,
                initial_backoff=args.initial_backoff_seconds,
            )
            gate_check(status == 200, "GET /compliance/evidence/archive/{report_id} returns 200")
            gate_check(str(archive.get("report_id", "")) == report_id, "Retrieved archive report_id matches")

    except urllib.error.HTTPError as exc:
        print(f"[ERROR] HTTP {exc.code} during gate checks: {exc.reason}")
        report["status"] = "error"
        report["error"] = f"HTTP {exc.code}: {exc.reason}"
        report["failures"] = failures
        report["recommendations"] = report.get("recommendations", [])
        report["finished_at_epoch"] = time.time()
        _write_report(args.output_json, report)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Gate checks failed unexpectedly: {exc}")
        report["status"] = "error"
        report["error"] = str(exc)
        report["failures"] = failures
        report["recommendations"] = report.get("recommendations", [])
        report["finished_at_epoch"] = time.time()
        _write_report(args.output_json, report)
        return 2

    if failures:
        print("\nRelease gate: FAILED")
        for item in failures:
            print(f"- {item}")
        if report.get("recommendations"):
            print("\nSuggested next actions:")
            for item in report["recommendations"]:
                print(f"- {item}")
        report["status"] = "failed"
        report["failures"] = failures
        report["finished_at_epoch"] = time.time()
        _write_report(args.output_json, report)
        return 1

    print("\nRelease gate: PASSED")
    report["status"] = "passed"
    report["failures"] = []
    report["finished_at_epoch"] = time.time()
    _write_report(args.output_json, report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run production release gate checks against Firewall Policy API")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001", help="API base URL")
    parser.add_argument("--token", default=None, help="Optional bearer token")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    parser.add_argument("--max-error-rate", type=float, default=0.02, help="Maximum allowed SLO error_rate")
    parser.add_argument("--max-latency-p95-ms", type=float, default=1500.0, help="Maximum allowed p95 latency in ms")
    parser.add_argument("--max-opa-unavailable", type=int, default=0, help="Maximum allowed opa_unavailable count")
    parser.add_argument("--retries", type=int, default=1, help="Retries for transient HTTP/network failures")
    parser.add_argument(
        "--initial-backoff-seconds",
        type=float,
        default=0.5,
        help="Initial backoff between retries; doubles each retry",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to write machine-readable gate result JSON",
    )
    parser.add_argument(
        "--max-slack-dispatch-failures",
        type=int,
        default=0,
        help="Maximum allowed Slack dispatch_failures count",
    )
    parser.add_argument(
        "--allow-alert-status",
        action="append",
        default=["ok"],
        help="Allowed /metrics/alerts status (repeatable, default: ok)",
    )
    parser.add_argument(
        "--skip-ingress-checks",
        action="store_true",
        help="Skip ingress and Grafana/Prometheus smoke checks",
    )
    parser.add_argument(
        "--ingress-base-url",
        default="https://127.0.0.1",
        help="Ingress base URL used for /health and /grafana/login checks",
    )
    parser.add_argument(
        "--ingress-host",
        default="18.170.45.5",
        help="Host header used for ingress checks",
    )
    parser.set_defaults(ingress_insecure_tls=True)
    parser.add_argument(
        "--verify-ingress-tls",
        action="store_false",
        dest="ingress_insecure_tls",
        help="Enable TLS verification for ingress checks (default is disabled)",
    )
    parser.add_argument(
        "--prometheus-base-url",
        default="http://127.0.0.1:9090",
        help="Prometheus base URL used to verify scrape targets",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.allowed_alert_status = {item.strip().lower() for item in args.allow_alert_status if item.strip()}
    if not args.allowed_alert_status:
        args.allowed_alert_status = {"ok"}
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
