#!/usr/bin/env python3
"""
Post a deploy/event annotation to all Grafana dashboards.

Usage (basic):
  python3 tools/post_grafana_annotation.py --text "Deployed v1.2.3"

Usage (custom tags):
  python3 tools/post_grafana_annotation.py --text "Config reload" --tags deploy config

Credentials (in priority order):
  1. --token / GRAFANA_TOKEN  (service account token or legacy API key)
  2. --user + --password      (basic auth)

URL defaults to http://127.0.0.1:3000; override with --url or GRAFANA_URL.

Exit codes:
  0  annotation posted successfully
  1  request failed (see stderr)
  2  bad arguments
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import sys
import time
from urllib.parse import urlparse


def _build_headers(token: str | None, user: str | None, password: str | None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif user and password:
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
    return headers


def _post_annotation(
    base_url: str,
    text: str,
    tags: list[str],
    headers: dict[str, str],
    dashboard_uid: str | None,
) -> tuple[int, dict]:
    parsed = urlparse(base_url)
    use_tls = parsed.scheme == "https"
    host = parsed.netloc or parsed.path
    ConnCls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    conn = ConnCls(host, timeout=10)

    payload: dict = {
        "text": text,
        "tags": tags,
        "time": int(time.time() * 1000),
        "timeEnd": int(time.time() * 1000),
    }
    if dashboard_uid:
        payload["dashboardUID"] = dashboard_uid

    body = json.dumps(payload).encode("utf-8")
    try:
        conn.request("POST", "/api/annotations", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, {"raw": data.decode("utf-8", "replace")}
    finally:
        conn.close()


def _post_annotation_with_retry(
    base_url: str,
    text: str,
    tags: list[str],
    headers: dict[str, str],
    dashboard_uid: str | None,
    retry_window_seconds: float,
    retry_initial_delay_seconds: float,
    retry_max_delay_seconds: float,
) -> tuple[int, dict, int]:
    attempts = 0
    delay = max(0.0, retry_initial_delay_seconds)
    max_delay = max(0.0, retry_max_delay_seconds)
    deadline = time.monotonic() + max(0.0, retry_window_seconds)

    while True:
        attempts += 1
        try:
            status, result = _post_annotation(base_url, text, tags, headers, dashboard_uid)
        except (OSError, http.client.HTTPException) as exc:
            status = 0
            result = {"error": f"{type(exc).__name__}: {exc}"}

        retryable = status == 0 or status in (408, 425, 429, 500, 502, 503, 504)
        now = time.monotonic()
        if not retryable or now >= deadline:
            return status, result, attempts

        sleep_for = min(delay, max(0.0, deadline - now))
        if sleep_for <= 0:
            return status, result, attempts

        print(
            f"warn: grafana annotation post attempt {attempts} failed "
            f"(status={status}, result={result}); retrying in {sleep_for:.1f}s",
            file=sys.stderr,
        )
        time.sleep(sleep_for)
        if max_delay > 0:
            delay = min(max_delay, delay * 2 if delay > 0 else max_delay)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Post a deploy/event annotation to Grafana dashboards.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Exit codes:")[0].strip(),
    )
    parser.add_argument("--text", required=True, help="Annotation body text")
    parser.add_argument(
        "--tags",
        nargs="*",
        default=["deploy"],
        metavar="TAG",
        help="Space-separated tags (default: deploy)",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000"),
        help="Grafana base URL (default: GRAFANA_URL env or http://127.0.0.1:3000)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GRAFANA_TOKEN"),
        help="Grafana service account token or legacy API key (GRAFANA_TOKEN env)",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("GRAFANA_USER", "admin"),
        help="Grafana username for basic auth (GRAFANA_USER env, default: admin)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("GRAFANA_PASSWORD"),
        help="Grafana password for basic auth (GRAFANA_PASSWORD env)",
    )
    parser.add_argument(
        "--dashboard-uid",
        default=None,
        help="Scope annotation to one dashboard UID (omit for global annotation)",
    )
    parser.add_argument(
        "--retry-window-seconds",
        type=float,
        default=float(os.environ.get("GRAFANA_RETRY_WINDOW_SECONDS", "30")),
        help="Total retry window for transient failures (default: 30)",
    )
    parser.add_argument(
        "--retry-initial-delay-seconds",
        type=float,
        default=float(os.environ.get("GRAFANA_RETRY_INITIAL_DELAY_SECONDS", "1")),
        help="Initial retry delay in seconds (default: 1)",
    )
    parser.add_argument(
        "--retry-max-delay-seconds",
        type=float,
        default=float(os.environ.get("GRAFANA_RETRY_MAX_DELAY_SECONDS", "8")),
        help="Maximum backoff delay in seconds (default: 8)",
    )

    args = parser.parse_args()

    if args.retry_window_seconds < 0:
        parser.error("--retry-window-seconds must be >= 0")
    if args.retry_initial_delay_seconds < 0:
        parser.error("--retry-initial-delay-seconds must be >= 0")
    if args.retry_max_delay_seconds < 0:
        parser.error("--retry-max-delay-seconds must be >= 0")

    if not args.token and not args.password:
        # No credentials configured — silent no-op so callers (e.g. systemd
        # ExecStartPost, CI scripts) don't fail when Grafana auth isn't set up.
        print("info: GRAFANA_TOKEN/GRAFANA_PASSWORD not set; skipping annotation")
        return 0

    headers = _build_headers(args.token, args.user, args.password)
    status, result, attempts = _post_annotation_with_retry(
        args.url,
        args.text,
        args.tags,
        headers,
        args.dashboard_uid,
        args.retry_window_seconds,
        args.retry_initial_delay_seconds,
        args.retry_max_delay_seconds,
    )

    if status in (200, 201):
        annotation_id = result.get("id", "?")
        print(
            f"annotation posted (id={annotation_id}, attempts={attempts}, tags={args.tags}): "
            f"{args.text}"
        )
        return 0

    print(f"error: grafana returned HTTP {status}: {result}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
