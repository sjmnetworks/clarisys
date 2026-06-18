#!/usr/bin/env python3
"""
Performance test for the /evaluate/bulk endpoint.

Runs sequential batches of sizes 1, 10, 50, 100, 200, 500, 1000 and reports
latency, throughput, response size (compressed and uncompressed), and verdict
mix.

The API's per-call bulk cap is 500 items, so batch sizes above 500 are split
into multiple back-to-back requests on the same HTTPS keep-alive connection
and aggregated.

Usage:
    python3 perf_test.py [--url URL] [--token TOKEN] [--runs N] [--insecure]

Examples:
    # Local HTTP (no auth)
    python3 perf_test.py --url http://127.0.0.1:8000

    # Production HTTPS with pilot key
    python3 perf_test.py \
        --url https://18.132.59.188 \
        --token A6DYz1GF7cQIAPQRPlmfQBtzkq_8IWQG9a1rh_IkvPo \
        --insecure
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

# ── Test parameters ──────────────────────────────────────────────────────────
BATCH_SIZES = [1, 10, 50, 100, 200, 500, 1000]
BULK_MAX_PER_CALL = 500           # server-side cap on /evaluate/bulk
DEFAULT_RUNS = 3                  # repeat each batch size N times for stability
HEALTH_TIMEOUT_SECONDS = 30

# ── Synthetic request generator ──────────────────────────────────────────────
INTERFACES = [
    ("finance-src", "analytics-dst"),
    ("payroll-src", "finance-dst"),
    ("office-src", "dns-dst"),
    ("retail-src", "payment-dst"),
    ("dmz-src", "internal-dst"),
    ("mgmt-src", "mgmt-dst"),
    ("partner-src", "shared-dst"),
    ("untrusted-src", "internet-dst"),
]


def make_request(seed_rng: random.Random) -> dict[str, Any]:
    src_if, dst_if = seed_rng.choice(INTERFACES)
    return {
        "source": f"10.{seed_rng.randint(1, 250)}.{seed_rng.randint(1, 250)}.{seed_rng.randint(1, 254)}",
        "destination": f"10.{seed_rng.randint(1, 250)}.{seed_rng.randint(1, 250)}.{seed_rng.randint(1, 254)}",
        "protocol": seed_rng.choice(["tcp", "udp"]),
        "port": seed_rng.choice([443, 22, 53, 80, 8080, 5432, 3306, 23, 3389]),
        "log": seed_rng.choice(["all", "no_log"]),
        "action": "accept",
        "source_interface": src_if,
        "destination_interface": dst_if,
        "data_classification": seed_rng.choice(["Internal", "Confidential", "Public"]),
        "approved_external_sharing": False,
    }


def make_batch(size: int, seed: int = 42) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    return [make_request(rng) for _ in range(size)]


# ── HTTP client ──────────────────────────────────────────────────────────────
def post_bulk(
    url: str,
    requests: list[dict[str, Any]],
    token: str | None,
    insecure: bool,
    timeout: float,
    endpoint: str = "/evaluate/bulk",
    stream: bool = False,
    synthetic_tag: str | None = None,
) -> tuple[int, int, int, dict[str, Any] | None, float, float | None]:
    """
    POST {requests: [...]} to {url}{endpoint}.

    Returns: (status_code, request_body_bytes, response_body_bytes, parsed_json, elapsed_s, ttfb_s)
    `ttfb_s` is populated only when `stream=True` (time to first response line).
    """
    payload = json.dumps({"requests": requests}, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept-Encoding": "identity" if stream else "gzip",
        "Connection": "keep-alive",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if synthetic_tag:
        headers["X-Request-Id"] = f"test-{synthetic_tag}-{uuid.uuid4().hex[:20]}"
        headers["X-Monitoring-Synthetic"] = "true"

    req = urllib.request.Request(
        url.rstrip("/") + endpoint,
        data=payload,
        headers=headers,
        method="POST",
    )

    ctx: ssl.SSLContext | None = None
    if url.lower().startswith("https://"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if stream:
                first_line = resp.readline()
                ttfb = time.perf_counter() - t0
                rest = resp.read()
                elapsed = time.perf_counter() - t0
                wire_bytes = len(first_line) + len(rest)
                summary = None
                # The summary line is always last; parse it for accept/deny counts.
                tail = (first_line + rest).rsplit(b"\n", 2)
                for candidate in reversed(tail):
                    if candidate.startswith(b'{"type": "summary"') or candidate.startswith(b'{"type":"summary"'):
                        try:
                            summary_obj = json.loads(candidate)
                            summary = {"summary": summary_obj["data"]}
                        except Exception:
                            pass
                        break
                return resp.status, len(payload), wire_bytes, summary, elapsed, ttfb
            body = resp.read()
            elapsed = time.perf_counter() - t0
            wire_bytes = len(body)
            try:
                import gzip
                decoded = gzip.decompress(body) if resp.headers.get("Content-Encoding") == "gzip" else body
                data = json.loads(decoded)
                return resp.status, len(payload), wire_bytes, data, elapsed, None
            except Exception:
                return resp.status, len(payload), wire_bytes, None, elapsed, None
    except HTTPError as e:
        elapsed = time.perf_counter() - t0
        return e.code, len(payload), 0, None, elapsed, None


# ── Benchmark runner ─────────────────────────────────────────────────────────
def bench_one(
    url: str,
    size: int,
    token: str | None,
    insecure: bool,
    timeout: float,
    stream: bool = False,
    synthetic_tag: str | None = None,
) -> dict[str, Any]:
    """Run a single batch of `size`, splitting if size > BULK_MAX_PER_CALL (or 5000 in stream mode)."""
    requests = make_batch(size)
    per_call_cap = 5000 if stream else BULK_MAX_PER_CALL
    endpoint = "/evaluate/bulk/stream" if stream else "/evaluate/bulk"

    if size <= per_call_cap:
        chunks = [requests]
    else:
        chunks = [
            requests[i : i + per_call_cap]
            for i in range(0, size, per_call_cap)
        ]

    total_req_bytes = 0
    total_resp_bytes = 0
    total_elapsed = 0.0
    first_ttfb: float | None = None
    acceptable = 0
    denied = 0
    status_codes: list[int] = []

    for chunk in chunks:
        status, req_bytes, resp_bytes, data, elapsed, ttfb = post_bulk(
            url,
            chunk,
            token,
            insecure,
            timeout,
            endpoint=endpoint,
            stream=stream,
            synthetic_tag=synthetic_tag,
        )
        status_codes.append(status)
        total_req_bytes += req_bytes
        total_resp_bytes += resp_bytes
        total_elapsed += elapsed
        if ttfb is not None and first_ttfb is None:
            first_ttfb = ttfb
        if data and "summary" in data:
            acceptable += data["summary"].get("acceptable", 0)
            denied += data["summary"].get("denied", 0)

    ok = all(s == 200 for s in status_codes)
    return {
        "size": size,
        "calls": len(chunks),
        "ok": ok,
        "status_codes": status_codes,
        "elapsed_s": total_elapsed,
        "ttfb_s": first_ttfb,
        "req_bytes": total_req_bytes,
        "resp_bytes": total_resp_bytes,
        "acceptable": acceptable,
        "denied": denied,
    }


def run(
    url: str,
    token: str | None,
    insecure: bool,
    runs: int,
    timeout: float,
    sizes: list[int] = BATCH_SIZES,
    stream: bool = False,
    synthetic_tag: str | None = None,
) -> int:
    print(f"Target: {url}")
    print(f"Runs per batch size: {runs}")
    if stream:
        print(f"Mode: NDJSON streaming (POST /evaluate/bulk/stream), per-call cap 5000\n")
    else:
        print(f"Bulk max per call: {BULK_MAX_PER_CALL} (batches above this size are split)\n")

    if stream:
        header = (
            f"{'size':>6} {'calls':>5} {'runs':>4} "
            f"{'ttfb_s':>8} {'mean_s':>8} {'p95_s':>8} {'max_s':>8} "
            f"{'req/s':>9} {'req_kb':>8} {'resp_kb':>8} "
            f"{'accept':>7} {'deny':>6} {'status':>10}"
        )
    else:
        header = (
            f"{'size':>6} {'calls':>5} {'runs':>4} "
            f"{'min_s':>8} {'mean_s':>8} {'p95_s':>8} {'max_s':>8} "
            f"{'req/s':>9} {'req_kb':>8} {'resp_kb':>8} "
            f"{'accept':>7} {'deny':>6} {'status':>10}"
        )
    print(header)
    print("-" * len(header))

    overall_ok = True

    for size in sizes:
        elapsed_samples: list[float] = []
        ttfb_samples: list[float] = []
        last: dict[str, Any] | None = None
        for _ in range(runs):
            try:
                result = bench_one(
                    url,
                    size,
                    token,
                    insecure,
                    timeout,
                    stream=stream,
                    synthetic_tag=synthetic_tag,
                )
            except (URLError, TimeoutError, OSError) as e:
                print(f"{size:>6} ERROR: {e}")
                overall_ok = False
                last = None
                break
            elapsed_samples.append(result["elapsed_s"])
            if result.get("ttfb_s") is not None:
                ttfb_samples.append(result["ttfb_s"])
            last = result

        if last is None:
            continue

        e_min = min(elapsed_samples)
        e_mean = statistics.mean(elapsed_samples)
        e_max = max(elapsed_samples)
        if len(elapsed_samples) >= 2:
            e_p95 = statistics.quantiles(elapsed_samples, n=20)[-1]
        else:
            e_p95 = e_max
        rps = size / e_mean if e_mean > 0 else 0.0

        status_str = ",".join(str(s) for s in last["status_codes"])
        leading = (
            statistics.mean(ttfb_samples) if stream and ttfb_samples else e_min
        )
        print(
            f"{size:>6} {last['calls']:>5} {runs:>4} "
            f"{leading:>8.3f} {e_mean:>8.3f} {e_p95:>8.3f} {e_max:>8.3f} "
            f"{rps:>9.1f} {last['req_bytes']/1024:>8.1f} {last['resp_bytes']/1024:>8.1f} "
            f"{last['acceptable']:>7} {last['denied']:>6} {status_str:>10}"
        )

        if not last["ok"]:
            overall_ok = False

    return 0 if overall_ok else 1


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_health(url: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except (HTTPError, URLError, ConnectionError, OSError) as e:
            last_err = e
            time.sleep(0.25)
    raise RuntimeError(f"self-hosted API never became healthy at {url}: {last_err}")


def _spawn_isolated_api() -> tuple[subprocess.Popen, str, Path]:
    """Spawn a uvicorn instance with every state-bearing path redirected
    into a fresh tempdir. The bench cannot then write to prod ROI gauges,
    decision history, audit log, or SLO state. Caller must terminate the
    process and delete the tempdir."""
    repo_root = Path(__file__).resolve().parent.parent
    tmp = Path(tempfile.mkdtemp(prefix="opa-bench-"))
    (tmp / "audit").mkdir(exist_ok=True)
    (tmp / "evidence").mkdir(exist_ok=True)
    port = _free_port()

    env = os.environ.copy()
    env.update({
        "FIREWALL_API_STATE_DIR": str(tmp),
        "ROI_METRICS_STATE_FILE": str(tmp / "roi-metrics.json"),
        "DECISION_HISTORY_FILE": str(tmp / "decision_history.jsonl"),
        "DECISION_LIFECYCLE_FILE": str(tmp / "decision_lifecycle.json"),
        "SLO_STATE_FILE": str(tmp / "slo-metrics.json"),
        "AUDIT_DIR": str(tmp / "audit"),
        "EVIDENCE_DIR": str(tmp / "evidence"),
        "APP_ENV": "development",
        "AUTH_ENABLED": "false",
        "LOG_LEVEL": "WARNING",
    })

    venv_uvicorn = repo_root / ".venv" / "bin" / "uvicorn"
    cmd = [
        str(venv_uvicorn) if venv_uvicorn.exists() else "uvicorn",
        "api.main:app",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--log-level", "warning",
    ]

    log_path = tmp / "uvicorn.log"
    log_fh = open(log_path, "w")
    proc = subprocess.Popen(
        cmd, cwd=str(repo_root), env=env,
        stdout=log_fh, stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_health(f"{base_url}/health", HEALTH_TIMEOUT_SECONDS)
    except Exception:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        sys.stderr.write(f"\n--- uvicorn log ({log_path}) ---\n")
        try:
            sys.stderr.write(log_path.read_text(errors="replace")[-4000:])
        except OSError:
            pass
        raise
    return proc, base_url, tmp


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=None,
                   help="Base URL of an existing API. DANGER: writes to that instance's "
                        "ROI metrics, audit, and decision history. Omit to spawn a fresh "
                        "isolated uvicorn (state in /tmp; prod is untouched).")
    p.add_argument("--token", default=None, help="Bearer token (pilot API key or JWT)")
    p.add_argument("--runs", type=int, default=DEFAULT_RUNS, help="Runs per batch size (default: %(default)s)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (for self-signed certs)")
    p.add_argument("--timeout", type=float, default=120.0, help="Per-call timeout in seconds (default: %(default)s)")
    p.add_argument("--sizes", default=None, help="Comma-separated batch sizes to test (default: %s)" % ",".join(str(s) for s in BATCH_SIZES))
    p.add_argument("--stream", action="store_true", help="Hit /evaluate/bulk/stream (NDJSON) and report TTFB in the first time column")
    p.add_argument(
        "--synthetic-tag",
        default="perf",
        help="Tag outgoing requests as synthetic using X-Request-Id and X-Monitoring-Synthetic (default: %(default)s). Set empty string to disable.",
    )
    args = p.parse_args()
    sizes = BATCH_SIZES if not args.sizes else [int(s) for s in args.sizes.split(",") if s.strip()]

    spawned: subprocess.Popen | None = None
    tmp_dir: Path | None = None
    try:
        if args.url:
            base_url = args.url
            print(f"⚠  Benchmarking external instance: {base_url}")
            print("⚠  This WILL write to that instance's ROI metrics, audit, and history.")
        else:
            print("Spawning isolated self-hosted API (state in /tmp; prod is untouched)...")
            spawned, base_url, tmp_dir = _spawn_isolated_api()
            print(f"  base_url   = {base_url}")
            print(f"  tmp_state  = {tmp_dir}")
        synthetic_tag = args.synthetic_tag.strip() if args.synthetic_tag is not None else ""
        return run(
            base_url,
            args.token,
            args.insecure,
            args.runs,
            args.timeout,
            sizes,
            stream=args.stream,
            synthetic_tag=synthetic_tag or None,
        )
    finally:
        if spawned is not None:
            spawned.terminate()
            try:
                spawned.wait(timeout=5)
            except subprocess.TimeoutExpired:
                spawned.kill()
                spawned.wait()
        if tmp_dir is not None and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
