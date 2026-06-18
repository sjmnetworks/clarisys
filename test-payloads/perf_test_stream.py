#!/usr/bin/env python3
"""Latency benchmark for /evaluate/bulk/stream.

Measures end-to-end (request-line to last-byte) latency for the NDJSON
streaming endpoint at several batch sizes, then reports p50/p95/p99 and
throughput. Used to pick the FirewallBulkStreamP95High alert threshold
in deploy/monitoring/firewall-rules.yml.

By default, spawns a fresh isolated uvicorn instance with all stateful
artifacts (ROI metrics, decision history, SLO state, audit log)
redirected to a tempdir, then tears it down after the run. This means
running this script CANNOT pollute prod ROI gauges, prod decision
history, or prod audit trail. Pass --target-existing URL to opt out.

Usage:
    python3 perf_test_stream.py                       # default: isolated self-host
    python3 perf_test_stream.py --runs 10
    python3 perf_test_stream.py --target-existing http://127.0.0.1:8001  # ⚠ contaminates that instance
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
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError


BATCH_SIZES = [1, 10, 50, 100, 250, 500]
DEFAULT_RUNS = 5
HEALTH_TIMEOUT_SECONDS = 30

INTERFACES = [
    ("finance-src", "analytics-dst"),
    ("payroll-src", "finance-dst"),
    ("office-src", "dns-dst"),
    ("retail-src", "payment-dst"),
    ("dmz-src", "internal-dst"),
]


def make_request(rng: random.Random) -> dict[str, Any]:
    src_if, dst_if = rng.choice(INTERFACES)
    return {
        "source": f"10.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 254)}",
        "destination": f"10.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 254)}",
        "protocol": rng.choice(["tcp", "udp"]),
        "port": rng.choice([443, 22, 53, 80, 8080]),
        "log": "all",
        "action": "accept",
        "source_interface": src_if,
        "destination_interface": dst_if,
        "data_classification": "Internal",
        "approved_external_sharing": False,
    }


def make_batch(size: int, seed: int = 42) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    return [make_request(rng) for _ in range(size)]


def stream_post(url: str, body: bytes, token: str | None, insecure: bool) -> tuple[float, int, int]:
    """POST and read the streamed response to completion. Returns
    (elapsed_seconds, bytes_received, line_count)."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-API-Key"] = token
    headers["X-Monitoring-Synthetic"] = "true"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    ctx = ssl._create_unverified_context() if insecure else None

    start = time.perf_counter()
    bytes_received = 0
    line_count = 0
    with urllib.request.urlopen(req, context=ctx) as resp:
        for raw in resp:
            bytes_received += len(raw)
            if raw.strip():
                line_count += 1
    elapsed = time.perf_counter() - start
    return elapsed, bytes_received, line_count


def run_size(url: str, size: int, runs: int, token: str | None, insecure: bool) -> dict[str, Any]:
    body = json.dumps({"requests": make_batch(size)}).encode("utf-8")
    samples_ms: list[float] = []
    bytes_received = 0
    lines = 0
    # warm-up (not measured)
    try:
        stream_post(url, body, token, insecure)
    except (HTTPError, URLError) as e:
        return {"size": size, "error": str(e)}

    for _ in range(runs):
        elapsed_s, b, l = stream_post(url, body, token, insecure)
        samples_ms.append(elapsed_s * 1000.0)
        bytes_received = b
        lines = l

    samples_ms.sort()
    n = len(samples_ms)
    p50 = samples_ms[n // 2]
    p95 = samples_ms[max(0, int(n * 0.95) - 1)] if n > 1 else samples_ms[0]
    p99 = samples_ms[max(0, int(n * 0.99) - 1)] if n > 1 else samples_ms[0]
    avg = statistics.mean(samples_ms)
    return {
        "size": size,
        "runs": runs,
        "avg_ms": round(avg, 1),
        "p50_ms": round(p50, 1),
        "p95_ms": round(p95, 1),
        "p99_ms": round(p99, 1),
        "min_ms": round(samples_ms[0], 1),
        "max_ms": round(samples_ms[-1], 1),
        "items_per_second": round(size / (avg / 1000.0), 1),
        "bytes": bytes_received,
        "ndjson_lines": lines,
    }


def _free_port() -> int:
    """Ask the kernel for a free TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_health(url: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("X-Monitoring-Synthetic", "true")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    return
        except (HTTPError, URLError, ConnectionError, OSError) as e:
            last_err = e
            time.sleep(0.25)
    raise RuntimeError(f"self-hosted API never became healthy at {url}: {last_err}")


def _spawn_isolated_api() -> tuple[subprocess.Popen, str, Path]:
    """Spawn a uvicorn instance with every state-bearing path redirected
    into a fresh tempdir. Caller must terminate the process and remove
    the tempdir.
    """
    repo_root = Path(__file__).resolve().parent.parent
    tmp = Path(tempfile.mkdtemp(prefix="opa-bench-"))
    (tmp / "audit").mkdir(exist_ok=True)
    (tmp / "evidence").mkdir(exist_ok=True)
    port = _free_port()

    # Force every state-bearing path into the tempdir so the bench can
    # never touch ~/.firewall-api/, policy/decision_history.jsonl, the
    # production audit dir, or the live SLO state file. These names must
    # stay in sync with the env-var lookups in api/main.py,
    # api/decision_history.py, and api/audit_store.py.
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
        cmd,
        cwd=str(repo_root),
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
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
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--target-existing",
        default=None,
        metavar="URL",
        help="Benchmark an already-running API at this base URL "
             "(e.g. http://127.0.0.1:8001). DANGER: contaminates that "
             "instance's ROI metrics, decision history, and audit trail. "
             "Omit to spawn a fresh isolated uvicorn for the benchmark.",
    )
    ap.add_argument("--token", default=None, help="API key sent as X-API-Key.")
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (only meaningful with --target-existing https://...).",
    )
    ap.add_argument("--sizes", default=",".join(str(s) for s in BATCH_SIZES))
    args = ap.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    spawned: subprocess.Popen | None = None
    tmp_dir: Path | None = None

    try:
        if args.target_existing:
            base_url = args.target_existing.rstrip("/")
            print(f"⚠  Benchmarking external instance: {base_url}")
            print("⚠  This WILL write to that instance's ROI metrics, audit, and history.")
        else:
            print("Spawning isolated self-hosted API (state in /tmp; prod is untouched)...")
            spawned, base_url, tmp_dir = _spawn_isolated_api()
            print(f"  base_url   = {base_url}")
            print(f"  tmp_state  = {tmp_dir}")

        stream_url = f"{base_url}/evaluate/bulk/stream"
        print(f"\nEndpoint: {stream_url}")
        print(f"Runs/size: {args.runs}")
        print(f"Sizes: {sizes}\n")

        rows: list[dict[str, Any]] = []
        for size in sizes:
            result = run_size(stream_url, size, args.runs, args.token, args.insecure)
            if "error" in result:
                print(f"size={size:>4}  ERROR: {result['error']}")
                continue
            rows.append(result)
            print(
                f"size={result['size']:>4}  "
                f"avg={result['avg_ms']:>8.1f}ms  "
                f"p50={result['p50_ms']:>8.1f}ms  "
                f"p95={result['p95_ms']:>8.1f}ms  "
                f"p99={result['p99_ms']:>8.1f}ms  "
                f"items/s={result['items_per_second']:>8.1f}"
            )

        print("\n--- summary ---")
        print(json.dumps(rows, indent=2))
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
