"""
ROI metrics exporter for Prometheus.
Tracks firewall rules processed with deduplication by request_id.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path

from api import decision_history
from api.atomic_io import atomic_write_json
from api.logging_setup import get_logger
from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry, generate_latest

log = get_logger("roi_metrics")

# Shared registry for all metrics
REGISTRY = CollectorRegistry()

ROI_METRICS_STATE_FILE = Path(
    os.environ.get("ROI_METRICS_STATE_FILE", str(Path.home() / ".firewall-api" / "roi-metrics.json"))
)

_STATE_LOCK = threading.Lock()

# Counters for total rules processed (deduped by request_id)
rules_processed_counter = Counter(
    "firewall_rules_processed_total",
    "Total firewall rules processed (deduplicated by request_id)",
    labelnames=["endpoint", "verdict"],
    registry=REGISTRY,
)

# Per-endpoint request latency histogram. Used by Prom's histogram_quantile()
# for SLO percentiles per endpoint (e.g. /evaluate/bulk/stream p95). Buckets
# are tuned for an internal API: dense around 5-500ms (where the bulk of API
# traffic lands), sparse for the multi-second tail (long bulk batches).
# Switching to a Histogram lets Prom compute correct time-windowed quantiles
# server-side; the in-process deque in main.py only knows lifetime quantiles
# and was global across all endpoints.
request_latency_histogram = Histogram(
    "firewall_request_latency_seconds",
    "Request handler latency in seconds, labelled by endpoint",
    labelnames=["endpoint"],
    buckets=(
        0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500,
        1.0, 2.5, 5.0, 10.0, 30.0,
    ),
    registry=REGISTRY,
)

# Dedicated histogram for NDJSON bulk-stream total wall-clock duration.
# The main request_latency_histogram fires when StreamingResponse is *returned*
# (time-to-first-response-object, typically <5ms); this histogram fires when the
# generator is fully exhausted and measures true end-to-end stream duration.
# Buckets are tuned to the observed throughput baseline (~30 items/s, linear):
#   1 item ~36ms, 50 items ~1.6s, 100 items ~3.3s, 500 items ~15.6s
stream_duration_histogram = Histogram(
    "firewall_stream_duration_seconds",
    "Total end-to-end wall-clock duration for NDJSON bulk-stream endpoints, labelled by endpoint",
    labelnames=["endpoint"],
    buckets=(
        0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 20.0, 30.0, 60.0,
    ),
    registry=REGISTRY,
)

# Gauge mirroring _METRICS_STATE["total_rules"]: the persisted, history-bootstrapped
# rule count. The labelled counter above resets to 0 on every process restart and
# only reflects post-restart traffic — using it on dashboards alongside the
# bootstrapped gauges below produced wildly inconsistent panels (e.g. 10 rules
# vs £742k saved). Read this gauge for any "total rules processed" panel.
rules_processed_gauge = Gauge(
    "firewall_rules_processed_current",
    "Current cumulative count of rules processed (mirrors persisted ROI state)",
    registry=REGISTRY,
)

# Gauge for HIPS freed (cumulative)
hips_freed_gauge = Gauge(
    "firewall_hips_freed_total",
    "Total HIPS (humans in process) freed by automation",
    registry=REGISTRY,
)

# Gauge for cumulative cost savings in GBP
cost_saved_gauge = Gauge(
    "firewall_cost_saved_gbp_total",
    "Total cost savings in GBP from automation",
    registry=REGISTRY,
)

# Gauge for FTE redeployed
fte_redeployed_gauge = Gauge(
    "firewall_fte_redeployed_total",
    "Total FTEs redeployed from manual work",
    registry=REGISTRY,
)

# OPA cache metrics
opa_cache_hits_gauge = Gauge(
    "firewall_opa_cache_hits_total",
    "Total OPA cache hits",
    registry=REGISTRY,
)

opa_cache_misses_gauge = Gauge(
    "firewall_opa_cache_misses_total",
    "Total OPA cache misses",
    registry=REGISTRY,
)

opa_cache_evictions_gauge = Gauge(
    "firewall_opa_cache_evictions_total",
    "Total OPA cache evictions due to size limit",
    registry=REGISTRY,
)

opa_cache_invalidations_gauge = Gauge(
    "firewall_opa_cache_invalidations_total",
    "Total OPA cache invalidations due to policy file changes",
    registry=REGISTRY,
)

opa_cache_size_gauge = Gauge(
    "firewall_opa_cache_entries",
    "Current OPA cache size (entries)",
    registry=REGISTRY,
)

opa_cache_hit_rate_gauge = Gauge(
    "firewall_opa_cache_hit_rate",
    "OPA cache hit rate (hits / (hits + misses))",
    registry=REGISTRY,
)

opa_requests_counter = Counter(
    "firewall_opa_requests_total",
    "Total OPA HTTP requests by mode and outcome",
    labelnames=["mode", "outcome"],  # mode=single|batch, outcome=success|error|timeout|circuit_open
    registry=REGISTRY,
)

opa_request_latency_histogram = Histogram(
    "firewall_opa_request_latency_seconds",
    "OPA HTTP request latency in seconds by mode",
    labelnames=["mode"],
    buckets=(0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0, 30.0),
    registry=REGISTRY,
)

opa_timeouts_counter = Counter(
    "firewall_opa_timeout_total",
    "Total OPA HTTP timeout events by mode",
    labelnames=["mode"],
    registry=REGISTRY,
)

# Counter incremented at startup when on-disk state diverges materially from
# the history-derived rule count. See _check_state_drift() for the rule.
roi_state_drift_counter = Counter(
    "firewall_roi_state_drift_total",
    "Times the ROI state file disagreed with decision history at bootstrap",
    labelnames=["direction"],  # "snapshot_high" or "snapshot_low"
    registry=REGISTRY,
)

# Counter incremented when drift is extreme enough that we discard the
# disk snapshot and rebuild from decision history (see _check_state_drift).
roi_state_drift_autocorrect_counter = Counter(
    "firewall_roi_state_drift_autocorrect_total",
    "Times the ROI state file was auto-rebuilt from decision history due to extreme drift",
    labelnames=["direction"],
    registry=REGISTRY,
)

# Track seen request_ids to deduplicate
_SEEN_REQUEST_IDS = set()
_METRICS_STATE = {
    "total_rules": 0,
    "last_updated": 0,
}

# ROI calculation constants
HIPS_FREED_PER_RULE = 21
HOURS_PER_RULE = 42  # 21 HIPS × 2 hours
HOURLY_RATE_GBP = 24.04  # £50k / 2080 hours
COST_PER_RULE = HOURS_PER_RULE * HOURLY_RATE_GBP  # 42h × £24.04/h = £1,009.68 (exact)
HOURS_PER_FTE = 2080


def _save_state() -> None:
    payload = {
        "total_rules": _METRICS_STATE["total_rules"],
        "last_updated": _METRICS_STATE["last_updated"],
        "seen_request_ids": sorted(_SEEN_REQUEST_IDS),
    }
    try:
        ROI_METRICS_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(ROI_METRICS_STATE_FILE, payload, separators=(",", ":"))
    except Exception:
        return


def _load_state() -> None:
    if not ROI_METRICS_STATE_FILE.exists():
        _bootstrap_from_history()
        return
    try:
        payload = json.loads(ROI_METRICS_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(payload, dict):
        return

    with _STATE_LOCK:
        try:
            _METRICS_STATE["total_rules"] = max(0, int(payload.get("total_rules", 0)))
        except (TypeError, ValueError):
            _METRICS_STATE["total_rules"] = 0
        try:
            _METRICS_STATE["last_updated"] = int(payload.get("last_updated", 0))
        except (TypeError, ValueError):
            _METRICS_STATE["last_updated"] = 0

        _SEEN_REQUEST_IDS.clear()
        seen_request_ids = payload.get("seen_request_ids", [])
        if isinstance(seen_request_ids, list):
            for item in seen_request_ids:
                if isinstance(item, str):
                    _SEEN_REQUEST_IDS.add(item)

        total_rules = _METRICS_STATE["total_rules"]
        rules_processed_gauge.set(total_rules)
        hips_freed_gauge.set(total_rules * HIPS_FREED_PER_RULE)
        cost_saved_gauge.set(total_rules * COST_PER_RULE)
        fte_redeployed_gauge.set(total_rules * HIPS_FREED_PER_RULE / HOURS_PER_FTE)

    _check_state_drift(_METRICS_STATE["total_rules"])


def _count_rules_in_history() -> int:
    """Return the number of valid decision rows in the history file.

    Returns -1 if the history file is missing or unreadable (caller should
    skip drift detection in that case rather than treat it as 0 rules).
    """
    history_path = decision_history._history_path()
    if not history_path.exists():
        return -1
    try:
        lines = history_path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return -1
    count = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            count += 1
    return count


# Drift detection thresholds. We want to ignore small bookkeeping skew
# (e.g. a single appended row not yet snapshotted) but flag the kind of
# in-memory ↔ disk divergence we saw on 2026-06-10 (50 → 22 jump on
# restart).
_STATE_DRIFT_ABS_THRESHOLD = 5
_STATE_DRIFT_REL_THRESHOLD = 0.10  # 10%

# Auto-correct threshold: when |delta| / max(history, 1) exceeds this,
# the disk snapshot is too far gone to trust and we rebuild from the
# decision history (which is append-only and authoritative). Picked at
# 0.5 because the 2026-06-10 incident (22 vs 505 ≈ -96%) and the previous
# day's stale-gauge case (50 vs 22 ≈ +127%) are both well above this,
# while normal bookkeeping skew is well below.
_STATE_DRIFT_AUTOCORRECT_REL_THRESHOLD = 0.5


def _check_state_drift(disk_total: int) -> bool:
    """Return True if the caller should keep the disk snapshot, False if
    we have already rebuilt state from decision history (caller must skip
    further state mutation)."""
    history_total = _count_rules_in_history()
    if history_total < 0:
        return True  # No history to reconcile against — trust the disk snapshot.

    delta = disk_total - history_total
    abs_delta = abs(delta)
    threshold = max(
        _STATE_DRIFT_ABS_THRESHOLD,
        int(history_total * _STATE_DRIFT_REL_THRESHOLD),
    )
    if abs_delta < threshold:
        return True

    direction = "snapshot_high" if delta > 0 else "snapshot_low"
    roi_state_drift_counter.labels(direction=direction).inc()
    log.warning(
        "roi.state_drift_detected",
        disk_total=disk_total,
        history_total=history_total,
        delta=delta,
        direction=direction,
        threshold=threshold,
    )

    # Auto-correct path: drift is so large the snapshot is untrustworthy.
    # Rebuild from decision history (which is append-only and survives
    # bad snapshot writes), then re-save the corrected snapshot so the
    # next restart starts from a consistent state.
    rel = abs_delta / max(history_total, 1)
    if rel >= _STATE_DRIFT_AUTOCORRECT_REL_THRESHOLD:
        roi_state_drift_autocorrect_counter.labels(direction=direction).inc()
        log.warning(
            "roi.state_drift_autocorrect",
            disk_total=disk_total,
            history_total=history_total,
            delta=delta,
            direction=direction,
            relative=round(rel, 4),
        )
        # _bootstrap_from_history mutates _METRICS_STATE under the same
        # lock as _save_state, so the rebuild + snapshot is atomic from
        # the caller's perspective.
        if _bootstrap_from_history():
            _save_state()
            return False
    return True


def _bootstrap_from_history() -> bool:
    history_path = decision_history._history_path()
    if not history_path.exists():
        return False

    total_rules = 0
    latest_ts = 0
    try:
        lines = history_path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False

    parse_errors = 0
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            parse_errors += 1
            if parse_errors <= 5:  # Log first 5 errors to avoid spam
                log.warning("roi.history_parse_error", line_number=idx, error=str(e))
            continue
        if not isinstance(row, dict):
            continue
        total_rules += 1
        ts_text = row.get("ts")
        if isinstance(ts_text, str):
            try:
                ts = int(datetime.fromisoformat(ts_text.replace("Z", "+00:00")).timestamp())
            except ValueError:
                ts = 0
            latest_ts = max(latest_ts, ts)

    if parse_errors > 5:
        log.warning("roi.history_parse_errors_truncated", total_errors=parse_errors, shown=5)
    if total_rules <= 0:
        return False

    with _STATE_LOCK:
        _METRICS_STATE["total_rules"] = total_rules
        _METRICS_STATE["last_updated"] = latest_ts
        # Clear the dedup set: composite keys for bulk/stream entries
        # (request_id:idx) cannot be reconstructed from history (which
        # only stores the parent request_id). Trying to keep stale keys
        # leads to a permanent mismatch where total_rules grows without
        # bound while seen_request_ids stays frozen at whatever was on
        # disk pre-bootstrap. Empty set → next traffic repopulates it.
        _SEEN_REQUEST_IDS.clear()
        rules_processed_gauge.set(total_rules)
        hips_freed_gauge.set(total_rules * HIPS_FREED_PER_RULE)
        cost_saved_gauge.set(total_rules * COST_PER_RULE)
        fte_redeployed_gauge.set(total_rules * HIPS_FREED_PER_RULE / HOURS_PER_FTE)
    return True


_load_state()


def record_rule_processed(request_id: str, endpoint: str, verdict: str) -> None:
    """
    Record a single rule processed, deduplicating by request_id.
    Updates all derived metrics (HIPS, cost, FTE).
    
    Args:
        request_id: Unique request identifier (used for deduplication)
        endpoint: API endpoint (e.g., "/evaluate", "/evaluate/bulk/stream")
        verdict: "ALLOW" or "DENY"
    """
    with _STATE_LOCK:
        if request_id in _SEEN_REQUEST_IDS:
            return

        _SEEN_REQUEST_IDS.add(request_id)
        _METRICS_STATE["total_rules"] += 1
        _METRICS_STATE["last_updated"] = int(time.time())

        # Increment counter
        rules_processed_counter.labels(endpoint=endpoint, verdict=verdict).inc()

        # Update gauges (cumulative)
        total_rules = _METRICS_STATE["total_rules"]
        rules_processed_gauge.set(total_rules)
        hips_freed_gauge.set(total_rules * HIPS_FREED_PER_RULE)
        cost_saved_gauge.set(total_rules * COST_PER_RULE)
        fte_redeployed_gauge.set(total_rules * HIPS_FREED_PER_RULE / HOURS_PER_FTE)
        _save_state()


def record_bulk_rules(request_id: str, endpoint: str, rules: list, verdicts: dict) -> None:
    """
    Record multiple rules from a bulk/stream operation.
    Each rule is deduplicated independently by a composite key.
    
    Args:
        request_id: Parent request identifier
        endpoint: API endpoint
        rules: List of traffic request objects with (source, destination, port)
        verdicts: Dict mapping rule index to verdict string
    """
    for idx, rule in enumerate(rules):
        # Composite dedup key: request_id + rule index
        dedup_key = f"{request_id}:{idx}"
        verdict = verdicts.get(idx, "UNKNOWN")
        record_rule_processed(dedup_key, endpoint, verdict)


def get_current_metrics() -> dict:
    """Return current metric state as a dict."""
    total = _METRICS_STATE["total_rules"]
    return {
        "total_rules": total,
        "rules_processed": total,
        "hips_freed": int(total * HIPS_FREED_PER_RULE),
        "hours_saved": int(total * HOURS_PER_RULE),
        "cost_saved_gbp": int(total * COST_PER_RULE),
        "fte_redeployed": total * HIPS_FREED_PER_RULE / HOURS_PER_FTE,
        "last_updated": _METRICS_STATE["last_updated"],
    }


def update_opa_cache_metrics(cache_stats: dict) -> None:
    """Update OPA cache Prometheus metrics from cache statistics."""
    hits = cache_stats.get("hits", 0)
    misses = cache_stats.get("misses", 0)
    
    opa_cache_hits_gauge.set(hits)
    opa_cache_misses_gauge.set(misses)
    opa_cache_evictions_gauge.set(cache_stats.get("evictions", 0))
    opa_cache_invalidations_gauge.set(cache_stats.get("invalidations", 0))
    opa_cache_size_gauge.set(cache_stats.get("size", 0))
    
    # Calculate hit rate
    total = hits + misses
    if total > 0:
        hit_rate = hits / total
    else:
        hit_rate = 0.0
    opa_cache_hit_rate_gauge.set(hit_rate)


def record_opa_request(
    *,
    mode: str,
    outcome: str,
    latency_seconds: float | None = None,
    timed_out: bool = False,
) -> None:
    """Record OPA request telemetry used by alerting and dashboards."""
    safe_mode = mode if mode in {"single", "batch"} else "single"
    safe_outcome = outcome if outcome in {"success", "error", "timeout", "circuit_open"} else "error"
    opa_requests_counter.labels(mode=safe_mode, outcome=safe_outcome).inc()
    if latency_seconds is not None and latency_seconds >= 0:
        opa_request_latency_histogram.labels(mode=safe_mode).observe(float(latency_seconds))
    if timed_out:
        opa_timeouts_counter.labels(mode=safe_mode).inc()


def get_prometheus_metrics() -> bytes:
    """Return Prometheus text format metrics."""
    return generate_latest(REGISTRY)


def reset_metrics() -> None:
    """Reset all metrics (use with caution, typically for testing)."""
    with _STATE_LOCK:
        _SEEN_REQUEST_IDS.clear()
        _METRICS_STATE["total_rules"] = 0
        _METRICS_STATE["last_updated"] = int(time.time())
        # Reset gauges
        rules_processed_gauge.set(0)
        hips_freed_gauge.set(0)
        cost_saved_gauge.set(0)
        fte_redeployed_gauge.set(0)
        _save_state()
