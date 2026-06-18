"""Tests for the per-endpoint request latency histogram."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import roi_metrics
from api.main import OPA_BINARY, app

pytestmark = pytest.mark.skipif(
    shutil.which(OPA_BINARY) is None and not shutil.which("opa"),
    reason="OPA binary is required for endpoint tests",
)


def _bucket_count_for(endpoint: str) -> int:
    """Return the +Inf bucket count for the given endpoint label."""
    for sample in roi_metrics.request_latency_histogram.collect()[0].samples:
        if (
            sample.name == "firewall_request_latency_seconds_count"
            and sample.labels.get("endpoint") == endpoint
        ):
            return int(sample.value)
    return 0


def test_request_latency_histogram_registered() -> None:
    """The histogram must exist on the shared registry exposed via /metrics."""
    output = roi_metrics.get_prometheus_metrics().decode("utf-8")
    assert "firewall_request_latency_seconds" in output
    assert "# TYPE firewall_request_latency_seconds histogram" in output


def test_request_latency_histogram_observes_per_endpoint() -> None:
    """A real /health call should bump the histogram for that route only."""
    client = TestClient(app)
    before = _bucket_count_for("/health")

    response = client.get("/health", headers={"x-request-id": "hist-health-1"})
    assert response.status_code == 200

    after = _bucket_count_for("/health")
    assert after - before == 1, (
        f"expected +1 observation for /health, got +{after - before}"
    )


def test_request_latency_histogram_label_uses_route_template() -> None:
    """Label must be the route template, not the request URL, so cardinality
    stays bounded by the number of registered routes."""
    client = TestClient(app)
    client.get("/health", headers={"x-request-id": "hist-health-2"})

    output = roi_metrics.get_prometheus_metrics().decode("utf-8")
    # /health is registered; bucket lines for it must appear with the exact
    # template as label value.
    assert 'endpoint="/health"' in output
    # An unregistered URL must not show up as its own label value.
    client.get("/this-path-does-not-exist", headers={"x-request-id": "hist-notfound-1"})
    output = roi_metrics.get_prometheus_metrics().decode("utf-8")
    assert 'endpoint="/this-path-does-not-exist"' not in output


def test_request_latency_histogram_excludes_synthetic_tagged_requests() -> None:
    """Synthetic-tagged calls must not appear in request latency metrics."""
    client = TestClient(app)
    before = _bucket_count_for("/evaluate")

    response = client.post(
        "/evaluate",
        json={
            "source": "10.157.26.5",
            "destination": "10.221.126.33",
            "protocol": "tcp",
            "port": 443,
            "log": "all",
            "data_classification": "Internal",
            "source_interface": "finance-src",
            "destination_interface": "analytics-dst",
        },
        headers={"x-monitoring-synthetic": "true"},
    )
    assert response.status_code == 200

    after = _bucket_count_for("/evaluate")
    assert after == before
