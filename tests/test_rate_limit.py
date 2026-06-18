"""Tests for rate limiting (Phase 3)."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import rate_limit
from api.main import OPA_BINARY, app

pytestmark = pytest.mark.skipif(
    shutil.which(OPA_BINARY) is None and not shutil.which("opa"),
    reason="OPA binary is required for endpoint tests",
)

client = TestClient(app)


@pytest.fixture()
def acceptable_request() -> dict:
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


# ── Rate limiting (Phase 3) ────────────────────────────────────────────────────
def test_rate_limit_disabled_by_default(acceptable_request: dict) -> None:
    # RATE_LIMIT_ENABLED is unset / "false" so /evaluate should respond normally
    # without 429 even if hit multiple times rapidly
    for _ in range(5):
        resp = client.post("/evaluate", json=acceptable_request)
        assert resp.status_code == 200, resp.text


def test_rate_limit_enabled_rejects_excess_requests(
    monkeypatch: pytest.MonkeyPatch, acceptable_request: dict
) -> None:
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECS", "60")
    monkeypatch.setenv("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", "3")
    rate_limit.reload_settings_for_tests()
    limiter = rate_limit.get_limiter()
    limiter.reset_for_tests()
    try:
        # First 3 requests should succeed
        for i in range(3):
            resp = client.post("/evaluate", json=acceptable_request)
            assert resp.status_code == 200, f"Request {i+1} failed: {resp.text}"
            assert "X-RateLimit-Limit" in resp.headers

        # 4th request should be rate-limited
        resp = client.post("/evaluate", json=acceptable_request)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert resp.text == "Rate limit exceeded."

        slo_metrics = client.get("/metrics/slo?format=prometheus")
        assert slo_metrics.status_code == 200, slo_metrics.text
        assert "firewall_rate_limited_total 1" in slo_metrics.text
    finally:
        monkeypatch.delenv("RATE_LIMIT_ENABLED", raising=False)
        monkeypatch.delenv("RATE_LIMIT_WINDOW_SECS", raising=False)
        monkeypatch.delenv("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", raising=False)
        rate_limit.reload_settings_for_tests()
        limiter.reset_for_tests()


def test_rate_limit_headers_stamped_on_response(
    monkeypatch: pytest.MonkeyPatch, acceptable_request: dict
) -> None:
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", "10")
    rate_limit.reload_settings_for_tests()
    limiter = rate_limit.get_limiter()
    limiter.reset_for_tests()
    try:
        resp = client.post("/evaluate", json=acceptable_request)
        assert resp.status_code == 200
        assert resp.headers.get("X-RateLimit-Limit") == "10"
        assert resp.headers.get("X-RateLimit-Remaining") == "9"
    finally:
        monkeypatch.delenv("RATE_LIMIT_ENABLED", raising=False)
        monkeypatch.delenv("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", raising=False)
        rate_limit.reload_settings_for_tests()
        limiter.reset_for_tests()


def test_rate_limit_per_endpoint(
    monkeypatch: pytest.MonkeyPatch, acceptable_request: dict
) -> None:
    # Different endpoints have different quotas
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", "5")
    monkeypatch.setenv("RATE_LIMIT_QUOTA_BULK_PER_MIN", "2")
    rate_limit.reload_settings_for_tests()
    limiter = rate_limit.get_limiter()
    limiter.reset_for_tests()
    try:
        # /evaluate allows 5 per minute (use 3)
        for _ in range(3):
            resp = client.post("/evaluate", json=acceptable_request)
            assert resp.status_code == 200

        # /evaluate/bulk allows only 2 per minute
        bulk_req = {"requests": [acceptable_request]}
        for i in range(2):
            resp = client.post("/evaluate/bulk", json=bulk_req)
            assert resp.status_code == 200, f"Bulk request {i+1} failed: {resp.text}"

        # 3rd bulk request should be rate-limited (hit quota of 2)
        resp = client.post("/evaluate/bulk", json=bulk_req)
        assert resp.status_code == 429
    finally:
        monkeypatch.delenv("RATE_LIMIT_ENABLED", raising=False)
        monkeypatch.delenv("RATE_LIMIT_QUOTA_EVALUATE_PER_MIN", raising=False)
        monkeypatch.delenv("RATE_LIMIT_QUOTA_BULK_PER_MIN", raising=False)
        rate_limit.reload_settings_for_tests()
        limiter.reset_for_tests()
