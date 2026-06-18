"""Tests for tools/post_grafana_annotation.py retry behavior."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "post_grafana_annotation.py"
_spec = importlib.util.spec_from_file_location("_post_grafana_annotation", _TOOL_PATH)
assert _spec is not None and _spec.loader is not None
post_grafana_annotation = importlib.util.module_from_spec(_spec)
sys.modules["_post_grafana_annotation"] = post_grafana_annotation
_spec.loader.exec_module(post_grafana_annotation)


def test_retry_stops_on_first_success(monkeypatch) -> None:
    """A 2xx response should return immediately with one attempt."""
    monkeypatch.setattr(
        post_grafana_annotation,
        "_post_annotation",
        lambda *args, **kwargs: (201, {"id": 123}),
    )
    monkeypatch.setattr(post_grafana_annotation.time, "monotonic", lambda: 0.0)

    slept: list[float] = []
    monkeypatch.setattr(post_grafana_annotation.time, "sleep", slept.append)

    status, result, attempts = post_grafana_annotation._post_annotation_with_retry(
        "http://grafana.local",
        "deploy",
        ["deploy"],
        {"Authorization": "Bearer x"},
        None,
        retry_window_seconds=30,
        retry_initial_delay_seconds=1,
        retry_max_delay_seconds=8,
    )

    assert status == 201
    assert result == {"id": 123}
    assert attempts == 1
    assert slept == []


def test_retry_retries_transient_errors_then_succeeds(monkeypatch) -> None:
    """Retryable failures should backoff and eventually return success."""
    outcomes = iter([
        (503, {"message": "busy"}),
        (429, {"message": "rate limited"}),
        (200, {"id": 42}),
    ])

    monkeypatch.setattr(post_grafana_annotation, "_post_annotation", lambda *args, **kwargs: next(outcomes))
    monkeypatch.setattr(post_grafana_annotation.time, "monotonic", lambda: 0.0)

    slept: list[float] = []
    monkeypatch.setattr(post_grafana_annotation.time, "sleep", slept.append)

    status, result, attempts = post_grafana_annotation._post_annotation_with_retry(
        "http://grafana.local",
        "deploy",
        ["deploy"],
        {"Authorization": "Bearer x"},
        None,
        retry_window_seconds=30,
        retry_initial_delay_seconds=1,
        retry_max_delay_seconds=8,
    )

    assert status == 200
    assert result == {"id": 42}
    assert attempts == 3
    assert slept == [1, 2]


def test_retry_stops_on_non_retryable_status(monkeypatch) -> None:
    """A non-retryable status should fail fast with one attempt."""
    monkeypatch.setattr(
        post_grafana_annotation,
        "_post_annotation",
        lambda *args, **kwargs: (400, {"message": "bad request"}),
    )
    monkeypatch.setattr(post_grafana_annotation.time, "monotonic", lambda: 0.0)

    slept: list[float] = []
    monkeypatch.setattr(post_grafana_annotation.time, "sleep", slept.append)

    status, result, attempts = post_grafana_annotation._post_annotation_with_retry(
        "http://grafana.local",
        "deploy",
        ["deploy"],
        {"Authorization": "Bearer x"},
        None,
        retry_window_seconds=30,
        retry_initial_delay_seconds=1,
        retry_max_delay_seconds=8,
    )

    assert status == 400
    assert result == {"message": "bad request"}
    assert attempts == 1
    assert slept == []


def test_retry_honors_max_delay_cap(monkeypatch) -> None:
    """Exponential backoff should not exceed retry_max_delay_seconds."""
    outcomes = iter([
        (503, {"message": "busy"}),
        (503, {"message": "busy"}),
        (503, {"message": "busy"}),
        (201, {"id": 7}),
    ])

    monkeypatch.setattr(post_grafana_annotation, "_post_annotation", lambda *args, **kwargs: next(outcomes))
    monkeypatch.setattr(post_grafana_annotation.time, "monotonic", lambda: 0.0)

    slept: list[float] = []
    monkeypatch.setattr(post_grafana_annotation.time, "sleep", slept.append)

    status, result, attempts = post_grafana_annotation._post_annotation_with_retry(
        "http://grafana.local",
        "deploy",
        ["deploy"],
        {"Authorization": "Bearer x"},
        None,
        retry_window_seconds=30,
        retry_initial_delay_seconds=1,
        retry_max_delay_seconds=2,
    )

    assert status == 201
    assert result == {"id": 7}
    assert attempts == 4
    assert slept == [1, 2, 2]


def test_main_rejects_negative_retry_window(monkeypatch) -> None:
    """CLI should reject invalid negative retry values with argparse exit 2."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "post_grafana_annotation.py",
            "--text",
            "deploy",
            "--token",
            "token",
            "--retry-window-seconds",
            "-1",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        post_grafana_annotation.main()

    assert excinfo.value.code == 2


def test_main_wires_retry_arguments_into_post(monkeypatch) -> None:
    """main() should pass parsed retry CLI args into retry helper."""
    captured: dict[str, object] = {}

    def _fake_post_with_retry(
        base_url: str,
        text: str,
        tags: list[str],
        headers: dict[str, str],
        dashboard_uid: str | None,
        retry_window_seconds: float,
        retry_initial_delay_seconds: float,
        retry_max_delay_seconds: float,
    ) -> tuple[int, dict, int]:
        captured["base_url"] = base_url
        captured["text"] = text
        captured["tags"] = tags
        captured["headers"] = headers
        captured["dashboard_uid"] = dashboard_uid
        captured["retry_window_seconds"] = retry_window_seconds
        captured["retry_initial_delay_seconds"] = retry_initial_delay_seconds
        captured["retry_max_delay_seconds"] = retry_max_delay_seconds
        return 201, {"id": 77}, 2

    monkeypatch.setattr(post_grafana_annotation, "_post_annotation_with_retry", _fake_post_with_retry)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "post_grafana_annotation.py",
            "--text",
            "deploy-1",
            "--tags",
            "deploy",
            "ops",
            "--url",
            "http://grafana.local",
            "--token",
            "token",
            "--dashboard-uid",
            "dash-1",
            "--retry-window-seconds",
            "40",
            "--retry-initial-delay-seconds",
            "2",
            "--retry-max-delay-seconds",
            "10",
        ],
    )

    rc = post_grafana_annotation.main()
    assert rc == 0
    assert captured["base_url"] == "http://grafana.local"
    assert captured["text"] == "deploy-1"
    assert captured["tags"] == ["deploy", "ops"]
    assert captured["dashboard_uid"] == "dash-1"
    assert captured["retry_window_seconds"] == 40.0
    assert captured["retry_initial_delay_seconds"] == 2.0
    assert captured["retry_max_delay_seconds"] == 10.0
