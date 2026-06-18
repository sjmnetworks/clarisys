"""
Structured JSON logging for the Clarisys Firewall Policy Compliance API.

Every log line is a single JSON object so it can be ingested directly into
Splunk / Sentinel / CloudWatch without grok parsing. Each request gets a
correlation `request_id` stamped onto every log line emitted while it is in
flight, plus an access-log-style `request.completed` event with verdict
metadata where available.
"""
from __future__ import annotations

import logging
import os
import sys
import time
import uuid
from typing import Any

try:
    import structlog  # type: ignore
    _STRUCTLOG_AVAILABLE = True
except ImportError:  # pragma: no cover — only hit if dependency is missing
    structlog = None  # type: ignore
    _STRUCTLOG_AVAILABLE = False


_CONFIGURED = False


def configure_logging(level: str | None = None) -> None:
    """Configure structlog + stdlib logging to emit single-line JSON."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    log_level_name = (level or os.environ.get("LOG_LEVEL", "INFO")).upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    # stdlib root logger → stdout, no formatter (structlog wraps it)
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setLevel(log_level)
    root.addHandler(handler)
    root.setLevel(log_level)

    if not _STRUCTLOG_AVAILABLE:
        # Fall back to a basic formatter; the API still works, just less rich.
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        _CONFIGURED = True
        return

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    _CONFIGURED = True


def get_logger(name: str = "api"):
    if not _CONFIGURED:
        configure_logging()
    if _STRUCTLOG_AVAILABLE:
        return structlog.get_logger(name)
    return logging.getLogger(name)


def new_request_id() -> str:
    request_id = uuid.uuid4().hex
    # Mark test requests so they can be filtered in Grafana dashboard queries.
    if os.environ.get("TESTING", "false").lower() == "true":
        request_id = f"test-{request_id}"
    return request_id


def bind_request_context(**kwargs: Any) -> None:
    """Attach context variables to every log line within this request."""
    if _STRUCTLOG_AVAILABLE:
        structlog.contextvars.bind_contextvars(**kwargs)


def clear_request_context() -> None:
    if _STRUCTLOG_AVAILABLE:
        structlog.contextvars.clear_contextvars()


class RequestTimer:
    """Tiny helper so middleware can measure request latency consistently."""

    __slots__ = ("started",)

    def __init__(self) -> None:
        self.started = time.perf_counter()

    def elapsed_ms(self) -> int:
        return int((time.perf_counter() - self.started) * 1000)
