"""Regression: bench scripts must default to self-host isolation.

If anyone changes the default to point at a live URL, this fails fast,
because that's how prod ROI gauges and decision history get poisoned.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_SCRIPTS = [
    REPO_ROOT / "test-payloads" / "perf_test_stream.py",
    REPO_ROOT / "test-payloads" / "perf_test.py",
]


@pytest.mark.parametrize("script", BENCH_SCRIPTS, ids=lambda p: p.name)
def test_bench_default_url_is_none_so_self_host_is_default(script: Path) -> None:
    """Both bench scripts must have `default=None` for the URL/target arg.

    A non-None default would make `python perf_test.py` (no flags) hit a
    real running API and pollute its ROI metrics and audit trail. The
    self-host spawn path is gated on the URL arg being None, so this is
    the load-bearing invariant.
    """
    src = script.read_text(encoding="utf-8")
    # Match either --url or --target-existing followed (eventually) by a default=
    # in the same add_argument call.
    pattern = re.compile(
        r"add_argument\(\s*\"--(?:url|target-existing)\"[^)]*?default\s*=\s*([^,\)\s]+)",
        re.DOTALL,
    )
    matches = pattern.findall(src)
    assert matches, f"{script.name}: could not find --url/--target-existing default"
    for default_value in matches:
        assert default_value == "None", (
            f"{script.name}: bench URL default must be None (got {default_value!r}). "
            "A non-None default makes the script silently hit a live API and pollute its state."
        )


@pytest.mark.parametrize("script", BENCH_SCRIPTS, ids=lambda p: p.name)
def test_bench_redirects_all_state_env_vars(script: Path) -> None:
    """The isolated spawn must redirect every state-bearing env var.

    If any of these are missing, that bit of state leaks into the prod
    paths (e.g. ~/.firewall-api/ or /var/log/firewall-audit). Names match
    the env-var lookups in api/main.py, api/decision_history.py, and
    api/audit_store.py.
    """
    required = {
        "FIREWALL_API_STATE_DIR",
        "ROI_METRICS_STATE_FILE",
        "DECISION_HISTORY_FILE",
        "DECISION_LIFECYCLE_FILE",
        "SLO_STATE_FILE",
        "AUDIT_DIR",
    }
    src = script.read_text(encoding="utf-8")
    missing = [name for name in required if name not in src]
    assert not missing, (
        f"{script.name}: isolated spawn does not override these env vars: {missing}. "
        "That state will leak into the prod paths."
    )
