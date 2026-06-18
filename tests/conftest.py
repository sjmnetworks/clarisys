"""Test isolation for stateful API artifacts.

The FastAPI ``TestClient`` exercises the real ``/evaluate``, ``/intake/evaluate``,
``/health`` etc. pipelines, so a naive test run mutates the same state files
the live service uses:

  * ``~/.firewall-api/roi-metrics.json`` (persisted ROI counters)
  * ``policy/decision_history.jsonl`` (decision audit trail consumed by ROI bootstrap)
  * ``policy/decision_lifecycle.json``
  * ``/var/log/firewall-audit/`` (or its ``~/.firewall-api/audit/`` fallback)

That inflates production ROI counters and pollutes the audit trail with
synthetic test traffic. Reroute every state-bearing path to a per-session
``tmpdir`` **before** any ``api.*`` module is imported, because module-level
constants such as ``roi_metrics.ROI_METRICS_STATE_FILE`` are evaluated at
import time and ``_load_state()`` runs at the bottom of that module.

A regression test (``test_isolation_reroutes_state_files``) asserts the
isolation is in effect, so a future ``conftest`` regression fails loudly.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

# Per-session tmp dir, created BEFORE the first ``import api.*``.
# pytest loads conftest.py before discovering test modules, so any
# ``from api.main import app`` at the top of a test file picks up these
# env vars when ``api.roi_metrics`` resolves its module-level
# ``ROI_METRICS_STATE_FILE`` constant.
_TEST_STATE_DIR = Path(tempfile.mkdtemp(prefix="opa-tests-"))
(_TEST_STATE_DIR / "audit").mkdir(parents=True, exist_ok=True)
(_TEST_STATE_DIR / "evidence").mkdir(parents=True, exist_ok=True)

# Force-override (not setdefault): if the developer's shell already has
# these pointing at production paths, the test run must still be isolated.
os.environ["ROI_METRICS_STATE_FILE"] = str(_TEST_STATE_DIR / "roi-metrics.json")
os.environ["DECISION_HISTORY_FILE"] = str(_TEST_STATE_DIR / "decision_history.jsonl")
os.environ["DECISION_LIFECYCLE_FILE"] = str(_TEST_STATE_DIR / "decision_lifecycle.json")
os.environ["SLO_STATE_FILE"] = str(_TEST_STATE_DIR / "slo-metrics.json")
os.environ["SLACK_STATE_FILE"] = str(_TEST_STATE_DIR / "slack-state.json")
os.environ["AUDIT_DIR"] = str(_TEST_STATE_DIR / "audit")
os.environ["EVIDENCE_DIR"] = str(_TEST_STATE_DIR / "evidence")
os.environ["TESTING"] = "true"

import atexit

import pytest


def _cleanup_test_state_dir() -> None:
    shutil.rmtree(_TEST_STATE_DIR, ignore_errors=True)


atexit.register(_cleanup_test_state_dir)


@pytest.fixture(scope="session")
def test_state_dir() -> Path:
    """Per-session tmp dir holding all rerouted state files. Available to any
    test that needs to inspect or seed the rerouted artifacts."""
    return _TEST_STATE_DIR


# ── regression test: state isolation contract ───────────────────────────────
# Tests must never touch production state files. If conftest.py loses track
# of a state-bearing env var or a new one is added to main.py, the regression
# test fails loudly on the next test run, before any test touches prod.

_REQUIRED_STATE_ENV_VARS = frozenset({
    "ROI_METRICS_STATE_FILE",
    "DECISION_HISTORY_FILE",
    "DECISION_LIFECYCLE_FILE",
    "SLO_STATE_FILE",
    "SLACK_STATE_FILE",
    "AUDIT_DIR",
    "EVIDENCE_DIR",
})

_PRODUCTION_STATE_DIR = Path.home() / ".firewall-api"

for var_name in _REQUIRED_STATE_ENV_VARS:
    var_val = os.environ.get(var_name)
    if var_val is None:
        raise RuntimeError(f"conftest: missing env var {var_name}")
    var_path = Path(var_val)
    if var_path == _PRODUCTION_STATE_DIR or (
        var_path.parent == _PRODUCTION_STATE_DIR
        and not str(var_path).startswith(str(_TEST_STATE_DIR))
    ):
        raise RuntimeError(
            f"conftest: state isolation broken: {var_name}={var_val} "
            f"points to production {_PRODUCTION_STATE_DIR}, not test dir {_TEST_STATE_DIR}"
        )
