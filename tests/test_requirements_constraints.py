"""Regression tests for security-pinned dependency constraints.

These assertions encode the *reason* a particular minimum version is
pinned in api/requirements.txt. If a future contributor relaxes one of
these, the CI test fails locally before pip-audit can flag it on GitHub.
"""
from __future__ import annotations

from pathlib import Path

REQUIREMENTS = Path(__file__).resolve().parents[1] / "api" / "requirements.txt"


def _read_constraints() -> dict[str, str]:
    """Return {package_name_lower: full_constraint_line} from requirements.txt."""
    out: dict[str, str] = {}
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Strip extras like pyjwt[crypto] for the name lookup, but keep
        # the original line as the value so the assertion error is useful.
        name = line.split(">=")[0].split("==")[0].split("<")[0].split("[")[0].strip().lower()
        out[name] = line
    return out


def test_pyjwt_min_version_blocks_pysec_2026_175_through_179() -> None:
    """PyJWT 2.13.0 is the floor that closes 4 PYSEC advisories from 2026-06."""
    constraints = _read_constraints()
    assert "pyjwt" in constraints, "pyjwt missing from requirements.txt"
    assert ">=2.13.0" in constraints["pyjwt"], (
        f"pyjwt floor must be >=2.13.0 (PYSEC-2026-175/177/178/179); "
        f"got: {constraints['pyjwt']!r}"
    )


def test_starlette_pinned_to_block_pysec_2026_161() -> None:
    """starlette 1.0.0 → 1.0.1 closes PYSEC-2026-161; pinned explicitly
    because fastapi pulls starlette transitively and could resolve to 1.0.0
    on a fresh install if our floor isn't enforced."""
    constraints = _read_constraints()
    assert "starlette" in constraints, "starlette must be pinned for security"
    assert ">=1.0.1" in constraints["starlette"], (
        f"starlette floor must be >=1.0.1 (PYSEC-2026-161); "
        f"got: {constraints['starlette']!r}"
    )


def test_httpx_constraint_is_explicitly_bounded_for_testclient_stability() -> None:
    """Keep httpx on the expected compatibility line until planned httpx2 migration."""
    constraints = _read_constraints()
    assert "httpx" in constraints, "httpx missing from requirements.txt"
    line = constraints["httpx"]
    assert ">=0.27.0" in line, f"httpx floor must remain >=0.27.0; got: {line!r}"
    assert "<1.0.0" in line, f"httpx must keep explicit <1.0.0 upper bound; got: {line!r}"
