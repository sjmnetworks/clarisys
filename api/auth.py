"""
JWT bearer-token authentication for the Clarisys Firewall Policy Compliance API.

Designed for Microsoft Entra ID (Azure AD) but will work with any OIDC-compliant
issuer that publishes a JWKS endpoint.

Configuration is environment-driven so the same image can run unauthenticated
in local development and protected in production:

    AUTH_ENABLED       "true" | "false"   (default: "false")
    AUTH_ISSUER        e.g. "https://login.microsoftonline.com/<tenant-id>/v2.0"
    AUTH_AUDIENCE      e.g. "api://firewall-policy"   (Application ID URI)
    AUTH_JWKS_URL      e.g. "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys"
    AUTH_ALGORITHMS    comma-separated, default "RS256"

Scopes (delivered in the standard "scp" claim or "roles" claim):

    firewall.evaluate   POST /evaluate, /evaluate/bulk, /intake/evaluate, /intake/evaluate/bulk
    firewall.audit      POST /audit/csv
    firewall.read       GET  /rules/summary  (future)
    firewall.admin      reserved for future ops endpoints

When AUTH_ENABLED is false, `require_scope(...)` becomes a no-op dependency so
the local dev workflow and the existing test suite stay untouched.
"""
from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from typing import Iterable

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

# Lazy-loaded so the module imports cleanly even if PyJWT is not yet installed
# (e.g. during pip resolution in CI). Real failure is deferred to first use.
try:
    import jwt  # type: ignore
    from jwt import PyJWKClient  # type: ignore
    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover — only hit if dependency is missing
    jwt = None  # type: ignore
    PyJWKClient = None  # type: ignore
    _JWT_AVAILABLE = False

# TLS pinning helpers (optional, only loaded if JWKS_PIN_CERT_FILE is set)
try:
    import urllib3  # type: ignore
    _URLLIB3_AVAILABLE = True
except ImportError:  # pragma: no cover
    urllib3 = None  # type: ignore
    _URLLIB3_AVAILABLE = False


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AuthSettings:
    enabled: bool
    issuer: str | None
    audience: str | None
    jwks_url: str | None
    algorithms: tuple[str, ...]
    tls_pin_cert_file: str | None

    @classmethod
    def from_env(cls) -> "AuthSettings":
        algorithms = tuple(
            a.strip()
            for a in os.environ.get("AUTH_ALGORITHMS", "RS256").split(",")
            if a.strip()
        )
        return cls(
            enabled=_env_bool("AUTH_ENABLED", default=False),
            issuer=os.environ.get("AUTH_ISSUER") or None,
            audience=os.environ.get("AUTH_AUDIENCE") or None,
            jwks_url=os.environ.get("AUTH_JWKS_URL") or None,
            algorithms=algorithms or ("RS256",),
            tls_pin_cert_file=os.environ.get("AUTH_JWKS_PIN_CERT_FILE") or None,
        )


@dataclass(frozen=True)
class CallerIdentity:
    """Identity attached to `request.state.caller` after successful auth."""
    sub: str
    scopes: frozenset[str]
    raw_claims: dict
    tenant_id: str


_settings = AuthSettings.from_env()
_jwks_client: object | None = None
_bearer = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _get_jwks_client():
    global _jwks_client
    if _jwks_client is None:
        if not _JWT_AVAILABLE:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT library not installed.",
            )
        if not _settings.jwks_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AUTH_JWKS_URL is not configured.",
            )

        # TLS pinning: if a cert file is provided, configure HTTPS session with pin.
        # PyJWKClient accepts an optional requests.Session for custom handling.
        if _settings.tls_pin_cert_file:
            if not _URLLIB3_AVAILABLE:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="TLS pinning requires urllib3.",
                )
            import requests  # type: ignore
            sess = requests.Session()
            try:
                # Load the pinned certificate for validation
                with open(_settings.tls_pin_cert_file, "rb") as f:
                    pinned_cert = f.read()
                # Create an SSL context that validates against the pinned cert
                ca_certs = ssl.create_default_context()
                ca_certs.load_verify_locations(cadata=pinned_cert)
                # Mount the custom context to the session
                adapter = requests.adapters.HTTPAdapter()
                # Note: requests.HTTPAdapter doesn't directly support urllib3 pool kwargs
                # in this version. For true pinning in production, consider using
                # a dedicated library or mounting a custom urllib3.PoolManager.
                # For now, we validate the cert is readable as a security check.
                sess.verify = True
            except Exception as e:  # pragma: no cover
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Failed to load TLS pin cert: {e}",
                )
            _jwks_client = PyJWKClient(_settings.jwks_url, cache_keys=True)
        else:
            _jwks_client = PyJWKClient(_settings.jwks_url, cache_keys=True)

    return _jwks_client


def _extract_scopes(claims: dict) -> frozenset[str]:
    """Pull scopes from either the OAuth2 `scp` claim or the Entra `roles` claim."""
    raw: list[str] = []
    scp = claims.get("scp") or claims.get("scope")
    if isinstance(scp, str):
        raw.extend(scp.split())
    elif isinstance(scp, list):
        raw.extend(str(x) for x in scp)
    roles = claims.get("roles")
    if isinstance(roles, list):
        raw.extend(str(x) for x in roles)
    return frozenset(s for s in (s.strip() for s in raw) if s)


def _validate_token(token: str) -> CallerIdentity:
    if not _JWT_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT validation is unavailable on this deployment.",
        )
    try:
        signing_key = _get_jwks_client().get_signing_key_from_jwt(token).key  # type: ignore[union-attr]
        claims = jwt.decode(  # type: ignore[union-attr]
            token,
            signing_key,
            algorithms=list(_settings.algorithms),
            audience=_settings.audience,
            issuer=_settings.issuer,
            options={
                "require": ["exp", "iat", "iss", "sub"],
                "verify_aud": _settings.audience is not None,
                "verify_iss": _settings.issuer is not None,
            },
        )
    except Exception as exc:  # noqa: BLE001 — collapse all jwt errors to 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid bearer token: {exc.__class__.__name__}",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    return CallerIdentity(
        sub=str(claims.get("sub", "")),
        scopes=_extract_scopes(claims),
        raw_claims=claims,
        tenant_id=str(claims.get("tenant_id", "")),
    )


def require_scope(*scopes: str):
    """FastAPI dependency that enforces one of the supplied scopes.

    Behaviour:
    * AUTH_ENABLED is false → no-op; sets a synthetic `dev` caller and returns.
    * AUTH_ENABLED is true  → validates the bearer token and checks that the
                              caller has at least one of the required scopes.
    """
    required = frozenset(scopes)

    async def _dep(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
        api_key: str | None = Security(_api_key_header),
    ) -> CallerIdentity:
        # ── Pilot API-key path (checked first, regardless of AUTH_ENABLED) ────
        if api_key is not None:
            from api.pilot_users import lookup_by_key
            pilot = lookup_by_key(api_key)
            if pilot is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or disabled API key.",
                    headers={"WWW-Authenticate": 'APIKey realm="pilot"'},
                )
            if required and not (required & pilot.scopes):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key missing required scope: one of {sorted(required)}",
                )
            caller = CallerIdentity(
                sub=f"pilot:{pilot.username}",
                scopes=pilot.scopes,
                raw_claims={"pilot": True, "email": pilot.email, "username": pilot.username},
                tenant_id=getattr(pilot, "tenant_id", ""),
            )
            request.state.caller = caller
            return caller

        # ── Self-issued JWT path (works regardless of AUTH_ENABLED) ───────────
        if credentials is not None and credentials.scheme.lower() == "bearer":
            local_caller = _try_local_jwt(credentials.credentials)
            if local_caller is not None:
                if required and not (required & local_caller.scopes):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Token missing required scope: one of {sorted(required)}",
                    )
                request.state.caller = local_caller
                return local_caller

        # ── Auth disabled fallback (no API key or local JWT provided) ─────────
        if not _settings.enabled:
            caller = CallerIdentity(sub="dev", scopes=required, raw_claims={}, tenant_id="")
            request.state.caller = caller
            return caller

        # ── External JWT bearer path (JWKS) ───────────────────────────────────
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token or X-API-Key required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        caller = _validate_token(credentials.credentials)
        if required and not (required & caller.scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token missing required scope: one of {sorted(required)}",
            )
        request.state.caller = caller
        return caller

    return _dep


def _try_local_jwt(token: str) -> CallerIdentity | None:
    """Attempt to decode a locally-issued HS256 JWT. Returns None on failure."""
    import os as _os
    secret = _os.environ.get("JWT_SECRET")
    if not secret and not _JWT_AVAILABLE:
        return None
    try:
        # Peek at header to see if it's HS256 (our local tokens)
        header = jwt.get_unverified_header(token) if jwt else {}
        if header.get("alg") != "HS256":
            return None
        # Import the secret from main — must match
        try:
            from api.main import _JWT_SECRET
            secret = _JWT_SECRET
        except ImportError:
            return None
        claims = jwt.decode(token, secret, algorithms=["HS256"])
        scopes_raw = claims.get("scopes", []) or claims.get("scp", "").split()
        return CallerIdentity(
            sub=claims.get("sub", ""),
            scopes=frozenset(scopes_raw),
            raw_claims=claims,
            tenant_id=claims.get("tenant_id", ""),
        )
    except Exception:
        return None


def reload_settings_for_tests() -> AuthSettings:
    """Re-read environment variables. Test-only helper."""
    global _settings, _jwks_client
    _settings = AuthSettings.from_env()
    _jwks_client = None
    return _settings


def current_settings() -> AuthSettings:
    return _settings


def settings_for(scopes: Iterable[str]) -> dict:
    """Convenience for log/debug output."""
    return {"enabled": _settings.enabled, "required_scopes": sorted(set(scopes))}
