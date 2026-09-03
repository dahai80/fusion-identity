from __future__ import annotations

import os
from dataclasses import dataclass

_logger_src = __import__("logging").getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 11470
DEFAULT_JWT_ISSUER = "fusion-identity"
DEFAULT_JWT_AUDIENCE = "fusion-cluster"
DEFAULT_JWT_TTL_SECONDS = 8 * 3600
DEFAULT_REFRESH_TTL_SECONDS = 7 * 24 * 3600
DEFAULT_DATABASE_URL = "postgresql://127.0.0.1:5432/fusion_tenant"
DEFAULT_LOGIN_LIMIT = 10
DEFAULT_LOGIN_WINDOW = 60
DEFAULT_REDIS_URL = "redis://127.0.0.1:6379/0"
DEFAULT_GRPC_PORT = 50051
DEFAULT_LEASE_TTL = 120
DEFAULT_DB_POOL_MAX = 8


class ConfigError(RuntimeError):
    pass


_MIN_KEY_LEN = 32
_MIN_TOKEN_LEN = 24
_KNOWN_JWT_ALGORITHMS = {"HS256", "RS256"}


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        _logger_src.error("config: required env %s is empty (fail-closed)", name)
        raise ConfigError(f"missing required env {name}")
    return val


def _int_env(name: str, default: int) -> int:
    # M8: bare int(env) raises ValueError; wrap to ConfigError so fail-closed
    # callers that only catch ConfigError still abort startup.
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        _logger_src.error("config: %s=%r is not an integer", name, raw)
        raise ConfigError(f"invalid int for {name}: {raw!r}") from exc


@dataclass(frozen=True, slots=True)
class Settings:
    host: str
    port: int
    database_url: str
    use_pgstore: bool
    jwt_signing_key: str
    jwt_issuer: str
    jwt_audience: str
    jwt_ttl_seconds: int
    refresh_ttl_seconds: int
    service_token: str
    bootstrap_admin_user: str | None
    bootstrap_admin_pass: str | None
    bootstrap_tenants: str | None
    log_level: str
    log_json: bool
    login_rate_limit: int
    login_rate_window: int
    jwt_algorithm: str
    jwt_private_key_pem: str | None
    jwt_public_keys: str | None
    kek: str
    mfa_enforce_admin: bool
    redis_url: str
    grpc_port: int
    lease_ttl_seconds: int
    trusted_proxies: frozenset[str]
    jwt_keyring_path: str
    db_pool_max: int


def load_settings() -> Settings:
    jwt_signing_key = os.environ.get("FUSION_IDENTITY_JWT_KEY", "").strip()
    if not jwt_signing_key:
        _logger_src.error(
            "config: FUSION_IDENTITY_JWT_KEY unset — service refuses start (fail-closed)"
        )
        raise ConfigError("missing FUSION_IDENTITY_JWT_KEY")
    # F9: reject weak signing keys — fail-closed, not just non-empty.
    if len(jwt_signing_key) < _MIN_KEY_LEN:
        _logger_src.error(
            "config: FUSION_IDENTITY_JWT_KEY too short (need >=%d bytes, fail-closed)",
            _MIN_KEY_LEN,
        )
        raise ConfigError(f"FUSION_IDENTITY_JWT_KEY must be at least {_MIN_KEY_LEN} bytes")
    service_token = os.environ.get("FUSION_IDENTITY_SERVICE_TOKEN", "").strip()
    if not service_token:
        _logger_src.error(
            "config: FUSION_IDENTITY_SERVICE_TOKEN unset — verify endpoint unprotected"
        )
        raise ConfigError("missing FUSION_IDENTITY_SERVICE_TOKEN")
    # F9: reject weak service tokens.
    if len(service_token) < _MIN_TOKEN_LEN:
        _logger_src.error(
            "config: FUSION_IDENTITY_SERVICE_TOKEN too short (need >=%d bytes, fail-closed)",
            _MIN_TOKEN_LEN,
        )
        raise ConfigError(f"FUSION_IDENTITY_SERVICE_TOKEN must be at least {_MIN_TOKEN_LEN} bytes")
    # M8: jwt_algorithm must be a known value; reject typos like "HS25".
    jwt_algorithm = os.environ.get("FUSION_IDENTITY_JWT_ALGORITHM", "HS256").strip().upper()
    if jwt_algorithm not in _KNOWN_JWT_ALGORITHMS:
        _logger_src.error("config: FUSION_IDENTITY_JWT_ALGORITHM=%r not supported", jwt_algorithm)
        raise ConfigError(f"unsupported jwt_algorithm: {jwt_algorithm!r}")
    # F16: KEK must be explicitly set and must NOT equal the JWT signing key —
    # key isolation so rotating one does not silently break MFA/IdP secrets.
    kek = os.environ.get("FUSION_IDENTITY_KEK", "").strip()
    if not kek:
        _logger_src.error(
            "config: FUSION_IDENTITY_KEK unset — KEK must not reuse JWT key (fail-closed)"
        )
        raise ConfigError("missing FUSION_IDENTITY_KEK (must not reuse JWT signing key)")
    if kek == jwt_signing_key:
        _logger_src.error(
            "config: FUSION_IDENTITY_KEK equals JWT signing key — key isolation required"
        )
        raise ConfigError("FUSION_IDENTITY_KEK must differ from the JWT signing key")
    bootstrap_admin_pass = os.environ.get("FUSION_BOOTSTRAP_ADMIN_PASS") or None
    bootstrap_admin_user = os.environ.get("FUSION_BOOTSTRAP_ADMIN_USER") or None
    # C1: reject weak bootstrap admin passwords — fail-closed. The first admin
    # is the only seed for a fresh tenant table; a brute-forceable default like
    # "adminpass" defeats fail-closed before any app-layer guard runs. Require
    # >= 12 chars when set. Allow unset only because an empty tenant table with
    # no creds skips bootstrap (operator seeds out-of-band), but when the
    # operator DOES provide a password it must be strong.
    _MIN_BOOTSTRAP_PASS_LEN = 12
    if bootstrap_admin_pass is not None and len(bootstrap_admin_pass) < _MIN_BOOTSTRAP_PASS_LEN:
        _logger_src.error(
            "config: FUSION_BOOTSTRAP_ADMIN_PASS too short (need >=%d chars, fail-closed)",
            _MIN_BOOTSTRAP_PASS_LEN,
        )
        raise ConfigError(
            f"FUSION_BOOTSTRAP_ADMIN_PASS must be at least {_MIN_BOOTSTRAP_PASS_LEN} chars"
        )
    return Settings(
        host=os.environ.get("FUSION_IDENTITY_HOST", DEFAULT_HOST),
        port=_int_env("FUSION_IDENTITY_PORT", DEFAULT_PORT),
        database_url=os.environ.get("FUSION_IDENTITY_DATABASE_URL", DEFAULT_DATABASE_URL),
        use_pgstore=os.environ.get("FUSION_IDENTITY_USE_PGSTORE", "0").strip()
        in ("1", "true", "yes"),
        jwt_signing_key=jwt_signing_key,
        jwt_issuer=os.environ.get("FUSION_IDENTITY_JWT_ISSUER", DEFAULT_JWT_ISSUER),
        jwt_audience=os.environ.get("FUSION_IDENTITY_JWT_AUDIENCE", DEFAULT_JWT_AUDIENCE),
        jwt_ttl_seconds=_int_env("FUSION_IDENTITY_JWT_TTL", DEFAULT_JWT_TTL_SECONDS),
        refresh_ttl_seconds=_int_env("FUSION_IDENTITY_REFRESH_TTL", DEFAULT_REFRESH_TTL_SECONDS),
        service_token=service_token,
        bootstrap_admin_user=bootstrap_admin_user,
        bootstrap_admin_pass=bootstrap_admin_pass,
        bootstrap_tenants=os.environ.get("FUSION_BOOTSTRAP_TENANTS") or None,
        log_level=os.environ.get("FUSION_IDENTITY_LOG_LEVEL", "INFO"),
        log_json=os.environ.get("FUSION_IDENTITY_LOG_JSON", "0").strip() in ("1", "true", "yes"),
        login_rate_limit=_int_env("FUSION_IDENTITY_LOGIN_RATE_LIMIT", DEFAULT_LOGIN_LIMIT),
        login_rate_window=_int_env("FUSION_IDENTITY_LOGIN_RATE_WINDOW", DEFAULT_LOGIN_WINDOW),
        jwt_algorithm=jwt_algorithm,
        jwt_private_key_pem=os.environ.get("FUSION_IDENTITY_JWT_PRIVATE_KEY_PEM") or None,
        jwt_public_keys=os.environ.get("FUSION_IDENTITY_JWT_PUBLIC_KEYS") or None,
        kek=kek,
        mfa_enforce_admin=os.environ.get("FUSION_IDENTITY_MFA_ENFORCE_ADMIN", "0").strip().lower()
        in ("1", "true", "yes"),
        redis_url=os.environ.get("FUSION_IDENTITY_REDIS_URL", ""),
        grpc_port=_int_env("FUSION_IDENTITY_GRPC_PORT", DEFAULT_GRPC_PORT),
        lease_ttl_seconds=_int_env("FUSION_IDENTITY_LEASE_TTL", DEFAULT_LEASE_TTL),
        # F8: trusted-proxy whitelist — XFF is only honored when the direct
        # peer is in this set, else the socket peer is used. Default empty so
        # spoofed XFF cannot bypass login rate-limiting.
        trusted_proxies=frozenset(
            p.strip()
            for p in os.environ.get("FUSION_IDENTITY_TRUSTED_PROXIES", "").split(",")
            if p.strip()
        ),
        # P0-1: persistence path for RS256 key rotation. When set, rotate()/prune()
        # atomically write current + retired keys here so a restart recovers the
        # rotated state instead of silently rolling back (which makes all
        # tokens signed by a retired key unverifiable).
        jwt_keyring_path=os.environ.get("FUSION_IDENTITY_JWT_KEYRING_PATH", ""),
        db_pool_max=_int_env("FUSION_IDENTITY_DB_POOL_MAX", DEFAULT_DB_POOL_MAX),
    )
