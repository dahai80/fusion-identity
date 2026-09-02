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


class ConfigError(RuntimeError):
    pass


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


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        _logger_src.error("config: required env %s is empty (fail-closed)", name)
        raise ConfigError(f"missing required env {name}")
    return val


def load_settings() -> Settings:
    jwt_signing_key = os.environ.get("FUSION_IDENTITY_JWT_KEY", "").strip()
    if not jwt_signing_key:
        _logger_src.error(
            "config: FUSION_IDENTITY_JWT_KEY unset — service refuses start (fail-closed)"
        )
        raise ConfigError("missing FUSION_IDENTITY_JWT_KEY")
    service_token = os.environ.get("FUSION_IDENTITY_SERVICE_TOKEN", "").strip()
    if not service_token:
        _logger_src.error(
            "config: FUSION_IDENTITY_SERVICE_TOKEN unset — verify endpoint unprotected"
        )
        raise ConfigError("missing FUSION_IDENTITY_SERVICE_TOKEN")
    return Settings(
        host=os.environ.get("FUSION_IDENTITY_HOST", DEFAULT_HOST),
        port=int(os.environ.get("FUSION_IDENTITY_PORT", DEFAULT_PORT)),
        database_url=os.environ.get("FUSION_IDENTITY_DATABASE_URL", DEFAULT_DATABASE_URL),
        use_pgstore=os.environ.get("FUSION_IDENTITY_USE_PGSTORE", "0").strip()
        in ("1", "true", "yes"),
        jwt_signing_key=jwt_signing_key,
        jwt_issuer=os.environ.get("FUSION_IDENTITY_JWT_ISSUER", DEFAULT_JWT_ISSUER),
        jwt_audience=os.environ.get("FUSION_IDENTITY_JWT_AUDIENCE", DEFAULT_JWT_AUDIENCE),
        jwt_ttl_seconds=int(os.environ.get("FUSION_IDENTITY_JWT_TTL", DEFAULT_JWT_TTL_SECONDS)),
        refresh_ttl_seconds=int(
            os.environ.get("FUSION_IDENTITY_REFRESH_TTL", DEFAULT_REFRESH_TTL_SECONDS)
        ),
        service_token=service_token,
        bootstrap_admin_user=os.environ.get("FUSION_BOOTSTRAP_ADMIN_USER") or None,
        bootstrap_admin_pass=os.environ.get("FUSION_BOOTSTRAP_ADMIN_PASS") or None,
        bootstrap_tenants=os.environ.get("FUSION_BOOTSTRAP_TENANTS") or None,
        log_level=os.environ.get("FUSION_IDENTITY_LOG_LEVEL", "INFO"),
        log_json=os.environ.get("FUSION_IDENTITY_LOG_JSON", "0").strip() in ("1", "true", "yes"),
        login_rate_limit=int(
            os.environ.get("FUSION_IDENTITY_LOGIN_RATE_LIMIT", DEFAULT_LOGIN_LIMIT)
        ),
        login_rate_window=int(
            os.environ.get("FUSION_IDENTITY_LOGIN_RATE_WINDOW", DEFAULT_LOGIN_WINDOW)
        ),
        jwt_algorithm=os.environ.get("FUSION_IDENTITY_JWT_ALGORITHM", "HS256").strip().upper(),
        jwt_private_key_pem=os.environ.get("FUSION_IDENTITY_JWT_PRIVATE_KEY_PEM") or None,
        jwt_public_keys=os.environ.get("FUSION_IDENTITY_JWT_PUBLIC_KEYS") or None,
        kek=os.environ.get("FUSION_IDENTITY_KEK", jwt_signing_key),
        mfa_enforce_admin=os.environ.get("FUSION_IDENTITY_MFA_ENFORCE_ADMIN", "0").strip().lower()
        in ("1", "true", "yes"),
        redis_url=os.environ.get("FUSION_IDENTITY_REDIS_URL", ""),
        grpc_port=int(os.environ.get("FUSION_IDENTITY_GRPC_PORT", DEFAULT_GRPC_PORT)),
        lease_ttl_seconds=int(os.environ.get("FUSION_IDENTITY_LEASE_TTL", DEFAULT_LEASE_TTL)),
    )
