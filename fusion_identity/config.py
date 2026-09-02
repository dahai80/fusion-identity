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


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Settings:
    host: str
    port: int
    database_url: str
    jwt_signing_key: str
    jwt_issuer: str
    jwt_audience: str
    jwt_ttl_seconds: int
    refresh_ttl_seconds: int
    service_token: str
    bootstrap_admin_user: str | None
    bootstrap_admin_pass: str | None
    log_level: str


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
        log_level=os.environ.get("FUSION_IDENTITY_LOG_LEVEL", "INFO"),
    )
