from __future__ import annotations

import logging
from typing import Any

from fusion_core.http import create_app
from fusion_core.logging import setup_logging
from fusion_core.tenant import install_tenant_middleware

from fusion_identity.auth import AuthService, bootstrap
from fusion_identity.config import Settings, load_settings
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

TENANT_EXEMPT = frozenset(
    {
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/api/v1/auth/login",
        "/api/v1/auth/verify",
        "/api/v1/auth/refresh",
    }
)


def build_app(settings: Settings, *, store: Any | None = None, run_bootstrap: bool = True) -> Any:
    setup_logging("fusion_identity", level=settings.log_level, json_format=False)
    app = create_app("fusion-identity", version="0.1.0")
    app.state.settings = settings
    app.state.store = store if store is not None else InMemoryStore()
    app.state.auth_service = AuthService(
        app.state.store,
        signing_key=settings.jwt_signing_key,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl=settings.jwt_ttl_seconds,
        refresh_ttl=settings.refresh_ttl_seconds,
    )

    from fusion_identity.routes.api_keys import router as api_keys_router
    from fusion_identity.routes.audit import router as audit_router
    from fusion_identity.routes.auth import router as auth_router
    from fusion_identity.routes.members import router as members_router
    from fusion_identity.routes.quotas import router as quotas_router
    from fusion_identity.routes.tenants import router as tenants_router

    app.include_router(auth_router)
    app.include_router(tenants_router)
    app.include_router(members_router)
    app.include_router(api_keys_router)
    app.include_router(quotas_router)
    app.include_router(audit_router)

    install_tenant_middleware(app, exempt_paths=TENANT_EXEMPT, require_jwt=False)
    logger.info("build_app: tenant-identity service wired, port=%s", settings.port)

    @app.on_event("startup")
    async def _startup() -> None:
        await app.state.store.connect()
        if run_bootstrap:
            try:
                await bootstrap(
                    app.state.store,
                    settings.bootstrap_admin_user,
                    settings.bootstrap_admin_pass,
                )
            except RuntimeError as exc:
                logger.warning("bootstrap skipped: %s", exc)

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await app.state.store.close()

    return app


def main() -> None:
    import uvicorn

    settings = load_settings()
    app = build_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level.lower())


if __name__ == "__main__":
    main()
