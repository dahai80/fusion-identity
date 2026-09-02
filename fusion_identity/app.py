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


async def _build_redis(settings: Settings) -> Any:
    # F13: when redis_url is set the operator intends the quota/concurrency
    # plane to be active. A connection failure must fail-closed (refuse to
    # start) rather than silently degrading to "no concurrency limits, no
    # quota cache". Only an explicitly unset redis_url is a valid opt-out.
    if not settings.redis_url:
        logger.info("build_app: redis disabled (FUSION_IDENTITY_REDIS_URL unset)")
        return None
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await client.ping()
        logger.info("build_app: redis connected url=%s", settings.redis_url)
        return client
    except Exception as exc:
        logger.error("build_app: redis connect failed (%s) — refusing to start", exc)
        raise RuntimeError(
            f"redis connect failed but FUSION_IDENTITY_REDIS_URL is set: {exc}"
        ) from exc


PREFIX_EXEMPT = ("/api/v1/auth/oidc/",)
SCIM_PREFIX = "/scim/v2/"


def _query_param(scope, name: str) -> str | None:
    qs = scope.get("query_string", b"")
    if not qs:
        return None
    from urllib.parse import parse_qs

    params = parse_qs(qs.decode("latin-1"))
    vals = params.get(name)
    return vals[0] if vals else None


class _OidcContextMiddleware:
    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            path = scope.get("path") or ""
            headers = list(scope.get("headers") or [])
            changed = False
            if path.startswith(PREFIX_EXEMPT):
                if not any(k == b"x-tenant-id" for k, _ in headers):
                    headers.append((b"x-tenant-id", b"oidc"))
                    changed = True
            elif path.startswith(SCIM_PREFIX) and not any(k == b"x-tenant-id" for k, _ in headers):
                tid = _query_param(scope, "tenantId")
                if tid:
                    headers.append((b"x-tenant-id", tid.encode("latin-1")))
                    changed = True
            if changed:
                scope["headers"] = headers
        await self._app(scope, receive, send)


class _SecurityHeadersMiddleware:
    # P1-6: attach baseline security response headers to every HTTP response.
    # No X-Content-Type-Options/ nosniff on the HTML /docs routes left a
    # content-sniffing surface; HSTS + X-Frame-Options harden the service
    # regardless of upstream proxy. This is ASGI, not a FastAPI BaseHTTPMiddleware,
    # to avoid the known request-body buffering overhead.
    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        async def _send(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                for name, val in (
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
                    (b"x-xss-protection", b"0"),
                    (b"referrer-policy", b"no-referrer"),
                ):
                    if not any(k.lower() == name for k, _ in headers):
                        headers.append((name, val))
                message = {**message, "headers": headers}
            await send(message)

        await self._app(scope, receive, _send)


TENANT_EXEMPT = frozenset(
    {
        "/health",
        "/ready",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/.well-known/jwks.json",
        "/.well-known/jwks/rotate",
        "/metrics",
        "/api/v1/auth/login",
        "/api/v1/auth/verify",
        "/api/v1/auth/refresh",
        "/api/v1/auth/introspect",
        "/scim/v2/Users",
    }
)


def _build_store(settings: Settings) -> Any:
    url = settings.database_url
    # F14: when use_pgstore=True the operator intends production persistence.
    # A PgStore init failure must refuse to start, not silently fall back to
    # InMemoryStore (which would lose all tenant data on restart and has no
    # consistency across workers). Only use_pgstore=False opts into InMemory.
    if settings.use_pgstore and url:
        from fusion_identity.db import PgStore

        store = PgStore(url, pool_max=settings.db_pool_max)
        logger.info(
            "build_app: store=PgStore url=%s pool_max=%s (production)",
            _safe_url(url),
            settings.db_pool_max,
        )
        return store
    logger.warning("build_app: store=InMemoryStore (NOT for production)")
    return InMemoryStore()


def _build_auth_service(settings: Settings, store: Any) -> AuthService:
    key_ring: Any = None
    if settings.jwt_algorithm == "RS256":
        from fusion_identity.jwks import KeyRing

        key_ring = KeyRing.rs256(
            settings.jwt_private_key_pem,
            public_keys_pem=settings.jwt_public_keys,
            persist_path=settings.jwt_keyring_path,
        )
        logger.info("build_app: KeyRing RS256 kid=%s", key_ring.kid)
    return AuthService(
        store,
        signing_key=settings.jwt_signing_key,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl=settings.jwt_ttl_seconds,
        refresh_ttl=settings.refresh_ttl_seconds,
        key_ring=key_ring,
        kek=settings.kek,
        mfa_enforce_admin=settings.mfa_enforce_admin,
    )


def build_app(settings: Settings, *, store: Any | None = None, run_bootstrap: bool = True) -> Any:
    setup_logging("fusion_identity", level=settings.log_level, json_format=settings.log_json)
    app = create_app("fusion-identity", version="0.1.0")
    app.state.settings = settings
    app.state.store = store if store is not None else _build_store(settings)
    app.state.auth_service = _build_auth_service(settings, app.state.store)
    app.state.redis = None
    app.state.cache = None
    app.state.concurrency = None
    app.state.grpc_server = None

    from fusion_identity.routes.admin import router as admin_router
    from fusion_identity.routes.api_keys import router as api_keys_router
    from fusion_identity.routes.audit import router as audit_router
    from fusion_identity.routes.auth import router as auth_router
    from fusion_identity.routes.health import router as health_router
    from fusion_identity.routes.idps import router as idps_router
    from fusion_identity.routes.jwks import router as jwks_router
    from fusion_identity.routes.members import router as members_router
    from fusion_identity.routes.metrics import router as metrics_router
    from fusion_identity.routes.mfa import router as mfa_router
    from fusion_identity.routes.oidc import router as oidc_router
    from fusion_identity.routes.quotas import router as quotas_router
    from fusion_identity.routes.scim import router as scim_router
    from fusion_identity.routes.tenants import router as tenants_router
    from fusion_identity.routes.usage import router as usage_router

    app.include_router(auth_router)
    app.include_router(health_router)
    app.include_router(tenants_router)
    app.include_router(members_router)
    app.include_router(api_keys_router)
    app.include_router(quotas_router)
    app.include_router(audit_router)
    app.include_router(usage_router)
    app.include_router(metrics_router)
    app.include_router(jwks_router)
    app.include_router(idps_router)
    app.include_router(oidc_router)
    app.include_router(scim_router)
    app.include_router(mfa_router)
    app.include_router(admin_router)

    def _verify_jwt(token: str) -> dict[str, Any] | None:
        try:
            parts = token.split(".")
        except (AttributeError, ValueError):
            return None
        if len(parts) != 3:
            return None
        try:
            from fusion_core.tenant.jwt_utils import decode_jwt_claims

            return decode_jwt_claims(token)
        except Exception as exc:
            logger.debug("tenant middleware: non-jwt bearer skipped: %s", exc)
            return None

    install_tenant_middleware(
        app, exempt_paths=TENANT_EXEMPT, verify_jwt=_verify_jwt, require_jwt=False
    )
    app.add_middleware(_OidcContextMiddleware)
    app.add_middleware(_SecurityHeadersMiddleware)
    logger.info("build_app: tenant-identity service wired, port=%s", settings.port)

    @app.on_event("startup")
    async def _startup() -> None:
        await app.state.store.connect()
        if hasattr(app.state.store, "ensure_schema"):
            await app.state.store.ensure_schema()
        redis = await _build_redis(settings)
        app.state.redis = redis
        if redis is not None:
            from fusion_identity.cache import IdentityCache
            from fusion_identity.concurrency import ConcurrencyManager

            app.state.cache = IdentityCache(redis)
            app.state.concurrency = ConcurrencyManager(redis, settings.lease_ttl_seconds)
            await app.state.cache.init_scripts()
            await app.state.concurrency.init_scripts()
        if run_bootstrap:
            # F15: bootstrap establishes the first admin — a failure must
            # fail-closed (refuse to start), not be swallowed. A silently
            # started service with no admin locks operators out.
            await bootstrap(
                app.state.store,
                settings.bootstrap_admin_user,
                settings.bootstrap_admin_pass,
                settings.bootstrap_tenants,
            )
        if settings.grpc_port > 0 and app.state.concurrency is not None:
            try:
                from fusion_identity.grpc_server import serve as serve_grpc

                app.state.grpc_server = await serve_grpc(
                    app, host=settings.host, port=settings.grpc_port
                )
                logger.info("build_app: grpc listening on %s:%s", settings.host, settings.grpc_port)
            except Exception as exc:
                # P0-2: fail-closed — gRPC is the authorization control plane.
                # A swallowed start failure leaves HTTP healthy (200) while every
                # AuthorizeAndAcquire dead-ends, causing a silent gateway
                # meltdown. Re-raise so the service refuses to come up, consistent
                # with F13 (redis) / F14 (store) fail-closed semantics.
                logger.error("build_app: grpc start failed, aborting startup (%s)", exc)
                raise

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        if app.state.grpc_server is not None:
            try:
                await app.state.grpc_server.stop(grace=2.0)
            except Exception as exc:
                logger.warning("grpc stop: %s", exc)
        if app.state.redis is not None:
            try:
                await app.state.redis.aclose()
            except Exception as exc:
                logger.warning("redis close: %s", exc)
        await app.state.store.close()

    return app


def main() -> None:
    import uvicorn

    settings = load_settings()
    app = build_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level.lower())


def _safe_url(url: str) -> str:
    if "@" in url:
        scheme, rest = url.split("://", 1)
        host = rest.split("@", 1)[1]
        return f"{scheme}://***@{host}"
    return url


if __name__ == "__main__":
    main()
