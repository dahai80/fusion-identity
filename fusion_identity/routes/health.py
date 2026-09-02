from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/ready", include_in_schema=False)
async def ready(request: Request) -> JSONResponse:
    # P1-3: /health (from fusion_core) is a static 200 that probes nothing, so a
    # broken DB/Redis/gRPC still looks live to orchestrators. /ready is a real
    # readiness check: probe the store + redis. A failing dependency returns 503
    # so the orchestrator stops routing traffic. Liveness (/health) stays as-is
    # (process-alive only) — a dead process should be restarted, a dead
    # dependency should not receive traffic.
    checks: dict[str, Any] = {}
    healthy = True
    store = getattr(request.app.state, "store", None)
    if store is not None:
        try:
            if hasattr(store, "stats"):
                await store.stats()
            checks["store"] = "ok"
        except Exception as exc:
            healthy = False
            checks["store"] = f"fail: {exc}"
            logger.warning("ready: store probe failed: %s", exc)
    else:
        healthy = False
        checks["store"] = "missing"
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        try:
            await redis.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            healthy = False
            checks["redis"] = f"fail: {exc}"
            logger.warning("ready: redis probe failed: %s", exc)
    else:
        # redis is optional (disabled unless FUSION_IDENTITY_REDIS_URL set) —
        # its absence is not a readiness failure, only noted.
        checks["redis"] = "disabled"
    status_code = 200 if healthy else 503
    logger.info("ready: healthy=%s checks=%s", healthy, checks)
    return JSONResponse(
        status_code=status_code,
        content={"status": "ready" if healthy else "unready", "checks": checks},
    )
