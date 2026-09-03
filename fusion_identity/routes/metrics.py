from __future__ import annotations

import logging
import platform
import time

from fastapi import APIRouter, Depends, Response

from fusion_identity import metrics_collector as mc
from fusion_identity.deps import get_store
from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])

_START = time.time()


@router.get("/metrics", include_in_schema=False)
async def metrics(
    store: InMemoryStore = Depends(get_store),
) -> Response:
    stats_error = 0
    try:
        s = await store.stats()
    except Exception as exc:
        # P3-2: a swallowed stats() failure left every gauge at 0, which a
        # scraper cannot distinguish from a genuinely empty system. Mark the
        # failure with a dedicated gauge so monitoring can alert on it loudly.
        logger.error("metrics: stats failed: %s", exc, exc_info=True)
        s = {}
        stats_error = 1
    lines = [
        "# HELP fusion_identity_stats_error 1 if store.stats() failed this scrape",
        "# TYPE fusion_identity_stats_error gauge",
        f"fusion_identity_stats_error {stats_error}",
        "# HELP fusion_identity_tenants Total active tenants",
        "# TYPE fusion_identity_tenants gauge",
        f"fusion_identity_tenants {s.get('tenants', 0)}",
        "# HELP fusion_identity_users Total users",
        "# TYPE fusion_identity_users gauge",
        f"fusion_identity_users {s.get('users', 0)}",
        "# HELP fusion_identity_members Total tenant memberships",
        "# TYPE fusion_identity_members gauge",
        f"fusion_identity_members {s.get('members', 0)}",
        "# HELP fusion_identity_api_keys Active API keys",
        "# TYPE fusion_identity_api_keys gauge",
        f"fusion_identity_api_keys {s.get('api_keys', 0)}",
        "# HELP fusion_identity_audit_records Audit log records",
        "# TYPE fusion_identity_audit_records gauge",
        f"fusion_identity_audit_records {s.get('audit_records', 0)}",
        "# HELP fusion_identity_revoked_jtis Revoked JTIs",
        "# TYPE fusion_identity_revoked_jtis gauge",
        f"fusion_identity_revoked_jtis {s.get('revoked_jtis', 0)}",
        "# HELP fusion_identity_active_refresh Active refresh tokens",
        "# TYPE fusion_identity_active_refresh gauge",
        f"fusion_identity_active_refresh {s.get('refresh_tokens', 0)}",
        (
            "# HELP fusion_identity_legacy_scrypt_users "
            "Legacy scrypt accounts (fixed salt, force-reset)"
        ),
        "# TYPE fusion_identity_legacy_scrypt_users gauge",
        f"fusion_identity_legacy_scrypt_users {s.get('legacy_scrypt_users', 0)}",
        "# HELP fusion_identity_uptime_seconds Process uptime",
        "# TYPE fusion_identity_uptime_seconds gauge",
        f"fusion_identity_uptime_seconds {time.time() - _START:.0f}",
        "# HELP fusion_identity_python_info Python version info",
        "# TYPE fusion_identity_python_info gauge",
        f'fusion_identity_python_info{{version="{platform.python_version()}",'
        f'impl="{platform.python_implementation()}"}} 1',
    ]
    try:
        lines.append(mc.render().decode("utf-8"))
    except Exception as exc:
        logger.warning("metrics: prometheus render failed: %s", exc)
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
