from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# Issue #99 (flywheel Loop A): ops-event emission helpers. Payload hygiene is
# a hard rule — hashed user/tenant ids ONLY, never raw emails, usernames,
# JWTs, or token material (the acceptance test greps emitted payloads for
# those). Every helper is a no-op when the emitter is absent (ops plane off).

_UID_PREFIX = "u:"
_TID_PREFIX = "t:"


def hash_user_id(user_id: str) -> str:
    return _UID_PREFIX + hashlib.sha256(f"identity:{user_id}".encode()).hexdigest()[:16]


def hash_tenant_id(tenant_id: str) -> str:
    return _TID_PREFIX + hashlib.sha256(f"identity:{tenant_id}".encode()).hexdigest()[:16]


def get_emitter(app_state: Any) -> Any:
    return getattr(app_state, "ops_emitter", None)


def claims_from_token(token: str) -> dict:
    # Unverified local decode — telemetry only (values are hashed before they
    # ever leave the process), never an auth decision.
    try:
        import jwt

        claims = jwt.decode(token, options={"verify_signature": False})
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def sub_from_token(token: str) -> str:
    return str(claims_from_token(token).get("sub", ""))


async def _emit(emitter: Any, event_type: str, tenant_id: str, payload: dict, **extra: Any) -> None:
    if emitter is None:
        return
    event = {
        "event_type": event_type,
        "tenant_hash": hash_tenant_id(tenant_id) if tenant_id else "",
        "payload": payload,
        **extra,
    }
    try:
        accepted = await emitter.emit(event)
        if not accepted:
            logger.debug("ops emit dropped (backpressure): %s", event_type)
    except Exception:
        # Telemetry must never break the auth plane.
        logger.exception("ops emit failed: %s", event_type)


async def emit_login_success(emitter: Any, tenant_id: str, user_id: str, latency_ms: int) -> None:
    await _emit(
        emitter,
        "auth.login.success",
        tenant_id,
        {"user_hash": hash_user_id(user_id)},
        latency_ms=int(latency_ms),
        status=200,
    )


async def emit_login_failure(emitter: Any, tenant_id: str, reason: str, status: int) -> None:
    # No user id on the failure path — login failures must not become an
    # account-existence oracle through the ops database.
    await _emit(emitter, "auth.login.failure", tenant_id, {"reason": reason}, status=int(status))


async def emit_token_issued(emitter: Any, tenant_id: str, user_id: str, kind: str) -> None:
    await _emit(
        emitter,
        "auth.token.issued",
        tenant_id,
        {"user_hash": hash_user_id(user_id), "kind": kind},
        status=200,
    )


async def emit_apikey_usage(emitter: Any, tenant_id: str, tokens: int, target_module: str) -> None:
    await _emit(
        emitter,
        "auth.apikey.usage",
        tenant_id,
        {"tokens": int(tokens), "module": target_module},
    )


async def emit_tenant_stats(emitter: Any, tenants: int, users: int) -> None:
    # Hourly aggregate snapshot (piggybacks on the retention sweep tick).
    await _emit(emitter, "auth.tenant.stats", "", {"tenants": int(tenants), "users": int(users)})


async def emit_data_reflow_optout(emitter: Any, tenant_id: str, user_id: str) -> None:
    # Fired on a true→false setting transition so the ops-side pipeline can
    # purge/anonymize any stored samples for this user per retention policy.
    await _emit(
        emitter,
        "auth.data_reflow.optout",
        tenant_id,
        {"user_hash": hash_user_id(user_id), "ts": time.time()},
    )
