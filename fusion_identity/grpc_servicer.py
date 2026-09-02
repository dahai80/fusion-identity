from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from fusion_identity import metrics_collector as mc
from fusion_identity.grpc import identity_pb2 as pb
from fusion_identity.grpc import identity_pb2_grpc as pb_grpc

logger = logging.getLogger(__name__)

_DEFAULT_MAX_TOKENS = 4096
_TIER_PRIORITY = {"enterprise": 3, "pro": 2, "standard": 2, "team": 2, "free": 1}


def _priority_from(quota: dict[str, Any] | None, tier: str) -> int:
    if quota and quota.get("default_priority"):
        return int(quota["default_priority"])
    return _TIER_PRIORITY.get(tier, 2)


def _daily_limit_for(quota: dict[str, Any] | None) -> int:
    if not quota:
        return 50000
    return int(quota.get("tpm", 50000) or 50000)


_ERROR_HTTP_STATUS = {
    pb.AuthErrorCode.INVALID_API_KEY: 401,
    pb.AuthErrorCode.TENANT_DISABLED: 403,
    pb.AuthErrorCode.MODULE_UNAUTHORIZED: 403,
    pb.AuthErrorCode.MODEL_UNAUTHORIZED: 403,
    pb.AuthErrorCode.CONCURRENCY_LIMIT_EXCEEDED: 429,
    pb.AuthErrorCode.DAILY_QUOTA_EXCEEDED: 429,
    pb.AuthErrorCode.RATE_LIMIT_EXCEEDED: 429,
}


def _error_http_status(code: int) -> int:
    return _ERROR_HTTP_STATUS.get(code, 401)


def _refuse(code: int, msg: str) -> pb.AuthorizeAndAcquireResponse:
    return pb.AuthorizeAndAcquireResponse(
        is_allowed=False,
        error_code=code,
        error_message=msg,
        lease_id="",
    )


class IdentityServiceServicer(pb_grpc.IdentityServiceServicer):
    def __init__(self, store: Any, cache: Any, concurrency: Any) -> None:
        self._store = store
        self._cache = cache
        self._concurrency = concurrency

    async def AuthorizeAndAcquire(self, request, context):
        start = time.perf_counter()
        try:
            resp = await self._authorize(request, context)
            tid = resp.tenant_context.tenant_id if resp.tenant_context.tenant_id else "unknown"
            result = "allowed" if resp.is_allowed else pb.AuthErrorCode.Name(resp.error_code)
            status_code = 200 if resp.is_allowed else _error_http_status(resp.error_code)
            mc.record_auth(tid, request.target_module or "unknown", result, status_code)
            return resp
        finally:
            cost_ms = (time.perf_counter() - start) * 1000
            mc.observe_rpc("AuthorizeAndAcquire", cost_ms / 1000)
            if cost_ms > 5:
                logger.warning("grpc AuthorizeAndAcquire high latency: %.2fms", cost_ms)
            logger.debug("grpc AuthorizeAndAcquire cost=%.2fms", cost_ms)

    async def _authorize(self, request, context) -> pb.AuthorizeAndAcquireResponse:
        api_key = (request.api_key or "").strip()
        if not api_key:
            return _refuse(pb.AuthErrorCode.INVALID_API_KEY, "empty api key")

        tenant_info = None
        if self._cache is not None:
            tenant_info = await self._cache.get_tenant_by_api_key(api_key)

        if tenant_info is None:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            key_record = await self._store.get_api_key_by_hash(key_hash)
            if not key_record:
                return _refuse(pb.AuthErrorCode.INVALID_API_KEY, "invalid or revoked api key")
            tenant_id = key_record["tenant_id"]
            tenant = await self._store.get_tenant(tenant_id)
            if not tenant:
                return _refuse(pb.AuthErrorCode.INVALID_API_KEY, "tenant missing for key")
            quota = await self._store.get_quota(tenant_id) or {}
            tenant_info = {
                "tenant_id": tenant_id,
                "tenant_name": tenant.get("display_name", tenant_id),
                "tier": tenant.get("plan", "standard"),
                "is_active": tenant.get("status", "active") == "active",
                "allowed_modules": quota.get("allowed_modules", []),
                "allowed_models": quota.get("allowed_models", []),
                "max_concurrency": int(quota.get("concurrent", 2) or 2),
                "daily_token_limit": int(quota.get("tpm", 50000) or 50000),
                "rpm_limit": int(quota.get("rpm", 0) or 0),
                "default_priority": quota.get("default_priority", 0),
            }
            if self._cache is not None:
                await self._cache.set_api_key(api_key, tenant_info, ttl=300)

        if not tenant_info.get("is_active", True):
            return _refuse(pb.AuthErrorCode.TENANT_DISABLED, "tenant disabled")

        tenant_id = tenant_info["tenant_id"]
        allowed_modules = tenant_info.get("allowed_modules") or []
        if (
            allowed_modules
            and request.target_module
            and request.target_module not in allowed_modules
        ):
            return _refuse(
                pb.AuthErrorCode.MODULE_UNAUTHORIZED,
                f"unauthorized module: {request.target_module}",
            )

        allowed_models = tenant_info.get("allowed_models") or []
        if allowed_models and request.target_model and request.target_model not in allowed_models:
            return _refuse(
                pb.AuthErrorCode.MODEL_UNAUTHORIZED,
                f"unauthorized model: {request.target_model}",
            )

        rpm_limit = int(tenant_info.get("rpm_limit", 0) or 0)
        if rpm_limit > 0 and self._cache is not None:
            rpm_ok, rpm_remaining = await self._cache.check_rpm(tenant_id, rpm_limit)
            if not rpm_ok:
                logger.info("grpc authorize refuse rpm tenant=%s limit=%s", tenant_id, rpm_limit)
                return _refuse(
                    pb.AuthErrorCode.RATE_LIMIT_EXCEEDED,
                    f"rpm limit ({rpm_limit}/min) exceeded",
                )

        daily_limit = int(tenant_info.get("daily_token_limit", 50000) or 50000)
        if self._cache is not None:
            quota_ok, remaining = await self._cache.check_daily_quota(tenant_id, daily_limit)
        else:
            quota_ok, remaining = True, daily_limit
        if not quota_ok:
            return _refuse(pb.AuthErrorCode.DAILY_QUOTA_EXCEEDED, "daily token quota exceeded")

        max_concurrency = int(tenant_info.get("max_concurrency", 2) or 2)
        lease_id = await self._concurrency.try_acquire(tenant_id, max_concurrency)
        if not lease_id:
            return _refuse(
                pb.AuthErrorCode.CONCURRENCY_LIMIT_EXCEEDED,
                f"concurrency limit ({max_concurrency}) reached",
            )
        await self._store.log_lease(tenant_id, lease_id, "acquire", "grpc_authorize")
        active = await self._concurrency.active_count(tenant_id)
        mc.set_active_concurrency(tenant_id, active)

        priority = _priority_from(
            {"default_priority": tenant_info.get("default_priority")},
            tenant_info.get("tier", "standard"),
        )
        max_tokens = min(_DEFAULT_MAX_TOKENS, remaining if remaining > 0 else _DEFAULT_MAX_TOKENS)

        logger.info(
            "grpc authorize pass tenant=%s module=%s lease=%s priority=%s",
            tenant_id,
            request.target_module,
            lease_id,
            priority,
        )
        return pb.AuthorizeAndAcquireResponse(
            is_allowed=True,
            error_code=pb.AuthErrorCode.AUTH_ERROR_CODE_UNSPECIFIED,
            tenant_context=pb.TenantContext(
                tenant_id=tenant_id,
                tenant_name=tenant_info.get("tenant_name", tenant_id),
                tier=tenant_info.get("tier", "standard"),
                priority=priority,
            ),
            lease_id=lease_id,
            max_allowed_tokens=max_tokens,
        )

    async def ReleaseLease(self, request, context):
        ok = await self._concurrency.release(request.lease_id, request.reason or "released")
        if ok:
            await self._store.log_lease(
                request.tenant_id, request.lease_id, "release", request.reason or "released"
            )
            active = await self._concurrency.active_count(request.tenant_id)
            mc.set_active_concurrency(request.tenant_id, active)
        logger.info(
            "grpc release lease=%s tenant=%s reason=%s ok=%s",
            request.lease_id,
            request.tenant_id,
            request.reason,
            ok,
        )
        return pb.ReleaseLeaseResponse(success=ok)

    async def ReportUsage(self, request, context):
        total_tokens = int(request.prompt_tokens) + int(request.completion_tokens)
        if self._cache is not None and total_tokens > 0:
            await self._cache.record_token_usage(request.tenant_id, total_tokens)
        if request.lease_id:
            await self._concurrency.release(request.lease_id, "usage_reported")
            await self._store.log_lease(
                request.tenant_id, request.lease_id, "release", "usage_reported"
            )
            active = await self._concurrency.active_count(request.tenant_id)
            mc.set_active_concurrency(request.tenant_id, active)
        daily_limit = _daily_limit_for(await self._store.get_quota(request.tenant_id))
        remaining = (
            await self._cache.remaining_quota(request.tenant_id, daily_limit)
            if self._cache is not None
            else daily_limit
        )
        if total_tokens > 0:
            mc.record_tokens(
                request.tenant_id, request.model_name or "unknown", total_tokens, "grpc"
            )
        mc.set_quota_remaining(request.tenant_id, remaining)
        try:
            await self._store.record_usage(
                request.tenant_id,
                metric="tokens",
                value=total_tokens,
                source="grpc",
                model=request.model_name or None,
                user_id=None,
            )
        except Exception as exc:
            logger.warning("grpc ReportUsage ledger write failed: %s", exc)
        logger.info(
            "grpc usage tenant=%s model=%s tokens=%s remaining=%s",
            request.tenant_id,
            request.model_name,
            total_tokens,
            remaining,
        )
        return pb.ReportUsageResponse(success=True, remaining_daily_quota=remaining)
