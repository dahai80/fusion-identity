from __future__ import annotations

import logging

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger(__name__)

registry = CollectorRegistry()

AUTH_REQUESTS = Counter(
    "fusion_identity_auth_requests_total",
    "Total auth (authorize) requests by result",
    ["tenant_id", "target_module", "status_code", "result"],
    registry=registry,
)

RPC_LATENCY = Histogram(
    "fusion_identity_rpc_latency_seconds",
    "gRPC AuthorizeAndAcquire latency",
    ["method"],
    buckets=(0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    registry=registry,
)

TENANT_ACTIVE_CONCURRENCY = Gauge(
    "fusion_identity_tenant_active_concurrency",
    "Active concurrency leases per tenant",
    ["tenant_id"],
    registry=registry,
)

TOKENS_CONSUMED = Counter(
    "fusion_identity_tokens_consumed_total",
    "Tokens consumed per tenant and model",
    ["tenant_id", "model_name", "type"],
    registry=registry,
)

QUOTA_REMAINING = Gauge(
    "fusion_identity_quota_remaining",
    "Remaining daily token quota per tenant",
    ["tenant_id"],
    registry=registry,
)


def record_auth(tenant_id: str, target_module: str, result: str, status_code: int = 200) -> None:
    try:
        AUTH_REQUESTS.labels(
            tenant_id=tenant_id,
            target_module=target_module,
            status_code=str(status_code),
            result=result,
        ).inc()
    except Exception as exc:
        logger.warning("metrics record_auth failed: %s", exc)


def observe_rpc(method: str, seconds: float) -> None:
    try:
        RPC_LATENCY.labels(method=method).observe(seconds)
    except Exception as exc:
        logger.warning("metrics observe_rpc failed: %s", exc)


def set_active_concurrency(tenant_id: str, value: int) -> None:
    try:
        TENANT_ACTIVE_CONCURRENCY.labels(tenant_id=tenant_id).set(value)
    except Exception as exc:
        logger.warning("metrics set_active_concurrency failed: %s", exc)


def record_tokens(tenant_id: str, model: str, tokens: int, usage_type: str = "grpc") -> None:
    try:
        TOKENS_CONSUMED.labels(tenant_id=tenant_id, model_name=model, type=usage_type).inc(tokens)
    except Exception as exc:
        logger.warning("metrics record_tokens failed: %s", exc)


def set_quota_remaining(tenant_id: str, remaining: int) -> None:
    try:
        QUOTA_REMAINING.labels(tenant_id=tenant_id).set(remaining)
    except Exception as exc:
        logger.warning("metrics set_quota_remaining failed: %s", exc)


def render() -> bytes:
    return generate_latest(registry)
