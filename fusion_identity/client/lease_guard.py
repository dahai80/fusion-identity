from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fusion_identity.client.identity_client import IdentityClient
from fusion_identity.grpc import identity_pb2 as pb

logger = logging.getLogger(__name__)


class LeaseDenied(Exception):
    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"lease denied code={code}: {message}")


@asynccontextmanager
async def lease_guard(
    client: IdentityClient,
    api_key: str,
    target_module: str,
    target_model: str = "",
    request_id: str = "",
    client_ip: str = "",
) -> AsyncIterator[pb.AuthorizeAndAcquireResponse]:
    resp = await client.authorize_and_acquire(
        api_key=api_key,
        target_module=target_module,
        target_model=target_model,
        request_id=request_id,
        client_ip=client_ip,
    )
    if not resp.is_allowed:
        raise LeaseDenied(resp.error_code, resp.error_message)
    logger.info(
        "lease_guard acquired tenant=%s lease=%s",
        resp.tenant_context.tenant_id,
        resp.lease_id,
    )
    try:
        yield resp
    finally:
        ok = await client.release_lease(
            resp.lease_id, resp.tenant_context.tenant_id, reason="guard_exit"
        )
        logger.debug("lease_guard released lease=%s ok=%s", resp.lease_id, ok)
