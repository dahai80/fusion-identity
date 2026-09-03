from __future__ import annotations

import logging

import grpc

from fusion_identity.grpc import identity_pb2 as pb
from fusion_identity.grpc import identity_pb2_grpc as pb_grpc

logger = logging.getLogger(__name__)

DEFAULT_DEADLINE_MS = 10
KV_PREFIX = "fusion:identity:"


class IdentityClient:
    def __init__(
        self,
        target: str = "127.0.0.1:50051",
        deadline_ms: int = DEFAULT_DEADLINE_MS,
    ) -> None:
        self._target = target
        self._deadline = deadline_ms / 1000
        self._channel: grpc.aio.Channel | None = None
        self._stub: pb_grpc.IdentityServiceStub | None = None

    async def connect(self) -> None:
        if self._channel is not None:
            return
        self._channel = grpc.aio.insecure_channel(self._target)
        self._stub = pb_grpc.IdentityServiceStub(self._channel)
        logger.info("identity client connected target=%s", self._target)

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()
            self._channel = None
            self._stub = None
            logger.info("identity client closed")

    async def health(self) -> bool:
        from grpc_health.v1 import health_pb2, health_pb2_grpc

        if self._channel is None:
            await self.connect()
        assert self._channel is not None
        stub = health_pb2_grpc.HealthStub(self._channel)
        try:
            resp = await stub.check(
                health_pb2.HealthCheckRequest(service=""),
                timeout=self._deadline,
            )
            return resp.status == health_pb2.HealthCheckResponse.SERVING
        except grpc.aio.AioRpcError as exc:
            logger.warning("identity health check failed: %s", exc)
            return False

    async def authorize_and_acquire(
        self,
        api_key: str,
        target_module: str,
        target_model: str = "",
        request_id: str = "",
        client_ip: str = "",
        tenant_id: str = "",
    ) -> pb.AuthorizeAndAcquireResponse:
        if self._stub is None:
            await self.connect()
        assert self._stub is not None
        # P2-3: optionally assert the tenant the api_key belongs to. The server
        # cross-checks it against the key's real tenant and refuses on mismatch.
        req = pb.AuthorizeAndAcquireRequest(
            api_key=api_key,
            target_module=target_module,
            target_model=target_model,
            request_id=request_id,
            client_ip=client_ip,
            tenant_id=tenant_id,
        )
        try:
            resp = await self._stub.AuthorizeAndAcquire(req, timeout=self._deadline)
            logger.debug(
                "authorize api_key=**%s allowed=%s",
                api_key[-4:],
                resp.is_allowed,
            )
            return resp
        except grpc.aio.AioRpcError as exc:
            logger.warning("authorize_and_acquire rpc failed: %s", exc)
            return pb.AuthorizeAndAcquireResponse(
                is_allowed=False,
                error_code=pb.AuthErrorCode.AUTH_ERROR_CODE_UNSPECIFIED,
                error_message=str(exc),
            )

    async def release_lease(self, lease_id: str, tenant_id: str, reason: str = "done") -> bool:
        if self._stub is None:
            await self.connect()
        assert self._stub is not None
        req = pb.ReleaseLeaseRequest(lease_id=lease_id, tenant_id=tenant_id, reason=reason)
        try:
            resp = await self._stub.ReleaseLease(req, timeout=self._deadline)
            return resp.success
        except grpc.aio.AioRpcError as exc:
            logger.warning("release_lease rpc failed: %s", exc)
            return False

    async def report_usage(
        self,
        lease_id: str,
        tenant_id: str,
        model_name: str,
        prompt_tokens: int,
        completion_tokens: int,
        execution_time_ms: int = 0,
        status: int = 1,
        release_after: bool = False,
    ) -> pb.ReportUsageResponse | None:
        if self._stub is None:
            await self.connect()
        assert self._stub is not None
        req = pb.ReportUsageRequest(
            lease_id=lease_id,
            tenant_id=tenant_id,
            model_name=model_name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            execution_time_ms=execution_time_ms,
            status=status,
            release_after=release_after,
        )
        try:
            return await self._stub.ReportUsage(req, timeout=self._deadline)
        except grpc.aio.AioRpcError as exc:
            logger.warning("report_usage rpc failed: %s", exc)
            return None


_client: IdentityClient | None = None


async def get_client(target: str = "127.0.0.1:50051") -> IdentityClient:
    global _client
    if _client is None:
        _client = IdentityClient(target)
        await _client.connect()
    return _client


async def shutdown_client() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None
