from __future__ import annotations

import hmac
import logging

import grpc

logger = logging.getLogger(__name__)

SERVICE_TOKEN_METADATA_KEY = "x-fusion-service-token"


class ServiceTokenInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, service_token: str) -> None:
        if not service_token:
            raise ValueError("service_token must be non-empty (fail-closed)")
        self._service_token = service_token

    async def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata or ())
        supplied = metadata.get(SERVICE_TOKEN_METADATA_KEY, "")
        if not supplied or not hmac.compare_digest(supplied, self._service_token):
            logger.warning(
                "grpc: reject rpc method=%s missing/invalid service token",
                handler_call_details.method,
            )

            async def _deny(_request, context):
                await context.abort(
                    grpc.StatusCode.UNAUTHENTICATED, "missing or invalid service token"
                )

            return grpc.unary_unary_rpc_method_handler(_deny)
        return await continuation(handler_call_details)
