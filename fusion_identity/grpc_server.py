from __future__ import annotations

import logging
from typing import Any

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from fusion_identity.grpc import identity_pb2_grpc as pb_grpc
from fusion_identity.grpc_servicer import IdentityServiceServicer

logger = logging.getLogger(__name__)


async def serve(app: Any, *, host: str, port: int) -> grpc.aio.Server:
    server = grpc.aio.server()
    pb_grpc.add_IdentityServiceServicer_to_server(
        IdentityServiceServicer(
            store=app.state.store,
            cache=app.state.cache,
            concurrency=app.state.concurrency,
        ),
        server,
    )
    health_servicer = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    await health_servicer.set(
        "fusion.identity.v1.IdentityService", health_pb2.HealthCheckResponse.SERVING
    )
    await health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    bound = server.add_insecure_port(f"{host}:{port}")
    await server.start()
    logger.info("grpc server started host=%s bound=%s", host, bound)
    return server
