# syntax=docker/dockerfile:1
# fusion-identity — tenant-identity service (multi-stage, distroless-ish runtime)
FROM python:3.12-slim AS builder

WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# fusion-core is an in-tree dependency; copy it in for the editable install.
COPY pyproject.toml ./
COPY fusion_identity ./fusion_identity

RUN pip wheel --no-deps -w /wheels .

FROM python:3.12-slim AS runtime

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FUSION_IDENTITY_HOST=0.0.0.0

# fusion-core wheels must be provided by the build orchestrator (mounted/copied
# into /wheels-core). Install runtime deps + fusion-identity.
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir \
    fastapi>=0.110 uvicorn>=0.29 pydantic>=2.6 asyncpg>=0.29 pyjwt>=2.8 \
    redis>=5 grpcio>=1.62 grpcio-health-checking>=1.62 protobuf>=4.25 \
    prometheus-client>=0.20 \
    /wheels/fusion_identity-*.whl && \
    rm -rf /wheels

EXPOSE 11470 50051
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:11470/health').status==200 else 1)"

# Fail-closed: service refuses to boot without JWT_KEY + SERVICE_TOKEN (env at run time).
CMD ["sh", "-c", "exec python -m fusion_identity.app"]
