# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`fusion-identity` — the **sole JWT issuer** and **tenant registry** for the Fusion ecosystem. Multi-tenant PRD §3 (tenant models), §4 (tenant context fabric), Appendix A (schema + JWT claims). Sits at the Base Framework layer alongside `fusion-core`; every other Fusion service consumes it, none re-implements it.

Binds **127.0.0.1 only** (PRD C8 — no external exposure; gateway fronts it).

## Environment

```bash
cd /Users/dahai/fusion
source .venv/bin/activate         # REQUIRED — shared monorepo venv, not a local one
pip install -e fusion-identity     # editable install; depends on fusion-core (pip install -e fusion-core first if not present)
```

## Required env (fail-closed — service refuses to start without both)

```bash
export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"        # HS256 signing key
export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"  # gates /verify
export FUSION_BOOTSTRAP_ADMIN_USER=admin
export FUSION_BOOTSTRAP_ADMIN_PASS=adminpass
```

Without bootstrap creds and an empty tenant table, bootstrap is skipped — operator must seed first admin out-of-band.

Full env table (host/port/db/issuer/audience/TTL/refresh/log-level) is in `README.md`.

## Run / lifecycle

```bash
./start.sh start     # nohup fusion-identity → ~/.fusion-identity/identity.log, pid file ~/.fusion-identity/identity.pid
./start.sh stop|restart|status|log [-f]
curl -s http://127.0.0.1:11470/health
```

Entry point: `fusion-identity` console script → `fusion_identity.app:main` → uvicorn.

## Test / lint

```bash
pytest tests/ -v                       # offline, InMemoryStore (default excludes `integration`)
pytest tests/test_auth.py::test_login -v   # single test
pytest tests/ -m integration -v        # needs live Postgres fusion_tenant (apply deploy/sql/schema.sql first)
ruff check . && ruff format --check .  # line-length 100, rules: E F W I UP B SIM; B008 ignored in routes/ and deps.py
```

Tests use Starlette `TestClient` against `build_app(store=InMemoryStore(), run_bootstrap=True)`. Fixtures in `tests/conftest.py` build a settings/store/app/client stack and expose `admin_token` (logs in `admin:adminpass` against the bootstrapped `default` tenant). Integration tests hit a real `fusion_tenant` DB — mark them `@pytest.mark.integration`.

## Architecture

### App wiring (`app.py`)

`build_app(settings, store=None, run_bootstrap=True)` → FastAPI app via `fusion_core.http.create_app`. State held on `app.state`:
- `settings` — `Settings` (frozen dataclass from `config.load_settings()`, reads env, raises `ConfigError` on missing required vars). Includes `redis_url`, `grpc_port`, `lease_ttl_seconds`.
- `store` — `InMemoryStore` (default) or a `PgStore` injected by the operator
- `auth_service` — `AuthService(store, signing_key, issuer, audience, ttl, refresh_ttl)`
- `redis` / `cache` / `concurrency` / `grpc_server` — all `None` unless `redis_url` set; built on startup

Routers included: `auth`, `tenants`, `members`, `api_keys`, `quotas`, `audit`, `usage`, `metrics`, `jwks`, `idps`, `oidc`, `scim`, `mfa`, `admin`. Tenant middleware installed from `fusion_core.tenant` with `TENANT_EXEMPT` paths (health/docs/login/verify/refresh — exact-match only). Startup order: connect store → ensure_schema → build Redis → init cache+concurrency scripts → bootstrap → start gRPC (only if `grpc_port>0` AND concurrency present). Shutdown: grpc.stop → redis.aclose → store.close.

Note: `build_app` defaults to `InMemoryStore` — production must inject a `PgStore`. The DDL in `deploy/sql/schema.sql` is applied by operator/CI; `PgStore.ensure_schema` only warns. The gRPC/cache/concurrency plane is **disabled** unless `FUSION_IDENTITY_REDIS_URL` is set.

### Store layer (`store.py`, `db.py`)

Two interchangeable backends sharing a `StoreProto` (declared in `auth.py`):
- **`InMemoryStore`** — dicts in memory, seeds 4 roles from `ROLES_SEED`, creates default quota on tenant create. Used by all offline tests.
- **`PgStore`** — asyncpg connection pool, generic `fetchrow/fetch/fetchval/execute`.

Domain logic lives on the store (CRUD for tenants/users/members/api_keys/quotas/audit, jti revocation). Routes are thin. `StoreConflict` = 409. Audit is append-only + hash-chained (`_chain_hash` links each record to the previous `chain_hash`, genesis = `"genesis"`).

Password hashing: scrypt (n=16384, r=8, p=1, fixed salt `"fusion-identity"`) via `scrypt_hash`/`verify_password` (constant-time `hmac.compare_digest`). API keys: `fmu_`-prefixed, SHA-256 hashed at rest, raw returned only on creation.

### Auth (`auth.py`, `jwt_utils.py`)

`AuthService` — login/verify/refresh/revoke + `resolve_bearer_claims` (used by deps).
- JWT HS256. Claims: `sub, tid, tenant, role, scope, iat, iss, aud, jti, type`. `verify_token` requires exp/iat/iss/aud/jti/sub/tid.
- **Role re-verification on every protected call**: token `role` claim is advisory. `verify` and `resolve_bearer_claims` re-fetch role from `tenant_members`; on drift they overwrite the claim's role/scope. Membership gone → 401.
- `bootstrap` — only runs when tenant table empty AND bootstrap creds set; creates `default` tenant + `usr_admin` tenant_admin.

4 unified roles: `tenant_admin` / `operator` / `member` / `viewer`. Scopes derived from `ROLES_SEED[role].permissions` as `{resource}:{action}`.

### Dependency injection (`deps.py`)

- `get_store` / `get_auth_service` / `get_settings` — pull from `request.app.state`.
- `require_bearer` — any valid token.
- `require_tenant_admin` — tenant_admin only; checks `X-Tenant-Id` header matches token `tid`.
- `require_tenant_admin_of(tenant_id_param)` — **cross-tenant guard**: compares token `tid` against BOTH the `X-Tenant-Id` header AND the path `{tenant_id}`. Mismatch → 403. Used by members/api-keys/quotas/audit routes.
- `require_service_token` — `hmac.compare_digest` against `settings.service_token`; gates `/verify`.

### Routes (`routes/*.py`)

All tenant-scoped routes require `Authorization: Bearer <jwt>` + `X-Tenant-Id: <tid>`; token `tid` must match both header and path.

- `auth` (`/api/v1/auth`): login (no auth), verify GET+POST (service token), refresh (no auth), revoke (tenant_admin).
- `tenants` (`/api/v1/tenants`): list/create/get/patch/delete — `require_tenant_admin`.
- `members` (`/api/v1/tenants/{tenant_id}/members`): list, add-or-create, delete — `require_tenant_admin_of`.
- `api_keys` (`/api/v1/tenants/{tenant_id}/api-keys`): list/create/revoke — `require_tenant_admin_of`.
- `quotas` (`/api/v1/tenants/{tenant_id}/quotas`): get/PUT hot-update — `require_tenant_admin_of`.
- `audit` (`/api/v1/tenants/{tenant_id}/audit`): self-query only, limit 1..1000 — `require_tenant_admin_of`.
- `usage` (`/api/v1/tenants/{tenant_id}`): POST `/usage` (service token, emit), GET `/usage` + `/config` + `/export` (tenant_admin).
- `idps` (`/api/v1/tenants/{tenant_id}/idps`): list/create/GET-one/PATCH/delete — `require_tenant_admin_of`. PATCH re-encrypts `client_secret` if provided (`update_idp` store method).
- `oidc` (`/api/v1/auth/oidc/{idp_id}`): login/callback — tenant-middleware-exempt (synthetic `X-Tenant-Id: oidc` injected by `_OidcContextMiddleware`). `_STATES` is a bounded LRU+TTL `OrderedDict` (`_STATES_MAX=1024`, `_STATES_TTL=600`).
- `scim` (`/scim/v2`): `/Users` list/create (exempt) + `/Users/{id}` GET/PATCH/DELETE (non-exempt). `_OidcContextMiddleware` injects `X-Tenant-Id` from the `tenantId` query param for `/scim/v2/` paths so the tenant middleware accepts them. All gated by service token.
- `admin` (`/api/v1/admin`): service-token gated, cross-tenant. GET/POST/PUT `/tenants` (+ quota fields `max_concurrency`→`concurrent`, `daily_token_limit`→`tpm`, `allowed_modules`, `allowed_models`), GET `/tenants/{id}/quota`, POST/DELETE api-keys (`/api-keys` + `/keys` alias), GET `/tenants/{id}/usage/today` (concurrency + token breakdown).

### Models (`models.py`)

Pydantic v2 request/response schemas. No DB models — store layer uses plain dicts. `QuotaUpdate` accepts `allowed_modules` + `default_priority`. `AdminTenantCreate`/`AdminTenantUpdate` map PRD quota fields; `IdpUpdate` for PATCH.

### gRPC / concurrency / cache plane (PRD §3.1)

- **`grpc/identity.proto`** — `fusion.identity.v1.IdentityService` (`AuthorizeAndAcquire` / `ReleaseLease` / `ReportUsage`). Stubs generated via `grpc_tools.protoc`; import fixed to `from fusion_identity.grpc import identity_pb2`. The `grpc/*_pb2*.py` files are ruff-exempt (generated).
- **`grpc_servicer.py`** — `IdentityServiceServicer(store, cache, concurrency)`. Authorize flow: api-key cache lookup → store `get_api_key_by_hash` fallback → tenant active / module+model allowlist → daily quota (`cache.check_daily_quota`) → `concurrency.try_acquire` (Redis Lua atomic) → `TenantContext.priority` (from `default_priority` or tier map). Refuses with `AuthErrorCode` enum labels; refusal HTTP status mapped via `_error_http_status`. Records Prometheus metrics (`metrics_collector`) with `target_module` + `status_code` labels. `ReportUsage` records token usage then computes `remaining_daily_quota` via `cache.remaining_quota` (NOT `record_token_usage`'s returned total — that was BUG #1) using the tenant quota `tpm` limit.
- **`concurrency.py`** — `ConcurrencyManager(redis, lease_ttl)`. `ACQUIRE_LUA`/`RELEASE_LUA` scripts: `incr` with rollback-on-overflow, `set lease:{id} EX ttl`; release is `get→del→decr` (floor 0). Lease id = `{tid}:{uuid hex[:12]}`. `active_count(tid)` for admin usage reporting.
- **`cache.py`** — `IdentityCache(redis)`: api-key→tenant (sha256, ttl 300), tenant cache, daily quota counters (`incrby` + 7d expire, clamps `max(0, limit-used)`). `record_token_usage` returns the new running total; `remaining_quota(tid, limit)` returns `max(0, limit-used)`.
- **`grpc_server.py`** — `serve(app, host, port)` → `grpc.aio.server()` with the servicer + `grpc_health.v1` HealthServicer (SERVING for `""` and the service name).
- **`client/`** — gateway SDK: `IdentityClient` (long-lived channel, 10ms deadline, async release/report, `health()`), `lease_guard` asynccontextmanager (raises `LeaseDenied`), `KV_PREFIX="fusion:identity:"`.
- **`metrics_collector.py`** — prometheus_client `CollectorRegistry` with 5 labeled metrics (auth_requests_total, rpc_latency_seconds, tenant_active_concurrency, tokens_consumed_total, quota_remaining). Exposed via `GET /metrics` alongside the store gauges.

## The three red lines (multi-tenant PRD — do not violate)

1. **Fail-closed** — missing `tenant_id`, invalid/expired token, missing required env, missing membership → 401 / refuse to start. No default-tenant degradation.
2. **Cross-tenant denied** — token `tid` must match both `X-Tenant-Id` header and path `{tenant_id}`. `require_tenant_admin_of()` is the enforcement point. Admin of tenant A cannot read tenant B's members/api-keys/quotas/audit.
3. **Data isolation layering** — strong = Postgres RLS (prod), medium = `tenant_id` column + guards (this service), namespace = key-prefix. Do not mix layers.

## Database

Postgres DB `fusion_tenant`, schema in `deploy/sql/schema.sql` (PRD Appendix A.1, independent of cowork RLS DB). 9 tables. Apply with `psql` before first run. `PgStore.ensure_schema` only warns — DDL is operator/CI responsibility.

## Conventions

- setuptools backend, `[tool.setuptools.packages.find] include = ["fusion_identity*"]`.
- Python ≥3.12. No docstrings (per global rules). 4-space indentation. Always include logging.
- Tests: `asyncio_mode=auto`, `testpaths=["tests"]`, `addopts="-m 'not integration'"`.
