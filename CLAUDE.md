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

Bootstrap runs only when the tenant table is empty. On an **empty** table with `FUSION_BOOTSTRAP_ADMIN_USER`/`PASS` unset, startup **refuses to start** (fail-closed — a fresh install must be seeded with a first admin; the service will not come up un-administerable). Bootstrap is a no-op when the table is **non-empty** (the operator pre-seeded the first admin out-of-band, e.g. via `psql`), so the service starts without those vars in that case.

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
pytest tests/ -m integration -v        # needs live Postgres fusion_identity (apply deploy/sql/schema.sql first)
ruff check . && ruff format --check .  # line-length 100, rules: E F W I UP B SIM; B008 ignored in routes/ and deps.py
```

Tests use Starlette `TestClient` against `build_app(store=InMemoryStore(), run_bootstrap=True)`. Fixtures in `tests/conftest.py` build a settings/store/app/client stack and expose `admin_token` (logs in `admin:adminpass` against the bootstrapped `default` tenant). Integration tests hit a real `fusion_identity` DB (issue #26: single canonical DB, legacy `fusion_tenant` retired) — mark them `@pytest.mark.integration`.

## Architecture

### App wiring (`app.py`)

`build_app(settings, store=None, run_bootstrap=True)` → FastAPI app via `fusion_core.http.create_app`. State held on `app.state`:
- `settings` — `Settings` (frozen dataclass from `config.load_settings()`, reads env, raises `ConfigError` on missing required vars). Includes `redis_url`, `grpc_port`, `lease_ttl_seconds`.
- `store` — `InMemoryStore` (default) or a `PgStore` injected by the operator
- `auth_service` — `AuthService(store, signing_key, issuer, audience, ttl, refresh_ttl)`
- `redis` / `cache` / `concurrency` / `grpc_server` — all `None` unless `redis_url` set; built on startup

Routers included: `auth`, `tenants`, `members`, `api_keys`, `quotas`, `audit`, `usage`, `metrics`, `jwks`, `idps`, `oidc`, `scim`, `mfa`, `admin`, `registration`, `join`. Tenant middleware installed from `fusion_core.tenant` with `TENANT_EXEMPT` paths (health/docs/login/verify/refresh/register/register-tenant/verify-email — exact-match only). Startup order: connect store → ensure_schema → build Redis → init cache+concurrency scripts → bootstrap → start gRPC (only if `grpc_port>0` AND concurrency present). Shutdown: grpc.stop → redis.aclose → store.close.

Note: `build_app` defaults to `InMemoryStore` — production must inject a `PgStore`. The DDL in `deploy/sql/schema.sql` is applied by operator/CI; `PgStore.ensure_schema` only warns. The gRPC/cache/concurrency plane is **disabled** unless `FUSION_IDENTITY_REDIS_URL` is set.

### Store layer (`store.py`, `db.py`)

Two interchangeable backends sharing a `StoreProto` (declared in `auth.py`):
- **`InMemoryStore`** — dicts in memory, seeds 4 roles from `ROLES_SEED`, creates default quota on tenant create. Used by all offline tests.
- **`PgStore`** — asyncpg connection pool, generic `fetchrow/fetch/fetchval/execute`.

Domain logic lives on the store (CRUD for tenants/users/members/api_keys/quotas/audit, jti revocation, email verification: `set_email_verify_token` / `verify_email_token` — migration `0017_email_verification.sql` adds `users.email_verified` (default TRUE for pre-existing users) + `email_verify_token_hash` / `email_verify_expires`). Routes are thin. `StoreConflict` = 409. Audit is append-only + hash-chained (`_chain_hash` links each record to the previous `chain_hash`, genesis = `"genesis"`).

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

- `auth` (`/api/v1/auth`): login (no auth), verify GET+POST (service token), refresh (no auth), revoke (tenant_admin), DELETE `/sessions` (service token, issue #29 — user-deletion flow revokes all access/session jtis + refresh families for `{sub, tenant_id}`, returns counts, 404 unknown tenant, audited). Issue #39: login 403-blocks email-unverified users ("email not verified — check your inbox for the verification link"); `AuthService.login(..., skip_email_verification=True)` is the internal-only bypass used by register-tenant for its single at-signup issuance. Issue #47: `LoginRequest.tenant_id` is optional — omitted tenant is resolved post-password via `memberships_for_user` (both stores): single active membership → that tenant, multiple → 409 `{error:"tenant_ambiguous",tenants:[{tenant_id,display_name}]}` (never pre-password — membership-listing leak), none → `invalid credentials`; explicit tenant still wins; wrong-tenant login is 401 `tenant_mismatch`. `_record_failed_login` skips tenant audit when tenant-less (audit_log.tenant_id NOT NULL) but still counts lockout attempts.
- `registration` (`/api/v1/auth/register*`, issue #39): public self-service signup (design `architecture/fusion-site-auth-1104.md`). `POST /register` — personal signup: create_user + auto-join `FUSION_IDENTITY_REGISTRATION_DEFAULT_TENANT` (default `community`, auto-created with the free plan template + `join_policy="open"` on first signup), role `member`; verification on → email required (422) + `{status:"verification_required"}` + login 403 until `/verify-email`; off → immediate token pair. `POST /register-tenant` — wraps `provision_core` (zero duplicated tenant-creation logic), `Idempotency-Key` replay supported, admin password never echoed, immediate token pair via the skip flag. `POST /verify-email` — single-use expiring redemption (sha256 at rest, lookup by hash, columns cleared on success, uniform 400). `POST /verify-email/resend` — PUBLIC by design (unverified users hold no bearer; bearer-gating would deadlock), uniform `{resent}` (no enumeration). Verification tokens: `secrets.token_urlsafe(32)`, TTL `email_verify_ttl_seconds`; SMTP unset → token WARNING-logged with the `token=` link line (dev fallback), delivery failures never fail signup. Audited to `_system` with `role="public"`: `auth.registered` / `auth.tenant_registered` / `auth.email_verified`.
- `join` (issue #40): the join-policy plane. Every tenant has admin-settable `join_policy` (`invite` default; `JOIN_POLICIES` frozenset in store.py; exposed on tenant create/PATCH, admin create/PUT, `ProvisionRequest.join_policy`; the auto-created `community` uses `open`). `invite` — `POST /api/v1/tenants/{tid}/invites` mints a single-use expiring `finv_` token (role pre-assigned, sha256 at rest, raw returned exactly once) + GET inventory (hashes never leave the store) + `POST /api/v1/auth/invites/redeem` (bearer; atomic single-use via `used_at IS NULL` WHERE clause; uniform 400). `open` — `POST /api/v1/auth/tenants/{tid}/join` (role FORCED `member`, 403 on non-open policy). `approval` — `POST /api/v1/tenants/{tid}/join-requests` submit (403 non-approval policy, 409 duplicate pending, re-apply after reject) + GET list + `approve`/`reject` (only pending decidable; approve grants membership role `member`). All rate-limited via `check_login_rate` pseudo keys; audited to the target tenant: `member.invited` / `member.joined` / `member.self_added` / `join.requested` / `join.approved` / `join.rejected`. Migration `0018_join_policy.sql`. Gotcha: PgStore returns TIMESTAMPTZ datetimes where InMemory returns epoch floats (`_invite_expired` in routes/join.py normalizes).
- `tenants` (`/api/v1/tenants`): list/create/get/patch/delete — `require_tenant_admin`.
- `members` (`/api/v1/tenants/{tenant_id}/members`): list, add-or-create, delete — `require_tenant_admin_of`.
- `api_keys` (`/api/v1/tenants/{tenant_id}/api-keys`): list/create/revoke — `require_tenant_admin_of`.
- `quotas` (`/api/v1/tenants/{tenant_id}/quotas`): get/PUT hot-update — `require_tenant_admin_of`.
- `audit` (`/api/v1/tenants/{tenant_id}/audit`): self-query only, limit 1..1000 — `require_tenant_admin_of`.
- `usage` (`/api/v1/tenants/{tenant_id}`): POST `/usage` (service token, emit), GET `/usage` + `/config` + `/export` (tenant_admin).
- `idps` (`/api/v1/tenants/{tenant_id}/idps`): list/create/GET-one/PATCH/delete — `require_tenant_admin_of`. PATCH re-encrypts `client_secret` if provided (`update_idp` store method).
- `oidc` (`/api/v1/auth/oidc/{idp_id}`): login/callback — tenant-middleware-exempt (synthetic `X-Tenant-Id: oidc` injected by `_OidcContextMiddleware`). `_STATES` is a bounded LRU+TTL `OrderedDict` (`_STATES_MAX=1024`, `_STATES_TTL=600`).
- `scim` (`/scim/v2`): `/Users` list/create (exempt) + `/Users/{id}` GET/PATCH/DELETE (non-exempt). `_OidcContextMiddleware` injects `X-Tenant-Id` from the `tenantId` query param for `/scim/v2/` paths so the tenant middleware accepts them. All gated by service token.
- `app_secrets` (`/api/v1/apps/{app_id}/secrets`): issue/list/rotate for business-app key material (issue #28) — `require_service_token`, raw `fms_` secret returned exactly once, sha256 hash at rest, rotation grace window (`FUSION_IDENTITY_SECRET_GRACE_SECONDS`), audit to tenant `_system`.
- `app_credentials` (`/api/v1/apps/{app_id}/credentials/{name}`): PUT/GET externally-issued SaaS credentials (issue #34) — `require_service_token`, AES-256-GCM under the KEK at rest (recoverable, unlike app_secrets' hash), fetch counter for anomaly detection, audit `app_credential.stored`/`fetched` to tenant `_system`.
- `admin` aggregation reads (issue #35, DC-3, for the fusion-security Admin Console): GET `/tenants/{tid}/members/summary` (count-only `{total,active,disabled,locked,by_role}`), GET `/tenants/{tid}/idps/summary` (`{configured,count,types,auto_provision}`, no secrets), GET `/app-secrets` (cross-app inventory, no key material). Plus `DELETE /api/v1/apps/{app_id}/secrets/{version}` — immediate revoke cuts a grace window short (UC-S3), audited `app_secret.revoked`.
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

Postgres DB `fusion_identity` — single canonical DB (issue #26, DB-2; legacy `fusion_tenant` retired). Schema in `deploy/sql/schema.sql` (PRD Appendix A.1, independent of cowork RLS DB); table inventory there is authoritative (27 tables — incl. platform-scope `app_secrets` from issue #28 and `app_credentials` from issue #34; issue #39 adds email-verification columns on `users` via migration `0017`; issue #40 adds `tenants.join_policy` + `tenant_invites` + `join_requests` via migration `0018`). Apply with `psql` before first run. `PgStore.ensure_schema` only warns — DDL is operator/CI responsibility.

## Conventions

- setuptools backend, `[tool.setuptools.packages.find] include = ["fusion_identity*"]`.
- Python ≥3.12. No docstrings (per global rules). 4-space indentation. Always include logging.
- Tests: `asyncio_mode=auto`, `testpaths=["tests"]`, `addopts="-m 'not integration'"`.
