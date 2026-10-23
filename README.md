# fusion-identity

Tenant-identity service for the Fusion ecosystem — the **sole JWT issuer** and **tenant registry** for multi-tenant isolation across all Fusion services.

Implements the multi-tenant PRD §3 (tenant model), §4 (tenant context fabric), and Appendix A (schema + JWT claims). Sits at the **Base Framework layer** alongside `fusion-core`; ecosystem services consume it, never re-implement it.

## Responsibilities

- **JWT issuance** — `HS256` (default) or `RS256` access + refresh tokens. Claims: `sub`, `tid`, `tenant`, `role`, `scope`, `iat`, `exp`, `iss`, `aud`, `jti`. Issuer `fusion-identity`, audience `fusion-cluster`. RS256 mode publishes a JWKS endpoint (`/.well-known/jwks.json`) and supports `kid` rotation with a 24h grace window.
- **Tenant registry** — CRUD tenants (`tenant_id`, `display_name`, `plan`, `status`).
- **Membership + RBAC** — 4 unified roles: `tenant_admin` / `operator` / `member` / `viewer`. Server re-verifies role from `tenant_members` on every protected call (token role claim is advisory, not immutable).
- **Quotas** — per-tenant `rpm` / `tpm` / `concurrent` / `storage_mb` / `allowed_models` / `allowed_modules` / `default_priority`, hot-updatable (no restart).
- **API keys** — per-tenant scoped keys, SHA-256 hashed at rest.
- **Audit log** — append-only, hash-chained, self-query only (admin of tenant A cannot read tenant B's audit).
- **Token verification endpoint** — service-to-service `POST /api/v1/auth/verify`, gated by a shared **service token** (`FUSION_IDENTITY_SERVICE_TOKEN`). Downstream services call this to validate bearer tokens.
- **Usage accounting + tenant export** — `POST /tenants/{id}/usage` (service token) for downstream services to report rpm/tpm/tokens; `GET /usage` (admin) aggregated; `GET /config`, `GET /export` (admin, secrets stripped, audited).
- **Metrics** — `GET /metrics` (Prometheus text format, no auth) exposing tenant/user/member/key/audit/refresh gauges + process uptime.
- **Structured logging** — JSON logs (`FUSION_IDENTITY_LOG_JSON=1`) tag every line with `tenant_id`/`user_id` from the tenant context.

## The three red lines (multi-tenant PRD)

1. **Fail-closed** — missing `tenant_id`, invalid token, or missing required env (`FUSION_IDENTITY_JWT_KEY`, `FUSION_IDENTITY_SERVICE_TOKEN`) → `401` / refuses to start. No default-tenant degradation.
2. **Cross-tenant denied** — a `tenant_admin` of tenant A is blocked (403) from tenant B's members, api-keys, quotas, and audit. Enforced by `require_tenant_admin_of()` comparing token `tid` against both the `X-Tenant-Id` header and the path `{tenant_id}`.
3. **Data isolation layering** — strong = Postgres RLS (prod), medium = `tenant_id` column + guards (this service), namespace = key-prefix. Layers are not mixed.

## Quick start

```bash
cd /Users/dahai/fusion
source .venv/bin/activate
pip install -e fusion-identity

# fail-closed: these env vars are REQUIRED
export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"
export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"
export FUSION_IDENTITY_KEK="$(openssl rand -hex 32)"   # must differ from JWT_KEY
export FUSION_BOOTSTRAP_ADMIN_USER=admin
export FUSION_BOOTSTRAP_ADMIN_PASS=adminpass

./fusion-identity/start.sh start
curl -s http://127.0.0.1:11470/health   # {"status":"ok","service":"fusion-identity",...}
curl -s http://127.0.0.1:11470/ready    # readiness probe: store + redis; 503 on failure
```

Binds **127.0.0.1 only** by default (PRD C8 — no external exposure; traffic reaches it via the gateway).

`/health` is a static liveness check (process alive); `/ready` is a real readiness probe that hits the store and Redis and returns `503` when a dependency is down, so orchestrators stop routing traffic.

## Environment

| Variable | Required | Default | Notes |
|---|---|---|---|
| `FUSION_IDENTITY_JWT_KEY` | **yes** | — | HS256 signing key (>= 32 bytes). Service refuses to start without it. |
| `FUSION_IDENTITY_SERVICE_TOKEN` | **yes** | — | Shared token (>= 24 bytes) gating `/verify` and JWKS rotation. |
| `FUSION_IDENTITY_KEK` | **yes** | — | Key-encryption key for IdP `client_secret` + TOTP secrets (AES-256-GCM, HKDF-SHA256 derived). Must be set explicitly and must differ from `FUSION_IDENTITY_JWT_KEY` (key isolation). |
| `FUSION_IDENTITY_JWT_ALGORITHM` | no | `HS256` | JWT signing algorithm — `HS256` or `RS256`. |
| `FUSION_IDENTITY_JWT_PRIVATE_KEY_PEM` | no | — | RS256 private key PEM (generated at startup if unset). |
| `FUSION_IDENTITY_HOST` | no | `127.0.0.1` | Bind address. |
| `FUSION_IDENTITY_PORT` | no | `11470` | Listen port. |
| `FUSION_IDENTITY_DATABASE_URL` | no | `postgresql://127.0.0.1:5432/fusion_tenant` | Postgres connection. |
| `FUSION_IDENTITY_JWT_ISSUER` | no | `fusion-identity` | JWT `iss` claim. |
| `FUSION_IDENTITY_JWT_AUDIENCE` | no | `fusion-cluster` | JWT `aud` claim. |
| `FUSION_IDENTITY_JWT_TTL` | no | `28800` (8h) | Access token TTL, seconds. |
| `FUSION_IDENTITY_REFRESH_TTL` | no | `604800` (7d) | Refresh token TTL, seconds. |
| `FUSION_BOOTSTRAP_ADMIN_USER` | no | — | Bootstrap `tenant_admin` username. |
| `FUSION_BOOTSTRAP_ADMIN_PASS` | no | — | Bootstrap `tenant_admin` password. **When set, must be >= 12 chars** (fail-closed) — the first admin is the only seed for a fresh tenant table, so a weak default defeats fail-closed. Unset → bootstrap skipped on an empty tenant table (operator seeds out-of-band). |
| `FUSION_BOOTSTRAP_TENANTS` | no | — | JSON array of extra tenants to seed at bootstrap, e.g. `[{"tenant_id":"acme","display_name":"Acme","plan":"team"}]`. |
| `FUSION_IDENTITY_LOG_LEVEL` | no | `INFO` | Log level. |
| `FUSION_IDENTITY_LOG_JSON` | no | `0` | Emit structured JSON logs with `tenant_id`/`user_id` from the tenant context. |
| `FUSION_IDENTITY_LOGIN_RATE_LIMIT` | no | `10` | Max logins per IP per window. `0` = unlimited. |
| `FUSION_IDENTITY_LOGIN_RATE_WINDOW` | no | `60` | Rate-limit window, seconds. |
| `FUSION_IDENTITY_KEK` | **yes** | — | (See required env above.) Key-encryption key for IdP `client_secret` + TOTP secrets (AES-256-GCM). Must not equal the JWT signing key. |
| `FUSION_IDENTITY_MFA_ENFORCE_ADMIN` | no | `0` | When `1`, `tenant_admin` logins are rejected until the admin has an enabled TOTP factor (AAL2 enforcement). |
| `FUSION_IDENTITY_REDIS_URL` | no | — (disabled) | Redis URL for the identity hot cache + concurrency lease store, e.g. `redis://127.0.0.1:6379/0`. When unset, the cache/concurrency/gRPC plane is disabled (REST-only mode). |
| `FUSION_IDENTITY_GRPC_PORT` | no | `0` (disabled) | gRPC `IdentityService` port (PRD §3.1). Enabled only when `>0` AND a Redis URL is set. Default `50051` in compose. |
| `FUSION_IDENTITY_LEASE_TTL` | no | `120` | Concurrency lease TTL in seconds (Redis-backed atomic locks). |
| `FUSION_IDENTITY_DB_POOL_MAX` | no | `8` | Postgres connection pool max size (`PgStore` only). Size to expected HTTP+gRPC concurrency; production suggests 20-50. |
| `FUSION_IDENTITY_KEK_PREV` | no | — | Previous KEK for online rotation dual-window. Set to the OLD key during a rotation; secrets still encrypted under it decrypt via this grace key. Must differ from `KEK` and `JWT_KEY`. Sweep with `POST /api/v1/admin/kek/reencrypt`, then drop. See [Operations](#operations). |
| `FUSION_IDENTITY_SERVICE_TOKEN_PREV` | no | — | Previous service token for rotation dual-window. Both tokens accepted (constant-time) until callers are rotated off the old one; then drop to close the window. Must differ from the current token and be >= 24 bytes. See [Operations](#operations). |
| `FUSION_IDENTITY_WEBHOOK_URL` | no | — (disabled) | Outbound webhook endpoint for the lifecycle event outbox (issue #14). Requires `FUSION_IDENTITY_WEBHOOK_SECRET` — a URL without a secret refuses to start (fail-closed). Unset = pull-only (poll `GET /api/v1/admin/events`). |
| `FUSION_IDENTITY_WEBHOOK_SECRET` | no | — | HMAC-SHA256 signing secret for webhook + post-provision hook payloads (`X-Fusion-Signature: sha256=<hex>`). |
| `FUSION_IDENTITY_WEBHOOK_TICK` | no | `5` | Webhook worker poll interval, seconds. |
| `FUSION_IDENTITY_WEBHOOK_MAX_ATTEMPTS` | no | `5` | Delivery attempts before an event is dead-lettered (status `dead`, stays queryable in the outbox). |

Without `FUSION_BOOTSTRAP_ADMIN_USER`/`PASS`, bootstrap is skipped when the tenant table is empty — the operator must seed the first admin out-of-band (fail-closed).

## API

All tenant-scoped routes require `Authorization: Bearer <jwt>` and `X-Tenant-Id: <tid>` headers; the token's `tid` must match both.

### Auth (`/api/v1/auth`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/login` | none | `{username,password,tenant_id,mfa_code?}` → `{access_token,refresh_token,must_change_password,mfa_required}`. When the user has an enabled TOTP factor and omits `mfa_code`, returns `mfa_required=true` with empty tokens; resend with `mfa_code` to complete. |
| GET | `/verify?token=` | service token | validate a token; returns `{tid,role,scopes,quota,tenant_status}` |
| POST | `/verify` | service token | body `{token}` |
| POST | `/introspect` | service token | RFC 7662 token introspection. Accepts JSON `{token}` or form-encoded `token=...`; returns `{active:false}` for invalid/revoked/expired tokens or `{active:true,scope,client_id,username,sub,tenant_id,role,token_type,iat,exp,jti,iss,aud}` for valid ones. |
| POST | `/refresh` | none | `{refresh_token}` → rotated access+refresh; reuse of a rotated token revokes the whole family |
| POST | `/revoke` | bearer (tenant_admin) | `{jti}` — revokes the caller's own jti (attribution audited) |
| POST | `/logout` | bearer | `{refresh_token?}` — revokes access jti + the refresh token |
| POST | `/password` | bearer | `{old_password,new_password}` — change own password (NIST 800-63B policy) |

### Session tokens (`/api/v1/auth/session` — Union Web R-2)

Gateway-issued browser session tokens for **single-tenant local mode** (fusion-web-shell does not carry its own auth; fusion-gateway issues + validates, the browser never talks to identity directly). Service-token gated, tenant-middleware exempt.

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/session` | service token | `{sub?="web-shell", tenant_id?="local", role?="member", ttl_seconds?(60..86400, default 43200)}` → `{access_token,jti,expires_in,role}`. The `local` tenant is auto-created (idempotent) on first use; any other tenant must already exist and be active (fail-closed). |
| POST | `/session/verify` | service token | `{token}` → `{valid,sub,tid,tenant,role,scope,iat,exp,jti,type}` or 401. Validates signature, `type=session`, jti revocation, tenant status. |

**Claims schema** (reserved — stable across local → multi-tenant rollout, no token format change later):

| Claim | Meaning |
|---|---|
| `sub` | browser principal (default `web-shell`) |
| `tid` / `tenant` | tenant id — reserved, fixed to `local` in local mode |
| `role` | unified role (`tenant_admin`/`operator`/`member`/`viewer`) |
| `scope` | `{resource}:{action}` list derived from the role |
| `type` | token type — `session` (access/refresh tokens are rejected on this flow) |
| `iat`/`nbf`/`exp`/`iss`/`aud`/`jti` | standard; `iss`+`aud` pinned to the identity deployment |

A `session` token is rejected by `/verify`/`/introspect` (type mismatch) — it only validates on `/session/verify`. Revocation: `POST /api/v1/auth/revoke` with the session `jti` (tenant_admin) or `revoke_user_sessions`.

### MFA (`/api/v1/auth/mfa`)

Self-service TOTP (RFC 6238) multi-factor. The TOTP secret is AES-GCM encrypted at rest under the KEK (`FUSION_IDENTITY_KEK`); only the raw secret + `otpauth://` URI are returned once at enroll time. All routes require a valid bearer token (the caller manages only their own factors, scoped by token `sub`).

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/enroll` | bearer | generate a TOTP secret, store encrypted, return `{method,secret,otpauth_uri,enabled}` |
| POST | `/verify` | bearer | `{code,method}` — confirm a correct TOTP code to enable the factor |
| GET | `` | bearer | list the caller's enrolled factors (secrets omitted) |
| DELETE | `/{method}` | bearer | remove a factor |

Admin enforcement: set `FUSION_IDENTITY_MFA_ENFORCE_ADMIN=1` to reject `tenant_admin` logins until the admin has an enabled TOTP factor (NIST 800-63B AAL2).

### Tenants (`/api/v1/tenants`)

Tenant creation/deletion is **operator-only** (no `POST`/`DELETE` endpoint — seeded via bootstrap or out-of-band). Self-service only:

| Method | Path | Notes |
|---|---|---|
| GET | `` | list — **self-only** (returns only the caller's `tid`) |
| GET | `/{tenant_id}` | get one (path guard) |
| PATCH | `/{tenant_id}` | update display_name/status/plan (path guard) |

### Members, API keys, Quotas, Audit — all under `/api/v1/tenants/{tenant_id}/...`

Members: add-or-create (`POST .../members`, new users get `must_change_password=true`), `GET`, role change (`PATCH .../{user_id}`), status change (`PATCH .../{user_id}/status`), password reset (`POST .../{user_id}/password`), `DELETE` — with last-tenant_admin and self-removal guards. API keys `POST`/`GET`/`DELETE`. Quotas `GET`/`PUT` (hot update). Audit `GET` (`limit` 1..1000, `since`/`until`/`cursor` params, self-query only) + `GET .../audit/verify` (chain-hash integrity check).

### Usage, Config, Export — under `/api/v1/tenants/{tenant_id}/...`

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/usage` | service token | emit a usage metric `{metric,value,source,model?,user_id?}` (downstream services report rpm/tpm/tokens) |
| GET | `/usage` | tenant_admin | aggregated usage (`since`/`until`/`metric` query params) |
| GET | `/usage/summary` | tenant_admin | aggregated usage report (`?since=&until=`) → `{events,totals{metric},by_source,by_model}` — enterprise admin contract (issue #10) |
| GET | `/config` | tenant_admin | non-sensitive tenant config (display_name, plan, status, quota) |
| GET | `/export` | tenant_admin | full tenant export (members without secrets, api-keys, quota, usage); audited as `tenant.export`. `?format=csv` returns a CSV attachment (default `json`) |

### Departments — under `/api/v1/tenants/{tenant_id}/departments` (issue #10)

Enterprise admin contract: department structure + per-department tool permission profiles, consumed by admin consoles (e.g. fusion-cowork). All routes `tenant_admin` + path guard.

| Method | Path | Notes |
|---|---|---|
| POST | `` | `{name,parent_id?,tool_allowlist:[...]}` → department record (201) |
| GET | `` | list tenant departments |
| GET | `/{dept_id}` | get one (404 if foreign) |
| PATCH | `/{dept_id}` | update name/parent_id/tool_allowlist |
| DELETE | `/{dept_id}` | remove |

### Audit event ingest + OTLP export — under `/api/v1/tenants/{tenant_id}/audit/...` (issue #10)

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/events` | service token | consumers (cowork, domain apps) push approval/permission/run events `{action,resource?,user_id?,severity?,detail?}` into the hash-chained tenant audit ledger; action is namespaced `external.*` |
| GET | `/otlp` | tenant_admin or service token | OTLP/JSON logs export (`?limit=1..1000&since=`) — point a local OTel Collector at it for SIEM ingestion, fully offline/LAN |

### JWKS (`/.well-known/jwks.json`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/.well-known/jwks.json` | none | RSA public keys in JWK format (RS256 mode); `{keys:[]}` under HS256. Prune expired grace keys on read. |
| POST | `/.well-known/jwks/rotate` | service token | rotate the RS256 signing `kid`; old key kept in JWKS for a 24h grace window so tokens issued before rotation still verify. HS256 → 400. |

### Identity Providers (`/api/v1/tenants/{tenant_id}/idps`)

Tenant admins register external OIDC IdPs per tenant. `client_secret` is AES-GCM encrypted at rest (KEK derived from `FUSION_IDENTITY_KEK`); the encrypted blob is never returned by the API.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `` | tenant_admin (path guard) | list IdPs for the tenant (secrets omitted) |
| POST | `` | tenant_admin (path guard) | create IdP `{idp_id,type,issuer_url,client_id,client_secret,scopes,auto_provision}` → encrypts secret |
| GET | `/{idp_id}` | tenant_admin (path guard) | get one IdP (secret omitted, must belong to tenant) |
| PATCH | `/{idp_id}` | tenant_admin (path guard) | patch IdP `{type?,issuer_url?,client_id?,client_secret?,scopes?,auto_provision?}` → re-encrypts secret if provided |
| DELETE | `/{idp_id}` | tenant_admin (path guard) | remove IdP (must belong to tenant) |

### OIDC SSO (`/api/v1/auth/oidc/{idp_id}/...`)

Authorization-code flow against a registered IdP. On success it auto-provisions the user + tenant membership (when `auto_provision=true`) and issues Fusion access/refresh JWTs. The OIDC endpoints are tenant-middleware-exempt (a synthetic `X-Tenant-Id: oidc` header is injected so downstream exempt checks still pass).

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/login` | none | 302 redirect to the IdP `/authorize` endpoint with a random `state` |
| POST | `/callback` | none | `{code,state}` → exchanges code for an IdP access token (httpx), fetches userinfo, auto-provisions, issues Fusion JWTs |

### SCIM 2.0 (`/scim/v2/Users`)

Inbound user provisioning for downstream services / IdP connectors. Service-token gated (`Authorization: Bearer <service_token>`), tenant selected via the `tenantId` query param. For path-scoped routes (`/Users/{id}`) the `tenantId` query param is injected as a synthetic `X-Tenant-Id` header so the tenant middleware accepts the call.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/Users?tenantId=` | service token | SCIM ListResponse of tenant members |
| POST | `/Users?tenantId=` | service token | create user + auto-add as `member`; `{userName,displayName,active}` |
| GET | `/Users/{id}?tenantId=` | service token | get one user (must be a tenant member) |
| PATCH | `/Users/{id}?tenantId=` | service token | RFC 7644 `Operations` array (`[{op,path,value}]`, replace/add/remove on `displayName`/`active`; `userName` read-only). Legacy flat-resource `{displayName?,active?}` also accepted. |
| DELETE | `/Users/{id}?tenantId=` | service token | remove membership + disable user |

SCIM `/Users` GET supports `startIndex`, `count`, `filter` (`attr eq "val"` subset), and `sortBy` query params; the ListResponse includes `totalResults`, `startIndex`, and `itemsPerPage`. `/Groups` maps the four unified roles to SCIM groups:

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/Groups?tenantId=` | service token | SCIM ListResponse of role-based groups (`tenant_admin`/`operator`/`member`/`viewer`), each with its member list; supports `startIndex`/`count`/`filter` |
| GET | `/Groups/{group_id}?tenantId=` | service token | one role-group with its members |

### RBAC contract — custom roles, write classes, menu matrix (issue #12, migration E5)

Generalizes the fixed four-role model into a per-tenant RBAC contract so an admin shell can host a Users & Roles GUI unchanged. Built-in roles (`tenant_admin`/`operator`/`member`/`viewer`) are immutable; their write classes are derived deterministically from the permission seeds (every seeded resource with a `write` action). Custom roles are per-tenant, bounded (≤64 per tenant, ≤64 write classes each), and grant write classes that the capability-spine mutation gating intersects with.

The **role ↔ menu matrix** is a runtime-editable policy: menus are declared by module manifests and registered per tenant; identity stores the matrix row per (tenant, role). Changes take effect on the next `POST /api/v1/auth/verify` call (next page load) — no frontend release needed. `POST .../roles/{role_id}/menus/reset` restores built-in defaults.

The `verify` response is the enforcement surface and now carries `write_classes` + `allowed_menus` alongside `role`/`scopes`, so the shell and gateway enforce server-side — never client-only. A membership row whose role no longer resolves (deleted custom role) fails closed at verify. The **requester != approver** invariant for any approval flow is a first-class contract endpoint.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `.../roles` | tenant_admin (path guard) | list built-in + custom roles with `write_classes` + current `menus` |
| POST | `.../roles` | tenant_admin (path guard) | create custom role `{role_id,display_name,write_classes}`; built-in collision → 409 |
| PATCH | `.../roles/{role_id}` | tenant_admin (path guard) | update custom role; built-in → 403 |
| DELETE | `.../roles/{role_id}` | tenant_admin (path guard) | delete custom role; built-in → 403, still assigned to members → 409 |
| GET | `.../roles/{role_id}/menus` | tenant_admin (path guard) | current matrix row (defaults if unset) |
| PUT | `.../roles/{role_id}/menus` | tenant_admin (path guard) | set matrix row `{menus:[...]}`; unregistered menu → 409 |
| POST | `.../roles/{role_id}/menus/reset` | tenant_admin (path guard) | reset to defaults |
| GET | `.../menus` | tenant_admin (path guard) | known (registered) menu ids for the tenant |
| POST | `.../menus` | tenant_admin (path guard) | register menu ids `{menus:[...]}` (≤256/tenant) |
| POST | `.../approvals/validate` | tenant_admin (path guard) | `{requester_id,approver_id}` → 200 `{valid:true}`; equal → 403, non-member → 404 |

Role assignment / enable / disable / password reset for users stay on the members plane (`/api/v1/tenants/{tid}/members...`); role validators now accept any resolvable role (built-in or that tenant's custom roles) with the store as the fail-closed authority. Member role guards (cannot demote/disable/remove the last `tenant_admin`, cannot change own role) are unchanged and apply to the custom-role paths too.

Schema: `custom_roles`, `role_menu_matrix`, `known_menus` (migration `0009_rbac_custom_roles.sql`, RLS-isolated like all tenant tables).

## gRPC IdentityService (PRD §3.1)

The high-throughput authorization plane for inference gateways. Enabled when `FUSION_IDENTITY_GRPC_PORT>0` and `FUSION_IDENTITY_REDIS_URL` is set. Serves `fusion.identity.v1.IdentityService` on `127.0.0.1:<port>` with a gRPC health check (`grpc.health.v1`).

Proto: [`fusion_identity/grpc/identity.proto`](fusion_identity/grpc/identity.proto). Regenerate the Python stubs after editing the proto with [`scripts/gen_proto.sh`](scripts/gen_proto.sh) (requires `grpcio-tools` in the venv; idempotent — it also patches the relative import in `identity_pb2_grpc.py` to the package-qualified form).

| RPC | Notes |
|---|---|
| `AuthorizeAndAcquire` | validate `api_key` → tenant context, module/model allowlist, RPM rate limit, daily quota, then atomically acquire a concurrency **lease** (Redis Lua). The request carries an optional `tenant_id`: when set, the server cross-checks it against the key's real tenant and refuses (fail-closed) on mismatch, so a key cannot be misattributed to another tenant. Returns `is_allowed`, `TenantContext` (incl. `priority`), `lease_id`, `max_allowed_tokens`. Refusal codes: `INVALID_API_KEY` / `TENANT_DISABLED` / `MODULE_UNAUTHORIZED` / `MODEL_UNAUTHORIZED` / `CONCURRENCY_LIMIT_EXCEEDED` / `DAILY_QUOTA_EXCEEDED` / `RATE_LIMIT_EXCEEDED`. |
| `ReleaseLease` | release a lease (decrement concurrency counter). |
| `ReportUsage` | record token usage (daily quota counter), release the lease, append to the usage ledger (non-blocking). |

Priority is derived from `quotas.default_priority` (settable via the admin/quotas API), falling back to tier: `enterprise=3`, `pro/standard/team=2`, `free=1`.

### Client SDK (gateway side)

[`fusion_identity/client/`](fusion_identity/client/) ships a Python client for gateways:

- `IdentityClient` — long-lived gRPC channel, 10 ms default deadline, async `authorize_and_acquire` (optionally asserts `tenant_id`) / `release_lease` / `report_usage` / `health`.
- `lease_guard` — `asynccontextmanager` that acquires a lease, yields the response, and always releases on exit; raises `LeaseDenied` on refusal.
- `KV_PREFIX = "fusion:identity:"` — shared Redis key namespace for cross-service coordination.

### Cache invalidation (PRD §2.6 — config changes take effect in seconds)

When Redis is enabled, mutations invalidate the affected cache keys so downstream reads pick up changes within the key TTL (≤300 s):
- tenant create/update, quota update, admin tenant create/update → `invalidate_tenant(tid)`.
- API key revoke (tenant + admin) → `invalidate_api_key_by_hash(key_hash)`.
RPM enforcement uses a 60 s sliding window (`rpm:{tid}`); a quota `rpm=0` disables it (fail-open when Redis is unset, matching the daily-quota pattern).

## Admin plane (`/api/v1/admin`)

Service-token gated cross-tenant management (operator/gateway use). Requests must carry `Authorization: Bearer <service_token>` and an `X-Tenant-Id` header (sentinel `_system` for cross-tenant calls — the tenant middleware requires the header; the service token authorizes the action).

| Method | Path | Notes |
|---|---|---|
| GET | `/tenants` | list all tenants |
| POST | `/tenants` | create tenant `{tenant_id,display_name,plan,tier?,max_concurrency?,daily_token_limit?,allowed_modules?,allowed_models?}` (409 on conflict); quota fields seed `quotas` |
| PUT | `/tenants/{tenant_id}` | update tenant `{max_concurrency?,daily_token_limit?,allowed_modules?,allowed_models?,display_name?,status?}` (quota fields → `quotas`, rest → tenant row) |
| GET | `/tenants/{tenant_id}/quota` | read the tenant's quota row |
| POST | `/tenants/{tenant_id}/api-keys` | mint an API key for a tenant `{user_id?,name?,scopes}`; raw key returned once |
| POST | `/tenants/{tenant_id}/keys` | alias of the above (PRD §3.2 `/keys` path) |
| DELETE | `/tenants/{tenant_id}/api-keys/{key_id}` | revoke a tenant's API key (404 if not in tenant) |
| DELETE | `/tenants/{tenant_id}/keys/{key_id}` | alias of the above (PRD §3.2 `/keys` path) |
| GET | `/tenants/{tenant_id}/usage/today` | 24h usage: `concurrency{current_active,max_limit}` + `tokens{prompt_tokens_today,completion_tokens_today,total_today,daily_limit,usage_percentage}` |

Quotas now also support `default_priority` and `allowed_modules` via `PUT /api/v1/tenants/{tenant_id}/quotas`.

## Provisioning automation (issue #14, migration `0010_provisioning.sql`)

One-shot tenant provisioning for SaaS control planes (CharacterVoiceAgent is the first consumer) — replaces 3+ separate admin calls with no transactional guarantee and no events.

### One-shot provisioning (M-A) — `POST /api/v1/admin/tenants/provision`

Service-token gated. Single call: tenant + plan-mapped quota + seed admin + API key.

```json
{
    "tenant_id": "cva",                  // optional — auto-generated `tnt_*` when omitted
    "display_name": "CharacterVoiceAgent",
    "plan": "pro",                       // resolves a plan quota template (M-C)
    "quotas": {"concurrent": 8},         // optional per-tenant overrides (beat the template)
    "seed_admin": {"username": "cva_admin", "password": "..."},  // password omitted → generated, returned once, must_change_password=true
    "api_key": {"scopes": ["inference"]},  // optional — raw fmu_ key returned once
    "hook_url": "http://control-plane/register"  // optional generic post-provision hook (M-D)
}
```

Response: `{tenant, quota, admin, api_key, hook?, idempotent_replay}`. The raw API key appears only in this response (and the signed hook payload) — never in outbox events.

**Idempotency**: send an `Idempotency-Key` header — replaying the same key returns the original result with `idempotent_replay: true` and creates nothing new. The seed-admin username is pre-checked before the tenant is created, so a conflict cannot orphan a half-provisioned tenant.

### Plan quota templates (M-C)

`plan` maps deterministically to quota template values. Built-ins: `free`, `starter`, `standard`, `pro`, `enterprise`. Effective quota = template + per-tenant overrides. Admin-managed at runtime:

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/admin/plan-templates` | list all templates |
| GET | `/api/v1/admin/plan-templates/{plan}` | one template (404 if unknown) |
| PUT | `/api/v1/admin/plan-templates/{plan}` | upsert `{quota: {...}}` — create or override |

**Note**: the `tpm` quota field is the **daily token limit** (legacy field name, kept for compatibility — the gRPC plane enforces it as a per-day counter).

### Lifecycle events (M-B) — outbox + webhook

All lifecycle mutations append to a transactional event outbox (`event_outbox` table, migration 0010): `tenant.created`, `tenant.quota_changed`, `tenant.status_changed`, `apikey.created`, `apikey.revoked`.

- **Pull**: `GET /api/v1/admin/events?cursor=<seq>&limit=100` (service token) — returns events plus `next_cursor` for incremental polling.
- **Push**: set `FUSION_IDENTITY_WEBHOOK_URL` + `FUSION_IDENTITY_WEBHOOK_SECRET` and a background worker drains the outbox to the endpoint with HMAC-SHA256 signatures (`X-Fusion-Signature: sha256=<hex>` of the exact request body, plus `X-Fusion-Event` / `X-Fusion-Event-Id` headers). Failed deliveries retry each tick; after `WEBHOOK_MAX_ATTEMPTS` the event is dead-lettered (`status=dead`) and stays queryable for reprocessing.

### Post-provision hook (M-D, optional)

`hook_url` in the provision request: identity POSTs `{"event": "provision.completed", "data": {tenant, quota, admin, api_key}}` to the URL, signed with the same HMAC scheme. Generic — the control plane can register the tenant's key in fusion-gateway (or any downstream) straight from the payload, no polling, no gateway-specific code in identity.

## Metrics

`GET /metrics` (no auth, Prometheus text format) exposes the store gauges plus labeled Prometheus counters from the gRPC plane:

- `fusion_identity_auth_requests_total{tenant_id,target_module,status_code,result}` — authorize results by label (`allowed` / `<error_code>`), with HTTP status code.
- `fusion_identity_rpc_latency_seconds{method}` — gRPC latency histogram.
- `fusion_identity_tenant_active_concurrency{tenant_id}` — active leases gauge.
- `fusion_identity_tokens_consumed_total{tenant_id,model_name,type}` — tokens reported (`type` = `grpc` / etc).
- `fusion_identity_quota_remaining{tenant_id}` — remaining daily quota gauge.

## Database

Postgres DB `fusion_tenant`. Schema in [`deploy/sql/schema.sql`](deploy/sql/schema.sql) (Appendix A.1 DDL) applied via idempotent migrations in [`migrations/`](migrations/) on `PgStore` startup. 23 tables: `tenants`, `users`, `tenant_members`, `api_keys`, `roles`, `quotas`, `usage_ledger`, `tenant_usage_daily`, `refresh_tokens`, `revoked_jtis`, `issued_jtis`, `audit_log`, `migration_orphans`, `identity_providers`, `user_mfa`, `lease_log`, `departments`, `custom_roles`, `role_menu_matrix`, `known_menus`, `plan_templates`, `idempotency_keys`, `event_outbox`. `users` stores argon2id hashes with per-user salts; `refresh_tokens` tracks rotation families (reuse → family revoke); `audit_log` is hash-chained with an atomic sequence; `lease_log` is the concurrency lease ledger (Redis is authoritative); `event_outbox` is the lifecycle event log (issue #14).

An `InMemoryStore` ships for tests and bootstrap; `build_app()` uses it when `FUSION_IDENTITY_USE_PGSTORE` is unset. Production sets that env and injects a `PgStore`, which runs idempotent migrations from [`migrations/`](migrations/) on startup (`ensure_schema`).

### Row-Level Security — strong isolation layer (PRD red-line #3)

Migration `0007_rls_strong_isolation.sql` is the **strong layer** of data isolation, defense-in-depth under the app-layer guard (`require_tenant_admin_of`). It enables + forces RLS on the 12 tenant-scoped tables (`tenants`, `tenant_members`, `api_keys`, `quotas`, `usage_ledger`, `tenant_usage_daily`, `refresh_tokens`, `revoked_jtis`, `issued_jtis`, `audit_log`, `identity_providers`, `lease_log`). Each policy is gated on the `app.current_tenant` GUC: a row is visible only when `tenant_id = current_setting('app.current_tenant')` or the GUC is the `_system` sentinel (the platform/admin scope that spans tenants — needed for login, refresh, api-key-by-hash, the admin plane, and stats). Platform tables (`users`, `roles`, `user_mfa`, `migration_orphans`) are intentionally not under RLS; they are shared across tenants by PRD design and governed by the app layer.

The migration also creates a dedicated non-superuser role `fusion_identity_app` (default password `change-me-operator-rotates` — **rotate before production**) and grants it least-privilege DML. **Superusers and `BYPASSRLS` roles bypass RLS by Postgres rule**, so the operator's own admin account does not enforce it — the service must connect as `fusion_identity_app` in production for RLS to bind. `ALTER DATABASE fusion_tenant SET app.current_tenant = '_system'` makes every session default to the platform scope, so the existing single-connection-pool service keeps working unchanged.

The database default keeps the service functional today; **per-request tenant GUC activation** (narrowing `app.current_tenant` to the verified token's `tid` inside a request-scoped transaction so RLS becomes the primary fence) is a tracked follow-up. It requires `PgStore` to hold one connection across a request instead of acquiring per call. Until then `require_tenant_admin_of` remains the primary cross-tenant enforcement point and RLS is the backstop that fails closed if a query ever drops its `WHERE tenant_id` filter while running as the low-priv role. RLS is verified by `tests/test_rls_isolation.py` (4 cases, integration).

## Test

```bash
pytest tests/ -v          # 219 cases, offline (InMemoryStore + fakeredis)
pytest tests/ -m integration -v   # 15 cases: PgStore lifecycle + Redis Lua real-run + RLS isolation
ruff check . && ruff format --check .
```

Integration tests (`@pytest.mark.integration`) need a live `fusion_tenant` Postgres (apply `deploy/sql/schema.sql`) and a live Redis:

```bash
export FUSION_IDENTITY_DATABASE_URL="postgresql://<user>@127.0.0.1:5432/fusion_tenant"
export FUSION_IDENTITY_REDIS_URL="redis://127.0.0.1:6379/0"
# RLS isolation tests connect as the low-priv role created by migration 0007:
export FUSION_IDENTITY_APP_ROLE_URL="postgresql://fusion_identity_app:<rotated-password>@127.0.0.1:5432/fusion_tenant"
pytest tests/ -m integration -v   # PgStore lifecycle + Redis Lua real-run + RLS isolation
```

## Deploy

```bash
docker build -f deploy/Dockerfile -t fusion-identity:0.1.0 .
docker run -p 11470:11470 -p 50051:50051 \
  -e FUSION_IDENTITY_JWT_KEY=... -e FUSION_IDENTITY_SERVICE_TOKEN=... \
  -e FUSION_IDENTITY_KEK=... \
  -e FUSION_IDENTITY_REDIS_URL=redis://host.docker.internal:6379/0 \
  -e FUSION_IDENTITY_GRPC_PORT=50051 \
  fusion-identity:0.1.0
```

### Docker Compose (redis + identity)

```bash
export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"
export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"
export FUSION_IDENTITY_KEK="$(openssl rand -hex 32)"
./start.sh compose up        # builds + starts redis + identity (gRPC on 50051)
./start.sh compose down
./start.sh compose logs
```

Compose file: [`deploy/docker-compose.yml`](deploy/docker-compose.yml).

### Performance benchmark

```bash
# against a running gRPC server (needs a valid tenant api key)
python deploy/bench/bench_grpc.py --target 127.0.0.1:50051 --api-key fmu_... \
  --total 5000 --concurrency 50
```

Targets: **P99 < 2 ms** and **> 5000 QPS** for `AuthorizeAndAcquire` (lease acquire + release). Reports p50/p95/p99 + QPS and whether targets are met.

Lifecycle is `start.sh` (`start|stop|restart|status|log|compose`) — fusion-supervisor compatible.

## Operations

Full production procedures — backup/restore, monitoring + alert rules, SLO targets, key rotation (KEK + service token + JWT), HA prerequisites, and on-call escalation — are in **[`docs/ops-runbook.md`](docs/ops-runbook.md)**.

### Key rotation (zero-downtime, dual-window)

**KEK** (encrypts IdP `client_secret` + MFA `secret` at rest) — set `FUSION_IDENTITY_KEK=<new>` + `FUSION_IDENTITY_KEK_PREV=<old>`, restart, sweep with `POST /api/v1/admin/kek/reencrypt` (service token, `X-Tenant-Id: _system`), then drop `KEK_PREV` and restart. Config rejects `KEK_PREV == KEK` or `KEK_PREV == JWT_KEY` (key isolation).

**Service token** (gates `/verify`, admin, SCIM, usage emit) — set `FUSION_IDENTITY_SERVICE_TOKEN=<new>` + `FUSION_IDENTITY_SERVICE_TOKEN_PREV=<old>`, restart (both accepted, constant-time compared), rotate callers off the old token, then drop `PREV` and restart. Config rejects `PREV == current` or `PREV` < 24 bytes.

Both rotations log a warning when the grace (prev) key/token is used, so the operator can see when rotation is complete. See the runbook for full step-by-step + rollback.

### HA consistency

The service is multi-instance safe at the application layer: two instances sharing one Postgres see consistent state for tenant visibility, jti issuance/revocation, the hash-chained audit log, and usage aggregation (verified by `tests/test_ha_consistency.py`, integration-marked). Postgres HA (streaming replication + failover) and Redis HA are infrastructure prerequisites — see the runbook.

## License

MIT
