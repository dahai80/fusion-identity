# fusion-identity

Tenant-identity service for the Fusion ecosystem — the **sole JWT issuer** and **tenant registry** for multi-tenant isolation across all Fusion services.

Implements the multi-tenant PRD §3 (tenant model), §4 (tenant context fabric), and Appendix A (schema + JWT claims). Sits at the **Base Framework layer** alongside `fusion-core`; ecosystem services consume it, never re-implement it.

## Responsibilities

- **JWT issuance** — `HS256` access + refresh tokens. Claims: `sub`, `tid`, `tenant`, `role`, `scope`, `iat`, `exp`, `iss`, `aud`, `jti`. Issuer `fusion-identity`, audience `fusion-cluster`.
- **Tenant registry** — CRUD tenants (`tenant_id`, `display_name`, `plan`, `status`).
- **Membership + RBAC** — 4 unified roles: `tenant_admin` / `operator` / `member` / `viewer`. Server re-verifies role from `tenant_members` on every protected call (token role claim is advisory, not immutable).
- **Quotas** — per-tenant `rpm` / `tpm` / `concurrent` / `storage_mb` / `allowed_models`, hot-updatable (no restart).
- **API keys** — per-tenant scoped keys, SHA-256 hashed at rest.
- **Audit log** — append-only, hash-chained, self-query only (admin of tenant A cannot read tenant B's audit).
- **Token verification endpoint** — service-to-service `POST /api/v1/auth/verify`, gated by a shared **service token** (`FUSION_IDENTITY_SERVICE_TOKEN`). Downstream services call this to validate bearer tokens.

## The three red lines (multi-tenant PRD)

1. **Fail-closed** — missing `tenant_id`, invalid token, or missing required env (`FUSION_IDENTITY_JWT_KEY`, `FUSION_IDENTITY_SERVICE_TOKEN`) → `401` / refuses to start. No default-tenant degradation.
2. **Cross-tenant denied** — a `tenant_admin` of tenant A is blocked (403) from tenant B's members, api-keys, quotas, and audit. Enforced by `require_tenant_admin_of()` comparing token `tid` against both the `X-Tenant-Id` header and the path `{tenant_id}`.
3. **Data isolation layering** — strong = Postgres RLS (prod), medium = `tenant_id` column + guards (this service), namespace = key-prefix. Layers are not mixed.

## Quick start

```bash
cd /Users/dahai/fusion
source .venv/bin/activate
pip install -e fusion-identity

# fail-closed: both env vars are REQUIRED
export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"
export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"
export FUSION_BOOTSTRAP_ADMIN_USER=admin
export FUSION_BOOTSTRAP_ADMIN_PASS=adminpass

./fusion-identity/start.sh start
curl -s http://127.0.0.1:11470/health   # {"status":"ok","service":"fusion-identity",...}
```

Binds **127.0.0.1 only** by default (PRD C8 — no external exposure; traffic reaches it via the gateway).

## Environment

| Variable | Required | Default | Notes |
|---|---|---|---|
| `FUSION_IDENTITY_JWT_KEY` | **yes** | — | HS256 signing key. Service refuses to start without it. |
| `FUSION_IDENTITY_SERVICE_TOKEN` | **yes** | — | Shared token gating `/verify`. |
| `FUSION_IDENTITY_HOST` | no | `127.0.0.1` | Bind address. |
| `FUSION_IDENTITY_PORT` | no | `11470` | Listen port. |
| `FUSION_IDENTITY_DATABASE_URL` | no | `postgresql://127.0.0.1:5432/fusion_tenant` | Postgres connection. |
| `FUSION_IDENTITY_JWT_ISSUER` | no | `fusion-identity` | JWT `iss` claim. |
| `FUSION_IDENTITY_JWT_AUDIENCE` | no | `fusion-cluster` | JWT `aud` claim. |
| `FUSION_IDENTITY_JWT_TTL` | no | `28800` (8h) | Access token TTL, seconds. |
| `FUSION_IDENTITY_REFRESH_TTL` | no | `604800` (7d) | Refresh token TTL, seconds. |
| `FUSION_BOOTSTRAP_ADMIN_USER` | no | — | Bootstrap `tenant_admin` username. |
| `FUSION_BOOTSTRAP_ADMIN_PASS` | no | — | Bootstrap `tenant_admin` password. |
| `FUSION_IDENTITY_LOG_LEVEL` | no | `INFO` | Log level. |

Without `FUSION_BOOTSTRAP_ADMIN_USER`/`PASS`, bootstrap is skipped when the tenant table is empty — the operator must seed the first admin out-of-band (fail-closed).

## API

All tenant-scoped routes require `Authorization: Bearer <jwt>` and `X-Tenant-Id: <tid>` headers; the token's `tid` must match both.

### Auth (`/api/v1/auth`)

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/login` | none | `{username,password,tenant_id}` → `{access_token,refresh_token,...}` |
| GET | `/verify?token=` | service token | validate a token; returns `{tid,role,scopes,quota}` |
| POST | `/verify` | service token | body `{token}` |
| POST | `/refresh` | none | `{refresh_token}` → new access token |
| POST | `/revoke` | bearer (tenant_admin) | `{jti}` |

### Tenants (`/api/v1/tenants`)

| Method | Path | Notes |
|---|---|---|
| GET | `` | list tenants |
| POST | `` | create (201) |
| GET | `/{tenant_id}` | get one |
| PATCH | `/{tenant_id}` | update display_name/status/plan |
| DELETE | `/{tenant_id}` | soft-delete |

### Members, API keys, Quotas, Audit — all under `/api/v1/tenants/{tenant_id}/...`

Membership add-or-create (`POST .../members`), list/`DELETE`. API keys `POST`/`GET`/`DELETE`. Quotas `GET`/`PUT` (hot update). Audit `GET` (`limit` 1..1000, self-query only).

## Database

Postgres DB `fusion_tenant`. Schema in [`deploy/sql/schema.sql`](deploy/sql/schema.sql) (Appendix A.1 DDL). 9 tables: `tenants`, `users`, `tenant_members`, `api_keys`, `roles`, `quotas`, `usage_ledger`, `audit_log`, `migration_orphans`. Apply with `psql` before first run; `PgStore.ensure_schema` only warns (DDL is the operator/CI's responsibility).

An `InMemoryStore` ships for tests and bootstrap; `build_app()` uses it when no Postgres store is injected.

## Test

```bash
pytest tests/ -v          # 20 cases, offline (InMemoryStore)
pytest tests/ -m integration -v   # needs live Postgres fusion_tenant
ruff check . && ruff format --check .
```

## Deploy

```bash
docker build -f deploy/Dockerfile -t fusion-identity:0.1.0 .
docker run -p 11470:11470 \
  -e FUSION_IDENTITY_JWT_KEY=... -e FUSION_IDENTITY_SERVICE_TOKEN=... \
  fusion-identity:0.1.0
```

Lifecycle is `start.sh` (`start|stop|restart|status|log`) — fusion-supervisor compatible.

## License

MIT
