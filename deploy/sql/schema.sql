-- fusion_tenant schema — tenant-identity service (multi-tenant-prd-0901 Appendix A.1)
-- Verbatim from PRD §A.1. Independent of cowork RLS business DB.
CREATE DATABASE fusion_tenant;

\c fusion_tenant

-- tenants
CREATE TABLE tenants (
    tenant_id    TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    plan         TEXT NOT NULL DEFAULT 'team',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at  TIMESTAMPTZ,
    deleted_at   TIMESTAMPTZ
);
CREATE INDEX tenants_status_idx ON tenants(status);

-- users (platform-level, may belong to multiple tenants)
CREATE TABLE users (
    user_id       TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    email         TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- tenant_members (user <-> tenant <-> role)
CREATE TABLE tenant_members (
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id    TEXT NOT NULL REFERENCES users(user_id),
    role       TEXT NOT NULL,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX tenant_members_user_idx ON tenant_members(user_id);

-- api_keys (gateway maps tenant_id, §7.1)
CREATE TABLE api_keys (
    key_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id     TEXT REFERENCES users(user_id),
    key_hash    TEXT NOT NULL,
    prefix      TEXT NOT NULL,
    scopes      JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX api_keys_tenant_idx ON api_keys(tenant_id);
CREATE INDEX api_keys_hash_idx ON api_keys(key_hash);

-- roles (v1 fixed four roles, stored for audit/extensibility)
CREATE TABLE roles (
    role         TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    permissions  JSONB NOT NULL
);

-- quotas (§10.1)
CREATE TABLE quotas (
    tenant_id       TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
    rpm             INT NOT NULL DEFAULT 60,
    tpm             INT NOT NULL DEFAULT 100000,
    concurrent      INT NOT NULL DEFAULT 4,
    storage_mb      INT NOT NULL DEFAULT 10240,
    allowed_models  JSONB NOT NULL DEFAULT '[]',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- usage_ledger (§10.3, hourly bucket)
CREATE TABLE usage_ledger (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    bucket_hour TIMESTAMPTZ NOT NULL,
    metric      TEXT NOT NULL,
    value       BIGINT NOT NULL,
    source      TEXT NOT NULL,
    UNIQUE (tenant_id, bucket_hour, metric, source)
);
CREATE INDEX usage_ledger_tenant_ts_idx ON usage_ledger(tenant_id, bucket_hour);

-- audit_log (§11.4, 7d hot + archive)
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    user_id     TEXT,
    jti         TEXT,
    role        TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    detail      JSONB,
    chain_hash  TEXT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_tenant_ts_idx ON audit_log(tenant_id, ts);

-- migration_orphans (§9.3, fail-visible)
CREATE TABLE migration_orphans (
    id           BIGSERIAL PRIMARY KEY,
    source_table TEXT NOT NULL,
    source_pk    TEXT NOT NULL,
    reason       TEXT NOT NULL,
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- seed: four roles
INSERT INTO roles VALUES
 ('tenant_admin','Tenant Admin','{"tenants":["read","write"],"users":["read","write"],"quotas":["read","write"],"audit":["read"]}'::jsonb),
 ('operator','Operator','{"models":["read","infer"],"tasks":["read","write"]}'::jsonb),
 ('member','Member','{"models":["infer"],"tasks":["write"]}'::jsonb),
 ('viewer','Viewer','{"models":["read"],"tasks":["read"]}'::jsonb);
