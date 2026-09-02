-- fusion_tenant schema — tenant-identity service (multi-tenant-prd-0901 Appendix A.1)
-- Verbatim from PRD §A.1, extended per multi-tenant-0902.md §5. Independent of cowork RLS business DB.
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
    deleted_at   TIMESTAMPTZ,
    CONSTRAINT tenants_status_chk CHECK (status IN ('active','disabled','deleted'))
);
CREATE INDEX tenants_status_idx ON tenants(status) WHERE status <> 'deleted';

-- users (platform-level, may belong to multiple tenants)
-- password_hash = legacy scrypt fixed-salt (migration), password_hash_v = argon2id per-user salt
CREATE TABLE users (
    user_id              TEXT PRIMARY KEY,
    username             TEXT NOT NULL,
    email                TEXT UNIQUE,
    password_hash        TEXT NOT NULL DEFAULT '',
    password_hash_v      TEXT NOT NULL DEFAULT '',
    salt                 TEXT NOT NULL DEFAULT '',
    password_algo        TEXT NOT NULL DEFAULT 'scrypt',
    status               TEXT NOT NULL DEFAULT 'active',
    failed_attempts      SMALLINT NOT NULL DEFAULT 0,
    locked_until         TIMESTAMPTZ,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_algo_chk  CHECK (password_algo IN ('argon2id','scrypt','legacy')),
    CONSTRAINT users_status_chk CHECK (status IN ('active','disabled','locked'))
);
CREATE INDEX users_username_idx ON users(username);

-- tenant_members (user <-> tenant <-> role)
CREATE TABLE tenant_members (
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id    TEXT NOT NULL REFERENCES users(user_id),
    role       TEXT NOT NULL,
    added_by   TEXT REFERENCES users(user_id),
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
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
    bucket_hour TIMESTAMPTZ NOT NULL DEFAULT date_trunc('hour', now()),
    metric      TEXT NOT NULL,
    value       BIGINT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    model       TEXT,
    user_id     TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, bucket_hour, metric, source)
);
CREATE INDEX usage_ledger_tenant_ts_idx ON usage_ledger(tenant_id, bucket_hour);

-- tenant_usage_daily (dashboard rollup, §4.11)
CREATE TABLE tenant_usage_daily (
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    bucket_day DATE NOT NULL,
    metric     TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    value      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, bucket_day, metric, source)
);

-- refresh_tokens (§4.6, rotation + family reuse detection)
CREATE TABLE refresh_tokens (
    jti         TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id     TEXT NOT NULL REFERENCES users(user_id),
    status      TEXT NOT NULL DEFAULT 'active',
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    replaced_by TEXT REFERENCES refresh_tokens(jti),
    CONSTRAINT rt_status_chk CHECK (status IN ('active','rotated','revoked'))
);
CREATE INDEX rt_family_idx      ON refresh_tokens(family_id);
CREATE INDEX rt_tenant_user_idx ON refresh_tokens(tenant_id, user_id);
CREATE INDEX rt_expires_idx     ON refresh_tokens(expires_at) WHERE status <> 'revoked';

-- revoked_jtis (§5.5, jti persistence survives restart)
CREATE TABLE revoked_jtis (
    jti        TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id    TEXT REFERENCES users(user_id),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason     TEXT,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX rj_expires_idx ON revoked_jtis(expires_at);

-- audit_log (§11.4, 7d hot + archive) — full-field chain hash + global seq
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    seq        BIGINT NOT NULL UNIQUE,
    tenant_id  TEXT NOT NULL,
    user_id    TEXT,
    jti        TEXT,
    role       TEXT,
    action     TEXT NOT NULL,
    resource   TEXT,
    detail     JSONB,
    chain_hash TEXT NOT NULL,
    prev_hash  TEXT NOT NULL DEFAULT '',
    ts         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_tenant_ts_idx ON audit_log(tenant_id, ts DESC);
CREATE INDEX audit_log_seq_idx       ON audit_log(seq);

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

-- identity_providers (§5.9, G20 OIDC/SCIM federation)
CREATE TABLE identity_providers (
    idp_id            TEXT        PRIMARY KEY,
    tenant_id         TEXT        NOT NULL REFERENCES tenants(tenant_id),
    type              TEXT        NOT NULL,
    issuer_url        TEXT,
    client_id         TEXT,
    client_secret_enc TEXT,
    scopes            TEXT,
    auto_provision    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX identity_providers_tenant_idx ON identity_providers(tenant_id);

-- user_mfa (§5.10, G21 TOTP)
CREATE TABLE user_mfa (
    user_id     TEXT        NOT NULL REFERENCES users(user_id),
    method      TEXT        NOT NULL,
    secret_enc  TEXT        NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, method)
);
