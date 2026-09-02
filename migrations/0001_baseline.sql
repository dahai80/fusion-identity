-- 0001_baseline: fusion_tenant v1 schema (multi-tenant-0902.md §5)
-- Applied against connected fusion_tenant DB. CREATE DATABASE is operator's job.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id    TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    plan         TEXT NOT NULL DEFAULT 'team',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at  TIMESTAMPTZ,
    deleted_at   TIMESTAMPTZ,
    CONSTRAINT tenants_status_chk CHECK (status IN ('active','disabled','deleted'))
);
CREATE INDEX IF NOT EXISTS tenants_status_idx ON tenants(status) WHERE status <> 'deleted';

CREATE TABLE IF NOT EXISTS users (
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
    CONSTRAINT users_algo_chk   CHECK (password_algo IN ('argon2id','scrypt','legacy')),
    CONSTRAINT users_status_chk CHECK (status IN ('active','disabled','locked'))
);
CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);

CREATE TABLE IF NOT EXISTS tenant_members (
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id    TEXT NOT NULL REFERENCES users(user_id),
    role       TEXT NOT NULL,
    added_by   TEXT REFERENCES users(user_id),
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS tenant_members_user_idx ON tenant_members(user_id);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id     TEXT REFERENCES users(user_id),
    key_hash    TEXT NOT NULL,
    prefix      TEXT NOT NULL,
    scopes      JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS api_keys_hash_idx  ON api_keys(key_hash);

CREATE TABLE IF NOT EXISTS roles (
    role         TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    permissions  JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS quotas (
    tenant_id       TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
    rpm             INT NOT NULL DEFAULT 60,
    tpm             INT NOT NULL DEFAULT 100000,
    concurrent      INT NOT NULL DEFAULT 4,
    storage_mb      INT NOT NULL DEFAULT 10240,
    allowed_models  JSONB NOT NULL DEFAULT '[]',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usage_ledger (
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
CREATE INDEX IF NOT EXISTS usage_ledger_tenant_ts_idx ON usage_ledger(tenant_id, bucket_hour);

CREATE TABLE IF NOT EXISTS tenant_usage_daily (
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    bucket_day DATE NOT NULL,
    metric     TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    value      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, bucket_day, metric, source)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
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
CREATE INDEX IF NOT EXISTS rt_family_idx      ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS rt_tenant_user_idx ON refresh_tokens(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS rt_expires_idx     ON refresh_tokens(expires_at) WHERE status <> 'revoked';

CREATE TABLE IF NOT EXISTS revoked_jtis (
    jti        TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id    TEXT REFERENCES users(user_id),
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason     TEXT,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS rj_expires_idx ON revoked_jtis(expires_at);

CREATE SEQUENCE IF NOT EXISTS audit_seq_seq;

CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    seq        BIGINT NOT NULL UNIQUE DEFAULT nextval('audit_seq_seq'),
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
CREATE INDEX IF NOT EXISTS audit_log_tenant_ts_idx ON audit_log(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_seq_idx       ON audit_log(seq);

CREATE TABLE IF NOT EXISTS migration_orphans (
    id           BIGSERIAL PRIMARY KEY,
    source_table TEXT NOT NULL,
    source_pk    TEXT NOT NULL,
    reason       TEXT NOT NULL,
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO roles (role, display_name, permissions) VALUES
 ('tenant_admin','Tenant Admin','{"tenants":["read","write"],"users":["read","write"],"quotas":["read","write"],"audit":["read"]}'::jsonb),
 ('operator','Operator','{"models":["read","infer"],"tasks":["read","write"]}'::jsonb),
 ('member','Member','{"models":["infer"],"tasks":["write"]}'::jsonb),
 ('viewer','Viewer','{"models":["read"],"tasks":["read"]}'::jsonb)
ON CONFLICT (role) DO NOTHING;
