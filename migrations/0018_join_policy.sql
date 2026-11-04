-- Issue #40: tenant join_policy + invite tokens + join requests.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS join_policy TEXT NOT NULL DEFAULT 'invite';

CREATE TABLE IF NOT EXISTS tenant_invites (
    invite_id   TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL DEFAULT 'member',
    email       TEXT,
    created_by  TEXT REFERENCES users(user_id),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    used_by     TEXT REFERENCES users(user_id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tenant_invites_tenant_idx ON tenant_invites(tenant_id);

CREATE TABLE IF NOT EXISTS join_requests (
    request_id   TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT REFERENCES users(user_id),
    decided_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT join_requests_status_chk CHECK (status IN ('pending','approved','rejected','cancelled')),
    CONSTRAINT join_requests_unique_pending UNIQUE (tenant_id, user_id, status)
);
CREATE INDEX IF NOT EXISTS join_requests_tenant_idx ON join_requests(tenant_id);
