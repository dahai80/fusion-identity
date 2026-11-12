-- Issue #76: headless service-account principal for acceptance suites
-- (owner verdict on fusion-site#37: no captcha backdoor — machines
-- authenticate via a pre-provisioned credential exchanged for a
-- short-TTL, tenant-pinned, revocable session token).
CREATE TABLE IF NOT EXISTS service_accounts (
    account_id    TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    scopes        JSONB NOT NULL DEFAULT '[]',
    cred_hash     TEXT NOT NULL UNIQUE,
    prefix        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'revoked')),
    created_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_service_accounts_tenant
    ON service_accounts(tenant_id, created_at);
