-- Issue #48: one-time SSO ticket exchange (cloud-try Phase 2).
CREATE TABLE IF NOT EXISTS sso_tickets (
    ticket_hash TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sso_tickets_tenant_idx ON sso_tickets(tenant_id);
