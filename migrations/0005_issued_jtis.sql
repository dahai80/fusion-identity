-- 0005_issued_jtis.sql — F4 cross-tenant jti revocation DoS
-- Records the tenant/user each access-token jti was issued to so /revoke can
-- assert the jti belongs to the caller's tenant before revoking.
CREATE TABLE IF NOT EXISTS issued_jtis (
    jti        TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(tenant_id),
    user_id    TEXT NOT NULL REFERENCES users(user_id),
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ij_expires_idx ON issued_jtis(expires_at);
