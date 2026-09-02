-- 0002_idp_mfa: identity_providers (G20 OIDC/SCIM) + user_mfa (G21 TOTP)
-- §5.9 + §5.10 of multi-tenant-0902.md

CREATE TABLE IF NOT EXISTS identity_providers (
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
CREATE INDEX IF NOT EXISTS identity_providers_tenant_idx ON identity_providers(tenant_id);

CREATE TABLE IF NOT EXISTS user_mfa (
    user_id     TEXT        NOT NULL REFERENCES users(user_id),
    method      TEXT        NOT NULL,
    secret_enc  TEXT        NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, method)
);
