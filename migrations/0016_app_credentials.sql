-- Issue #34: externally-issued SaaS credentials for business-app provider
-- layers (ai-trysuite §8.2 boot injection + 401 re-pull). Unlike app_secrets
-- (issue #28, sha256 hash — raw shown once), these values are chosen by the
-- third-party SaaS and MUST be recoverable by the consumer, so they are
-- stored AES-256-GCM encrypted under the KEK (crypto.encrypt_secret).
-- Platform-scope table (service-token plane, no tenant_id) — same trust level
-- as app_secrets, no RLS policy. Only reachable behind require_service_token.

CREATE TABLE IF NOT EXISTS app_credentials (
    app_id          TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    secret_enc      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    fetch_count     BIGINT      NOT NULL DEFAULT 0,
    last_fetched_at TIMESTAMPTZ,
    PRIMARY KEY (app_id, name)
);
CREATE INDEX IF NOT EXISTS ix_app_credentials_app ON app_credentials(app_id);
