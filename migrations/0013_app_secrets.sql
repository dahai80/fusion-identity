-- 0013_app_secrets.sql
-- Issue #28: application secret issuance for business apps (AGENTS.md
-- convention #1 — any secret beyond the three business env vars is issued
-- by fusion-identity, never .env key stuffing). Identity stores ONLY the
-- sha256 hash; raw material is returned to the caller exactly once.
-- Versions rotate with a grace window: the demoted version stays readable
-- in `status='grace'` until grace_until, then reads back as 'expired'.
-- Platform table (not tenant-scoped, like users/roles) — no RLS; access is
-- gated by the service token at the app layer.
CREATE TABLE IF NOT EXISTS app_secrets (
    secret_id   TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL,
    version     INTEGER NOT NULL,
    secret_hash TEXT NOT NULL,
    prefix      TEXT NOT NULL,
    status      TEXT NOT NULL,
    grace_until TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_app_secrets_app_version
    ON app_secrets(app_id, version);
CREATE INDEX IF NOT EXISTS ix_app_secrets_app ON app_secrets(app_id);

-- Keep the low-priv role's DML reachability even where 0007's default
-- privileges do not cover this table (e.g. migrations run by another role).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fusion_identity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON app_secrets TO fusion_identity_app;
    END IF;
END
$$;
