-- Issue #14: tenant provisioning automation — plan quota templates (M-C),
-- provisioning idempotency keys (M-A), lifecycle event outbox (M-B).
-- `tpm` is the DAILY token limit (legacy field name, kept for compatibility).

CREATE TABLE plan_templates (
    plan       TEXT        NOT NULL PRIMARY KEY,
    quota      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE idempotency_keys (
    idem_key   TEXT        NOT NULL PRIMARY KEY,
    endpoint   TEXT        NOT NULL,
    response   JSONB       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE event_outbox (
    event_id   TEXT        NOT NULL PRIMARY KEY,
    seq        BIGSERIAL   NOT NULL UNIQUE,
    event_type TEXT        NOT NULL,
    tenant_id  TEXT        NOT NULL REFERENCES tenants(tenant_id),
    payload    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    status     TEXT        NOT NULL DEFAULT 'pending',
    attempts   INT         NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_event_outbox_status_seq ON event_outbox(status, seq);

-- Seed the built-in plan templates so PgStore sees the same defaults as
-- InMemoryStore's PLAN_TEMPLATES.
INSERT INTO plan_templates(plan, quota) VALUES
    ('free',       '{"rpm": 10, "tpm": 20000, "concurrent": 2, "storage_mb": 1024, "allowed_models": [], "allowed_modules": [], "default_priority": 0}'),
    ('starter',    '{"rpm": 30, "tpm": 50000, "concurrent": 3, "storage_mb": 5120, "allowed_models": [], "allowed_modules": [], "default_priority": 0}'),
    ('standard',   '{"rpm": 60, "tpm": 100000, "concurrent": 4, "storage_mb": 10240, "allowed_models": [], "allowed_modules": [], "default_priority": 0}'),
    ('pro',        '{"rpm": 200, "tpm": 1000000, "concurrent": 16, "storage_mb": 51200, "allowed_models": [], "allowed_modules": [], "default_priority": 1}'),
    ('enterprise', '{"rpm": 1000, "tpm": 10000000, "concurrent": 64, "storage_mb": 204800, "allowed_models": [], "allowed_modules": [], "default_priority": 2}')
ON CONFLICT (plan) DO NOTHING;

ALTER TABLE event_outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON event_outbox
USING (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system')
WITH CHECK (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system');

-- plan_templates and idempotency_keys are platform-scope tables (service-token
-- admin plane only, no tenant_id) — same trust level as schema_migrations, no
-- RLS policy. They are only reachable behind require_service_token.
