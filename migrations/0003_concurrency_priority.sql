-- 0003_concurrency_priority.sql
-- N3 priority + N4 allowed_modules + N2 lease_log (runtime state in Redis, this is ledger only)

ALTER TABLE quotas ADD COLUMN IF NOT EXISTS default_priority int NOT NULL DEFAULT 0;
ALTER TABLE quotas ADD COLUMN IF NOT EXISTS allowed_modules jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS lease_log (
    id         BIGSERIAL PRIMARY KEY,
    tenant_id  TEXT        NOT NULL,
    lease_id   TEXT        NOT NULL,
    action     TEXT        NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT lease_action_chk CHECK (action IN ('acquire','release','expire'))
);

CREATE INDEX IF NOT EXISTS lease_log_tenant_idx ON lease_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS lease_log_lease_idx ON lease_log(lease_id);
