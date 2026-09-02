-- 0003_concurrency_priority.sql
-- N3 priority + N4 allowed_modules + N2 lease_log (runtime state in Redis, this is ledger only)

ALTER TABLE quotas ADD COLUMN IF NOT EXISTS default_priority int NOT NULL DEFAULT 2;
ALTER TABLE quotas ADD COLUMN IF NOT EXISTS allowed_modules jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS lease_log (
    lease_id        text PRIMARY KEY,
    tenant_id       text NOT NULL,
    request_id      text,
    acquired_at     timestamptz NOT NULL DEFAULT now(),
    released_at     timestamptz,
    release_reason  text
);
CREATE INDEX IF NOT EXISTS idx_lease_log_tenant ON lease_log(tenant_id, acquired_at);
