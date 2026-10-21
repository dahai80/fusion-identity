-- Issue #10: department structure + per-department tool permission profiles
-- consumed by enterprise admin consoles (e.g. fusion-cowork).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE departments (
    dept_id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      TEXT        NOT NULL REFERENCES tenants(tenant_id),
    name           TEXT        NOT NULL,
    parent_id      UUID        REFERENCES departments(dept_id),
    tool_allowlist JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX departments_tenant_idx ON departments(tenant_id);

ALTER TABLE departments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON departments
USING (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system')
WITH CHECK (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system');
