-- Issue #12 (Migration E5): RBAC contract generalization — per-tenant custom
-- roles with write classes + runtime-editable role <-> menu permission matrix.
CREATE TABLE custom_roles (
    role_id       TEXT        NOT NULL,
    tenant_id     TEXT        NOT NULL REFERENCES tenants(tenant_id),
    display_name  TEXT        NOT NULL,
    write_classes JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, role_id)
);

CREATE TABLE role_menu_matrix (
    tenant_id  TEXT        NOT NULL REFERENCES tenants(tenant_id),
    role_id    TEXT        NOT NULL,
    menus      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, role_id)
);

CREATE TABLE known_menus (
    tenant_id  TEXT        NOT NULL REFERENCES tenants(tenant_id),
    menu       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, menu)
);

ALTER TABLE custom_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON custom_roles
USING (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system')
WITH CHECK (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system');

ALTER TABLE role_menu_matrix ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON role_menu_matrix
USING (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system')
WITH CHECK (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system');

ALTER TABLE known_menus ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON known_menus
USING (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system')
WITH CHECK (tenant_id = current_setting('app.current_tenant')
OR current_setting('app.current_tenant') = '_system');
