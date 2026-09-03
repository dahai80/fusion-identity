-- 0007_rls_strong_isolation.sql
-- PRD red-line #3 strong layer: Postgres Row-Level Security.
-- Defense-in-depth under the app-layer guard (require_tenant_admin_of).
-- Tenant-scoped tables get a policy gated on the app.current_tenant GUC.
-- GUC '_system' is the sentinel for platform/admin queries that must span
-- tenants (login, refresh, api-key-by-hash, admin plane, stats). The default
-- is '_system' so the existing single-role service connection keeps working;
-- a dedicated non-superuser role (fusion_identity_app) is what actually
-- enforces RLS — superusers and BYPASSRLS roles bypass it by Postgres rule.
--
-- Per-request tenant GUC activation (SET LOCAL app.current_tenant inside a
-- request-scoped transaction) is a tracked follow-up: it requires PgStore to
-- hold one connection across a request instead of acquiring per-call. Until
-- then the app-layer guard remains the primary cross-tenant enforcement
-- point and RLS is the backstop that fails closed if a query ever drops its
-- WHERE tenant_id filter while running as the low-priv role.

-- Default the GUC at the database level so every session starts in the
-- platform sentinel scope (sees all tenants) unless a caller explicitly
-- narrows it. Fail-safe: an unset GUC must not silently hide everything.
ALTER DATABASE fusion_tenant SET app.current_tenant = '_system';

-- Dedicated non-superuser role the service should connect as in production.
-- Superusers bypass RLS, so the operator's own admin account does NOT enforce
-- it; only fusion_identity_app (or any role granted it) does. Created in a DO
-- block so re-running the migration is idempotent.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fusion_identity_app') THEN
        CREATE ROLE fusion_identity_app LOGIN PASSWORD 'change-me-operator-rotates';
    END IF;
END
$$;

-- Grants: the low-priv role needs full DML on tenant-scoped tables and the
-- platform tables it touches (users, roles, user_mfa, audit_log already
-- covered above, migration_orphans, schema_migrations). Revoked-by-default
-- public privileges are re-granted explicitly so the role is least-privilege.
GRANT USAGE ON SCHEMA public TO fusion_identity_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fusion_identity_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fusion_identity_app;
-- Keep future tables reachable (migrations 0008+) without manual re-grant.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO fusion_identity_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO fusion_identity_app;

-- Enable + FORCE RLS on every tenant-scoped table. FORCE matters: it makes
-- the table owner subject to RLS too, so even a connection that owns the
-- tables cannot bypass the policy (only BYPASSRLS roles/superusers can).
-- Policies are dropped-if-exists first so re-apply never conflicts.
CREATE POLICY tenant_isolation ON tenant_members
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON api_keys
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON quotas
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON usage_ledger
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON tenant_usage_daily
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON refresh_tokens
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON revoked_jtis
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON issued_jtis
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON audit_log
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON identity_providers
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');
CREATE POLICY tenant_isolation ON lease_log
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');

-- The tenants table is keyed BY tenant_id (it is the PK, not a column among
-- many), so its policy compares the row's own tenant_id to the GUC.
CREATE POLICY tenant_isolation ON tenants
    USING (tenant_id = current_setting('app.current_tenant')
           OR current_setting('app.current_tenant') = '_system')
    WITH CHECK (tenant_id = current_setting('app.current_tenant')
                OR current_setting('app.current_tenant') = '_system');

-- Platform tables (users, roles, user_mfa, migration_orphans,
-- schema_migrations) are intentionally NOT under RLS: they are shared across
-- tenants by PRD design (a user may belong to several tenants; roles are
-- global; MFA is per-user not per-tenant). Their cross-tenant exposure is
-- governed by the app layer, not the DB strong layer.

-- Enable + FORCE last so policies exist before enforcement flips on. FORCE
-- is set after policy creation to avoid a window where the owner is locked
-- out mid-migration. The list mirrors the policy targets above.
ALTER TABLE tenant_members       ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys             ENABLE ROW LEVEL SECURITY;
ALTER TABLE quotas               ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_ledger         ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_usage_daily   ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens       ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_jtis         ENABLE ROW LEVEL SECURITY;
ALTER TABLE issued_jtis          ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log            ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_providers   ENABLE ROW LEVEL SECURITY;
ALTER TABLE lease_log            ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants              ENABLE ROW LEVEL SECURITY;

ALTER TABLE tenant_members       FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys             FORCE ROW LEVEL SECURITY;
ALTER TABLE quotas               FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_ledger         FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_usage_daily   FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens       FORCE ROW LEVEL SECURITY;
ALTER TABLE revoked_jtis         FORCE ROW LEVEL SECURITY;
ALTER TABLE issued_jtis          FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log            FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_providers   FORCE ROW LEVEL SECURITY;
ALTER TABLE lease_log            FORCE ROW LEVEL SECURITY;
ALTER TABLE tenants              FORCE ROW LEVEL SECURITY;
