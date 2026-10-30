-- 0012_single_database_convergence.sql
-- Issue #26 (DB conventions DB-2: one app, one database): fusion_identity is
-- the single canonical database. This migration heals existing deployments
-- where 0007 recorded itself as applied but its hard-coded
-- "ALTER DATABASE fusion_tenant" mis-targeted the legacy database, leaving
-- fusion_identity without the platform-scope GUC default — every
-- fusion_identity_app session on RLS tables would fail on
-- current_setting('app.current_tenant') being unset.
-- Idempotent and database-agnostic: targets whatever DB it runs against.
DO $$
BEGIN
    EXECUTE format(
        'ALTER DATABASE %I SET app.current_tenant = %L',
        current_database(), '_system'
    );
END
$$;
