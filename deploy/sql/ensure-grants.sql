-- Issue #94: operator-side privilege backstop. The migration runner grants
-- + probes on every startup (fusion_identity/migrations.py), but when the
-- runner connects AS the app role it cannot grant on tables owned by
-- postgres — this script, run as superuser/owner, is the manual fix:
--   sudo -u postgres psql -d fusion_identity -f deploy/sql/ensure-grants.sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fusion_identity_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO fusion_identity_app;

-- Deployment check: fail loudly listing any table the app role cannot read.
DO $$
DECLARE
    t text;
    missing text := '';
    n int := 0;
BEGIN
    FOR t IN
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
          AND table_name <> 'schema_migrations'
        ORDER BY table_name
    LOOP
        IF NOT has_table_privilege('fusion_identity_app', t, 'SELECT') THEN
            missing := missing || ' ' || t;
            n := n + 1;
        END IF;
    END LOOP;
    IF n > 0 THEN
        RAISE EXCEPTION 'app role fusion_identity_app lacks SELECT on % table(s):%', n, missing;
    END IF;
    RAISE NOTICE 'privilege probe passed: fusion_identity_app can read every public table';
END $$;
