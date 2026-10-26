-- 0011: business-app audit events (issue #18) — events ride the existing
-- audit_log ledger with required fields in detail JSONB (source/trace_id/
-- client_ts/actor/object_id). GIN index so compliance queries filtering on
-- trace_id / actor / object_id stay index-backed instead of seq-scanning.
CREATE INDEX IF NOT EXISTS audit_log_detail_gin
    ON audit_log USING GIN (detail jsonb_path_ops);
