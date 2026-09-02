-- 0004_usage_model_dimension.sql
-- F19: record_usage collapsed the model dimension into one row per
-- (tenant, hour, metric, source) because the unique/upsert target omitted model.
-- Drop the old unique constraint and add one including model so per-model
-- usage buckets are preserved.

ALTER TABLE usage_ledger
    DROP CONSTRAINT IF EXISTS usage_ledger_tenant_id_bucket_hour_metric_source_key;

ALTER TABLE usage_ledger
    DROP CONSTRAINT IF EXISTS usage_ledger_tenant_id_bucket_hour_metric_source_model_key;

-- P2-13: ADD CONSTRAINT has no IF NOT EXISTS in Postgres. A crash-retry after
-- the constraint was added but the version row was not recorded would raise
-- duplicate_constraint and wedge the migration. Guard with an existence check
-- so the migration is idempotent.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'usage_ledger_tenant_id_bucket_hour_metric_source_model_key'
    ) THEN
        ALTER TABLE usage_ledger
            ADD CONSTRAINT usage_ledger_tenant_id_bucket_hour_metric_source_model_key
            UNIQUE (tenant_id, bucket_hour, metric, source, model);
    END IF;
END $$;
