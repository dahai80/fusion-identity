-- Issue #99/#101 (flywheel Loop A): per-user data-reflow opt-out.
-- TRUE (default) = desensitized reflow allowed; FALSE = counters only,
-- zero prompt-text storage for this user anywhere in the pipeline.
ALTER TABLE users ADD COLUMN IF NOT EXISTS data_reflow_enabled BOOLEAN NOT NULL DEFAULT TRUE;
