-- Issue #119: tenant-level data classification ledger flag.
-- `standard` (default) = no restriction; `confidential` = tenant content is
-- regulated, downstream consumers (site#196 sensitivity selector, model
-- routing) must keep processing local-only.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS data_classification TEXT NOT NULL DEFAULT 'standard';
