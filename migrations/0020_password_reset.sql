-- Issue #54: self-service password recovery. Reset token stored hashed
-- (sha256), single use, expiring; successful reset clears both columns.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_reset_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMPTZ;
