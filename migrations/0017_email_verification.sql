-- Issue #39: email verification for public registration. Default TRUE so
-- every pre-existing user (created via provisioning/SCIM/members APIs) keeps
-- logging in unchanged — only public signups after this migration can be
-- created unverified. The verify token is stored hashed (sha256), single use,
-- expiring; successful verification clears both columns.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS email_verify_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS email_verify_expires TIMESTAMPTZ;
