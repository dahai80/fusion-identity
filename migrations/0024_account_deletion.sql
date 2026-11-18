-- Issue #91: self-service account deletion with a 7-day grace window.
-- The users row stays intact until the purge deadline; login and bearer
-- verification consult this table and refuse service while a deletion is
-- pending. Cancelling removes the row and restores full access.
CREATE TABLE IF NOT EXISTS account_deletions (
    user_id      TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    purge_at     TIMESTAMPTZ NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS account_deletions_purge_idx
    ON account_deletions(purge_at) WHERE status = 'pending';
