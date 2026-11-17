-- Issue #83: username uniqueness. The register route pre-checks duplicates,
-- but concurrent signups race past it (no DB constraint — email had UNIQUE,
-- username never did). Login resolves usernames via a single-row lookup, so
-- a raced duplicate is a login-hijack vector. Safe to apply only after any
-- pre-existing duplicates are merged/deleted (verified none on prod 2026-11-17).
CREATE UNIQUE INDEX IF NOT EXISTS users_username_uniq ON users(username);
