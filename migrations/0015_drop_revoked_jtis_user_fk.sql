-- 0015_drop_revoked_jtis_user_fk.sql
-- Same bug class as 0014, second site, found live-verifying issue #29's
-- DELETE /auth/sessions: revoked_jtis.user_id carried a FK to users(user_id)
-- (0001 baseline), so revoking a SYNTHETIC session principal (no users row)
-- raised ForeignKeyViolationError — the revocation endpoint 500'd exactly
-- when it was supposed to kill the token. user_id on revoked_jtis is a
-- principal label mirroring issued_jtis (which has no FK since 0014); drop
-- it. The tenants FK stays.
ALTER TABLE revoked_jtis DROP CONSTRAINT IF EXISTS revoked_jtis_user_id_fkey;
