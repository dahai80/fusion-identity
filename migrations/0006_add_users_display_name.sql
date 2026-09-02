-- 0006_add_users_display_name.sql
-- P0-1: InMemoryStore.update_user persists display_name but the users table had
-- no display_name column, so PgStore.update_user silently dropped SCIM
-- displayName on the production backend. Add the column so SCIM POST/PATCH
-- displayName survives a Postgres round-trip. Nullable: legacy rows have none.

ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
