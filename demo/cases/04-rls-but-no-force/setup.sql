-- ============================================================
-- Use case 4: RLS but no FORCE — SEC002
-- ENABLE without FORCE. The table owner role bypasses RLS, which
-- masks broken policies in dev/CI when the migration tool is the
-- owner.
-- ============================================================

CREATE TABLE app.notes (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    content TEXT
);
ALTER TABLE app.notes ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE app.notes FORCE ROW LEVEL SECURITY;  -- intentionally omitted
-- Canonical PERMISSIVE policy targeting `app_authenticated` (created
-- in `_shared.sql`). Without it, the RESTRICTIVE-only shape below
-- would be silently deny-all (SEC012). Adding the PERMISSIVE keeps
-- this case demonstrating SEC002 (no FORCE) without bringing in
-- SEC012 noise.
CREATE POLICY notes_authenticated_access ON app.notes
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY notes_owner ON app.notes
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
