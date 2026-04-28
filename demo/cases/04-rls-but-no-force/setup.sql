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
CREATE POLICY notes_owner ON app.notes
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
