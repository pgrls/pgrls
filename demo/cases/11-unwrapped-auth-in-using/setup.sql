-- ============================================================
-- Use case 11: Unwrapped auth in USING — PERF001
-- `current_setting(...)` (or `auth.uid()` etc.) called inline is
-- re-evaluated per row. Wrap in `(SELECT ...)` so Postgres caches
-- it once per statement.
-- ============================================================

CREATE TABLE app.messages (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    body TEXT
);
ALTER TABLE app.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.messages FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with the *correctly wrapped* form for
-- contrast — pgrls expects this to NOT fire PERF001. The
-- RESTRICTIVE policy below has the unwrapped call (the rule's
-- catch). Keeping both side-by-side makes the right-vs-wrong
-- shape visible in one fixture.
CREATE POLICY messages_authenticated_access ON app.messages
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY messages_owner ON app.messages
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = current_setting('app.user', true));  -- not wrapped
