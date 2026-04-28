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
CREATE POLICY messages_owner ON app.messages
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = current_setting('app.user', true));  -- not wrapped
