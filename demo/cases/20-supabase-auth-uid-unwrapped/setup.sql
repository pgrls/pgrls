-- ============================================================
-- Use case 20: Supabase auth.uid() unwrapped — PERF001
-- Inline `auth.uid()` is re-evaluated per row. Wrap as
-- `(SELECT auth.uid())` to let Postgres cache the result
-- once per statement.
-- ============================================================

CREATE TABLE app.todos (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    body TEXT
);
ALTER TABLE app.todos ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.todos FORCE ROW LEVEL SECURITY;
CREATE POLICY todos_owner ON app.todos
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.uid());  -- not wrapped
