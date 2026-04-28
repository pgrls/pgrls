-- ============================================================
-- Use case 76: SEC011 — `OR true` branch hidden in policy
-- The `id = 1 OR true` predicate evaluates to `true` for every
-- row regardless of `id`. Almost always a leftover debug branch
-- ("temporarily let everything through"). SEC008 catches the
-- literal at the top level; SEC011 catches the same effect
-- buried inside a larger expression.
-- ============================================================

CREATE TABLE app.or_true_table (
    id BIGSERIAL,
    user_id TEXT,
    payload TEXT
);
ALTER TABLE app.or_true_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.or_true_table FORCE ROW LEVEL SECURITY;
CREATE POLICY debug_branch_left_in ON app.or_true_table
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT current_setting('app.user', true))
        OR true  -- forgotten debug bypass
    );
