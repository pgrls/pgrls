-- ============================================================
-- Use case 44: SQLValueFunction `current_user` in policy —
-- CLEAN against PERF001
-- `current_user` is in SEC004's default auth_functions set
-- but NOT in PERF001's. Postgres evaluates SQLValueFunctions
-- like `current_user` cheaply, so wrapping buys nothing — the
-- rule deliberately omits them. Pin the asymmetry from a real
-- DB rather than only the unit test in test_perf001.py.
-- ============================================================

CREATE TABLE app.current_user_check (
    id BIGSERIAL PRIMARY KEY,
    visibility TEXT
);
ALTER TABLE app.current_user_check ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.current_user_check FORCE ROW LEVEL SECURITY;
CREATE POLICY only_admin_role ON app.current_user_check
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (current_user = 'postgres' OR visibility = 'public');
