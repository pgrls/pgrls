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
-- PERMISSIVE policy referencing the own `visibility` column so
-- SEC005 stays silent. `visibility IS NOT NULL` is a benign own-
-- column predicate, no auth involved → PERF001 / SEC004 silent.
CREATE POLICY current_user_check_authenticated_access ON app.current_user_check
    FOR ALL TO app_authenticated
    USING (visibility IS NOT NULL)
    WITH CHECK (visibility IS NOT NULL);
CREATE POLICY only_admin_role ON app.current_user_check
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (current_user = 'postgres' OR visibility = 'public');
