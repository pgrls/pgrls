-- ============================================================
-- Use case 38: PERF001 with `auth.jwt() ->> 'sub'` unwrapped
-- The JSON-text operator wraps a function call. PERF001 walks
-- through `JsonbExtractPathText` (or the `->>` operator's
-- arguments) to find unwrapped auth functions. Pin that.
-- ============================================================

CREATE TABLE app.jwt_unwrapped (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT
);
ALTER TABLE app.jwt_unwrapped ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.jwt_unwrapped FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with auth.jwt() WRAPPED (PERF001 silent).
-- The RESTRICTIVE policy below has the unwrapped `auth.jwt()
-- ->> 'sub'` form the case demonstrates.
CREATE POLICY jwt_unwrapped_authenticated_access ON app.jwt_unwrapped
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT auth.jwt()) ->> 'sub')
    WITH CHECK (user_id = (SELECT auth.jwt()) ->> 'sub');
CREATE POLICY jwt_unwrapped_owner ON app.jwt_unwrapped
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.jwt() ->> 'sub');
