-- ============================================================
-- Use case 57: PERF001 with auth wrapped in TypeCast — fires
-- `auth.uid()::text` casts the function result; PERF001 still
-- needs to see the unwrapped call inside. Pins
-- find_func_calls walking through TypeCast.arg.
-- ============================================================

CREATE TABLE app.typecast_auth (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT
);
ALTER TABLE app.typecast_auth ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.typecast_auth FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with auth.uid() wrapped in `(SELECT …)`
-- BEFORE the typecast — PERF001 silent on this policy. The
-- RESTRICTIVE below has the unwrapped form the case
-- demonstrates (auth call inside a TypeCast).
CREATE POLICY typecast_auth_authenticated_access ON app.typecast_auth
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT auth.uid())::text)
    WITH CHECK (user_id = (SELECT auth.uid())::text);
CREATE POLICY auth_cast ON app.typecast_auth
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.uid()::text);
