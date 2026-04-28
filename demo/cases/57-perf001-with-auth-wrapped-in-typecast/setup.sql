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
CREATE POLICY auth_cast ON app.typecast_auth
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.uid()::text);
