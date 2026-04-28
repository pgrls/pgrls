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
CREATE POLICY jwt_unwrapped_owner ON app.jwt_unwrapped
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.jwt() ->> 'sub');
