-- ============================================================
-- Use case 19: Supabase auth.uid() inverted — SEC004
-- The exact shape of the public Lovable RLS CVE: a top-level
-- OR with `auth.uid() IS NULL` lets anonymous connections see
-- every row. Distinct from use case 06 only in the function
-- name; pgrls's default `auth_functions` list covers both.
-- ============================================================

CREATE TABLE app.profiles (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    display_name TEXT
);
ALTER TABLE app.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.profiles FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy gating per-user access via Supabase's
-- `auth.uid()`. Wrapped in `(SELECT ...)` so PERF001 doesn't
-- fire on this policy. The buggy RESTRICTIVE policy below is
-- what SEC004 catches.
CREATE POLICY profiles_authenticated_access ON app.profiles
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT auth.uid()))
    WITH CHECK (user_id = (SELECT auth.uid()));
CREATE POLICY allow_anon ON app.profiles
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (auth.uid() IS NULL OR user_id = auth.uid());
    -- also fires PERF001 (auth.uid unwrapped)
