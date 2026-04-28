-- ============================================================
-- Use case 39: Custom auth function — config-driven detection
-- An app-defined function (`app.current_user_id()`) wrapping
-- a session GUC. By default PERF001 doesn't know about it, so
-- this table is silent. The companion test invokes pgrls with
-- a one-off config that adds `app.current_user_id` to
-- PERF001's `auth_functions` list — at which point PERF001
-- catches the unwrapped call here.
-- ============================================================

CREATE FUNCTION app.current_user_id() RETURNS UUID
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('app.user', true)::UUID $$;

CREATE TABLE app.user_workspaces (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID
);
ALTER TABLE app.user_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.user_workspaces FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_owner ON app.user_workspaces
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = app.current_user_id());
