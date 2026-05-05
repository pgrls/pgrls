-- ============================================================
-- Use case 85: Non-`security_invoker` view over RLS table — VIEW001
-- The view runs queries with the view owner's privileges, NOT the
-- caller's. RLS on `app.uc85_users` is evaluated against the view
-- owner (typically a privileged migration role), so referenced
-- rows leak past the per-tenant boundary. `security_barrier = true`
-- is set so VIEW002 does NOT co-fire.
-- ============================================================

CREATE TABLE app.uc85_users (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    display_name TEXT
);
ALTER TABLE app.uc85_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc85_users FORCE ROW LEVEL SECURITY;
CREATE POLICY p_uc85 ON app.uc85_users
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant_id', true))::UUID
    );

CREATE VIEW app.uc85_user_summary
    WITH (security_barrier = true)
    AS SELECT id, display_name FROM app.uc85_users;
