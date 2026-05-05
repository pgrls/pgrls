-- ============================================================
-- Use case 86: Non-`security_barrier` view over RLS table — VIEW002
-- Without `security_barrier = true`, the planner is free to push a
-- caller-supplied predicate (e.g. a volatile `leak()` in WHERE)
-- below the view's RLS-derived filter, leaking rows from
-- `app.uc86_users` before the policy applies. `security_invoker
-- = true` is set so VIEW001 does NOT co-fire.
-- ============================================================

CREATE TABLE app.uc86_users (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    email TEXT
);
ALTER TABLE app.uc86_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc86_users FORCE ROW LEVEL SECURITY;
CREATE POLICY p_uc86 ON app.uc86_users
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant_id', true))::UUID
    );

CREATE VIEW app.uc86_user_summary
    WITH (security_invoker = true)
    AS SELECT id, email FROM app.uc86_users;
