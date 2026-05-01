-- ============================================================
-- Use case 88: View through SECDEF function reading RLS table — VIEW004
-- The view's body calls a SECURITY DEFINER function that reads from
-- `app.uc88_users`. The function runs with the function owner's
-- privileges, so RLS on the underlying table is evaluated against
-- the function owner — NOT the calling user — even though the view
-- itself has `security_invoker = true`. Both VIEW001 and VIEW002 are
-- set so they do NOT co-fire; only VIEW004 fires here.
-- ============================================================

CREATE TABLE app.uc88_users (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    email TEXT
);
ALTER TABLE app.uc88_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc88_users FORCE ROW LEVEL SECURITY;
CREATE POLICY p_uc88 ON app.uc88_users
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant_id', true))::UUID
    );

CREATE FUNCTION app.uc88_read_users() RETURNS SETOF app.uc88_users
    LANGUAGE sql SECURITY DEFINER
    AS $$ SELECT * FROM app.uc88_users $$;

CREATE VIEW app.uc88_user_summary
    WITH (security_invoker = true, security_barrier = true)
    AS SELECT id, email FROM app.uc88_read_users();
