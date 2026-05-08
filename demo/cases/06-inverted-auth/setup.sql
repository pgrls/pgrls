-- ============================================================
-- Use case 6: Inverted auth — SEC004
-- A top-level OR with `current_setting() IS NULL`. When the
-- session variable isn't set (fresh connection, misconfigured
-- pool), the predicate is true for every row. This is the shape
-- of the public Lovable RLS CVE.
-- ============================================================

CREATE TABLE app.accounts (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    balance_cents INT
);
ALTER TABLE app.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.accounts FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy gating access to authenticated app users. The
-- buggy RESTRICTIVE policy below is what SEC004 catches; this
-- PERMISSIVE exists so the RESTRICTIVE-only shape doesn't make the
-- table silently deny-all (SEC012).
CREATE POLICY accounts_authenticated_access ON app.accounts
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY allow_unset_user ON app.accounts
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        current_setting('app.user', true) IS NULL
        OR user_id = current_setting('app.user', true)
    );  -- also fires PERF001 (current_setting unwrapped)
