-- ============================================================
-- Use case 7: Session-state-only policy — SEC005
-- Policy expression has no own-column reference. The predicate
-- evaluates the same for every row in the table, so the table is
-- gated by who-asks rather than by which-row.
-- ============================================================

CREATE TABLE app.singletons (
    key TEXT PRIMARY KEY,
    value JSONB
);
ALTER TABLE app.singletons ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.singletons FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy targeting `app_authenticated`. The
-- RESTRICTIVE policy below has no own-column ref (SEC005's
-- catch); this PERMISSIVE has one (`key IS NOT NULL`) so it
-- doesn't itself trip SEC005, and it keeps the table from being
-- silently deny-all (SEC012).
CREATE POLICY singletons_authenticated_access ON app.singletons
    FOR ALL TO app_authenticated
    USING (key IS NOT NULL)
    WITH CHECK (key IS NOT NULL);
CREATE POLICY admin_only ON app.singletons
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (current_setting('app.role', true) = 'admin');
    -- also fires PERF001
