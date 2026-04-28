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
CREATE POLICY admin_only ON app.singletons
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (current_setting('app.role', true) = 'admin');
    -- also fires PERF001
