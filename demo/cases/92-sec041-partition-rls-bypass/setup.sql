-- ============================================================
-- Use case 92: partition child bypasses parent RLS — SEC041
-- A partitioned table with RLS enabled on the PARENT but a child
-- partition whose own RLS is disabled. Postgres does not inherit
-- row-level security to partitions, so a query that names the child
-- directly (a PostgREST request on it, or a direct SELECT) bypasses
-- the parent's policy and returns every row. SEC041 fires on the
-- RLS-off child. A sibling child that enables RLS (with its own
-- policy) stays SILENT — the rule's boundary, pinned through live
-- introspection. SEC001 cedes both children because the parent has
-- RLS, so SEC041 is the only rule that surfaces the bypass.
-- ============================================================

CREATE TABLE app.uc92_events (
    tenant_id BIGINT NOT NULL,
    body TEXT
) PARTITION BY LIST (tenant_id);
ALTER TABLE app.uc92_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc92_events FORCE ROW LEVEL SECURITY;
CREATE POLICY uc92_tenant ON app.uc92_events
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint));

-- The bug: this child has NO RLS and is granted directly to the app role,
-- so a query naming it bypasses the parent's policy. SEC041 fires here.
CREATE TABLE app.uc92_events_t1 PARTITION OF app.uc92_events
    FOR VALUES IN (1);
GRANT SELECT ON app.uc92_events_t1 TO app_authenticated;

-- The fix: this sibling child enables RLS and re-applies the policy, so a
-- direct query on it is still scoped. SEC041 stays silent here.
CREATE TABLE app.uc92_events_t2 PARTITION OF app.uc92_events
    FOR VALUES IN (2);
ALTER TABLE app.uc92_events_t2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc92_events_t2 FORCE ROW LEVEL SECURITY;
CREATE POLICY uc92_tenant_t2 ON app.uc92_events_t2
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint));
-- Granted directly like t1, but its own RLS is enabled — so SEC041 stays
-- silent here (the silence is the RLS, not the absence of a grant).
GRANT SELECT ON app.uc92_events_t2 TO app_authenticated;
