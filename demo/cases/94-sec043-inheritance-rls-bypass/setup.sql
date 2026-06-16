-- ============================================================
-- Use case 94: classic-inheritance child bypasses parent RLS — SEC043
-- A table with RLS enabled on the PARENT but a child created via
-- `CREATE TABLE child () INHERITS (parent)` (classic inheritance, NOT a
-- declarative partition) whose own RLS is disabled. Postgres does not
-- inherit row-level security to inheritance children, so a query that
-- names the child directly (a PostgREST request on it, or a direct
-- SELECT) bypasses the parent's policy and returns every row. SEC043
-- fires on the RLS-off child. A sibling child that enables its own RLS
-- (with its own policy) stays SILENT — the rule's boundary, pinned
-- through live introspection. This is the classic-INHERITS analogue of
-- use case 92 (SEC041, declarative partitions).
--
-- Unlike the partition case, SEC001 ALSO fires on the RLS-off child
-- here: SEC001/SEC032 do not walk classic inheritance, so they do not
-- cede it. Both findings are correct and point to the same fix (enable
-- RLS on the child); SEC043 adds the bypass/reachability context. These
-- tests assert SEC043's own firing/silence — the SEC001 double-report is
-- expected and documented.
-- ============================================================

CREATE TABLE app.uc94_events (
    tenant_id BIGINT NOT NULL,
    body TEXT
);
ALTER TABLE app.uc94_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc94_events FORCE ROW LEVEL SECURITY;
CREATE POLICY uc94_tenant ON app.uc94_events
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint));

-- The bug: this child inherits from the RLS parent (classic INHERITS) but
-- has NO RLS of its own and is granted directly to the app role, so a
-- query naming it bypasses the parent's policy. SEC043 fires here.
CREATE TABLE app.uc94_events_legacy () INHERITS (app.uc94_events);
GRANT SELECT ON app.uc94_events_legacy TO app_authenticated;

-- The fix: this sibling child also inherits from the parent but enables
-- its own RLS and re-applies the policy, so a direct query on it is still
-- scoped. SEC043 stays silent here.
CREATE TABLE app.uc94_events_scoped () INHERITS (app.uc94_events);
ALTER TABLE app.uc94_events_scoped ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc94_events_scoped FORCE ROW LEVEL SECURITY;
CREATE POLICY uc94_tenant_scoped ON app.uc94_events_scoped
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint));
-- Granted directly like the legacy child, but its own RLS is enabled — so
-- SEC043 stays silent here (the silence is the RLS, not the absence of a
-- grant).
GRANT SELECT ON app.uc94_events_scoped TO app_authenticated;
