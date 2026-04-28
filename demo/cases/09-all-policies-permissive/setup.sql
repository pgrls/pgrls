-- ============================================================
-- Use case 9: All policies permissive — SEC007 (info)
-- Single permissive policy, no restrictive floor. A restrictive
-- policy combines with AND, which gives you a hard floor (e.g.
-- "tenant_id must match") that no future permissive policy can
-- bypass via OR.
-- ============================================================

CREATE TABLE app.tags (
    id BIGSERIAL PRIMARY KEY,
    name TEXT
);
ALTER TABLE app.tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tags FORCE ROW LEVEL SECURITY;
CREATE POLICY tags_visible ON app.tags
    FOR SELECT TO PUBLIC
    USING (true);  -- also fires SEC003, SEC005, SEC008
