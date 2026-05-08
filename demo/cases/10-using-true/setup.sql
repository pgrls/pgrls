-- ============================================================
-- Use case 10: USING (true) — SEC008
-- A policy whose USING is the literal `true` adds no protection;
-- it is almost always a leftover from prototyping. Wrapped here
-- in an isolated table (RESTRICTIVE so SEC003 doesn't fire).
-- ============================================================

CREATE TABLE app.feature_flags (
    name TEXT PRIMARY KEY,
    enabled BOOLEAN
);
ALTER TABLE app.feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.feature_flags FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy targeting `app_authenticated`. References
-- the own `name` column so SEC005 doesn't fire on this policy.
-- The buggy RESTRICTIVE policy below is what SEC008 catches.
CREATE POLICY feature_flags_authenticated_access ON app.feature_flags
    FOR ALL TO app_authenticated
    USING (name IS NOT NULL)
    WITH CHECK (name IS NOT NULL);
CREATE POLICY public_flags ON app.feature_flags
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (true);  -- also fires SEC005
