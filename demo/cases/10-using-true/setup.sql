-- ============================================================
-- Use case 10: USING (true) — SEC008 (permissive) vs SEC031 (restrictive)
-- A policy whose USING is the literal `true` adds no protection,
-- but the failure differs by policy kind: on a PERMISSIVE policy it
-- admits every row (SEC008); on a RESTRICTIVE policy it AND-combines
-- to a no-op floor that enforces nothing (SEC031). Both shapes appear
-- here, on an isolated table.
-- ============================================================

CREATE TABLE app.feature_flags (
    name TEXT PRIMARY KEY,
    enabled BOOLEAN
);
ALTER TABLE app.feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.feature_flags FORCE ROW LEVEL SECURITY;
-- Real permissive policy. References the own `name` column so SEC005
-- doesn't fire on it; FOR ALL keeps the table off SEC022.
CREATE POLICY feature_flags_authenticated_access ON app.feature_flags
    FOR ALL TO app_authenticated
    USING (name IS NOT NULL)
    WITH CHECK (name IS NOT NULL);
-- Permissive USING (true) → SEC008 (admits every row). Granted TO
-- app_authenticated (not PUBLIC) so SEC003 stays quiet. Also fires
-- SEC005 (no own-column reference).
CREATE POLICY open_perm ON app.feature_flags
    FOR SELECT TO app_authenticated
    USING (true);
-- Restrictive USING (true) → SEC031, the no-op floor: it looks like a
-- boundary but AND-combines to nothing. Also fires SEC005.
CREATE POLICY public_flags ON app.feature_flags
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (true);
