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
CREATE POLICY public_flags ON app.feature_flags
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (true);  -- also fires SEC005
