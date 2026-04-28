-- ============================================================
-- Use case 35: SEC005 with literal `USING (1=1)` — fires
-- Not the literal Boolean true but evaluates to it. SEC008's
-- detector keys on the literal Boolean `A_Const`, so the
-- (1=1) shape only fires SEC005 (no own-column reference);
-- SEC008 does NOT fire. Pin the asymmetry.
-- ============================================================

CREATE TABLE app.always_open (
    id BIGSERIAL PRIMARY KEY,
    label TEXT
);
ALTER TABLE app.always_open ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.always_open FORCE ROW LEVEL SECURITY;
CREATE POLICY trivially_open ON app.always_open
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (1 = 1);
