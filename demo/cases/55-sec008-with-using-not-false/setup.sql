-- ============================================================
-- Use case 55: SEC008 with `USING (NOT false)` — CLEAN
-- Logically equivalent to `USING (true)` but the AST is a
-- BoolExpr (NOT) over an A_Const, NOT a literal Boolean.
-- SEC008's detector keys on the literal True A_Const, so this
-- shape stays silent. Pin the asymmetry so the detector
-- doesn't drift toward semantic equivalence.
-- ============================================================

CREATE TABLE app.not_false_table (
    id BIGSERIAL PRIMARY KEY,
    label TEXT
);
ALTER TABLE app.not_false_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.not_false_table FORCE ROW LEVEL SECURITY;
CREATE POLICY not_false ON app.not_false_table
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (NOT false);
