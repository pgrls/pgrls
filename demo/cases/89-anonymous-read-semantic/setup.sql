-- ============================================================
-- Use case 89: Semantic anonymous-read leak — SEC038
-- The inverted-auth hole of use case 6, but in a NOT-wrapped
-- form that SEC004's syntactic `auth() IS NULL` matcher cannot
-- see: `NOT ((SELECT auth.uid()) IS NOT NULL)` is semantically
-- `auth.uid() IS NULL`. Under an anonymous session auth.uid()
-- returns NULL, so the disjunct is TRUE for every row and the
-- policy reads all rows — the same Lovable-CVE class as uc06,
-- only obfuscated. SEC038 (the Z3-backed semantic check) proves
-- the USING is unconditionally TRUE under anon and fires;
-- syntactic SEC004 stays silent on this shape, which is exactly
-- the value the semantic rule adds.
-- ============================================================

CREATE TABLE app.anon_reports (
    id BIGSERIAL PRIMARY KEY,
    owner_id UUID NOT NULL,
    body TEXT
);
ALTER TABLE app.anon_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.anon_reports FORCE ROW LEVEL SECURITY;
-- The intended per-user access policy. Correct on its own.
CREATE POLICY anon_reports_owner_access ON app.anon_reports
    FOR ALL TO app_authenticated
    USING (owner_id = (SELECT auth.uid()))
    WITH CHECK (owner_id = (SELECT auth.uid()));
-- The buggy policy: a NOT-wrapped inverted-auth disjunct. SEC004
-- misses it (no literal `auth() IS NULL`); SEC038 proves it is
-- anon-valid and fires. PERMISSIVE + FOR SELECT so it is
-- read-capable (SEC038 only inspects read-capable permissive
-- policies).
CREATE POLICY anon_reports_leaky_read ON app.anon_reports
    FOR SELECT TO app_authenticated
    USING (
        NOT ((SELECT auth.uid()) IS NOT NULL)
        OR owner_id = (SELECT auth.uid())
    );
