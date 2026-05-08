-- ============================================================
-- Use case 34: SEC004 nested IS NULL inside AND — CLEAN
-- The rule fires only on TOP-LEVEL OR disjuncts where one is
-- `auth_func() IS NULL`. A nested `... AND auth.uid() IS NULL`
-- must NOT trip SEC004 — the AND-context cannot produce the
-- Lovable CVE bypass (the inverted-USING bug requires the IS
-- NULL to short-circuit a top-level OR).
-- ============================================================

CREATE TABLE app.flags_table (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    flag_name TEXT,
    is_admin BOOLEAN
);
ALTER TABLE app.flags_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.flags_table FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy granting per-user access. No top-level OR
-- with auth IS NULL → SEC004 silent on this policy. The
-- RESTRICTIVE below has the nested IS NULL the case is built
-- to test.
CREATE POLICY flags_table_authenticated_access ON app.flags_table
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT auth.uid()))
    WITH CHECK (user_id = (SELECT auth.uid()));
-- The `(SELECT auth.uid()) IS NULL` test is reachable but lives
-- under a top-level AND (the outer conjunction). SEC004 must
-- skip it — the rule's job is to flag inverted USING shapes
-- where the IS NULL is a top-level OR disjunct that admits
-- anonymous callers wholesale.
CREATE POLICY flags_owner ON app.flags_table
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT auth.uid())
        AND ((SELECT auth.uid()) IS NULL OR is_admin)
    );
