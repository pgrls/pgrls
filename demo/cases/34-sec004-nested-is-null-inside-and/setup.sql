-- ============================================================
-- Use case 34: SEC004 nested IS NULL inside AND — CLEAN
-- The rule fires only on TOP-LEVEL OR disjuncts where one is
-- `auth_func() IS NULL`. A nested `... AND auth.uid() IS NULL`
-- (or `IS NULL` on a non-auth function) must NOT trip SEC004.
-- ============================================================

CREATE TABLE app.flags_table (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    flag_name TEXT
);
ALTER TABLE app.flags_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.flags_table FORCE ROW LEVEL SECURITY;
CREATE POLICY flags_owner ON app.flags_table
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT auth.uid())
        AND flag_name IS NOT NULL
    );
