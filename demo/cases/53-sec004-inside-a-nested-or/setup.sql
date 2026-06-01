-- ============================================================
-- Use case 53: SEC004 inside a nested OR — now caught.
-- OR is associative, so `auth_func() IS NULL` buried inside a
-- parenthesized nested OR is the same anonymous-access hole as
-- the flat form. SEC004 now flattens nested OR disjuncts
-- (ast_utils.flatten_or_disjuncts) before the IS NULL check, so
-- it fires on the `nested_or` policy below — previously a
-- documented false negative. Flattening stops at AND / NOT /
-- subqueries, so an IS NULL gated by an AND is still not flagged.
-- ============================================================

CREATE TABLE app.nested_or_check (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    flag TEXT
);
ALTER TABLE app.nested_or_check ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.nested_or_check FORCE ROW LEVEL SECURITY;
-- Policy with a flat predicate (no OR with auth IS NULL) —
-- SEC004 stays silent. The nested-OR shape that SEC004 now
-- catches (after flattening) lives on the `nested_or` policy
-- below.
CREATE POLICY nested_or_check_authenticated_access ON app.nested_or_check
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT auth.uid()))
    WITH CHECK (user_id = (SELECT auth.uid()));
CREATE POLICY nested_or ON app.nested_or_check
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        flag = 'system'
        OR (
            (SELECT auth.uid()) IS NULL
            OR user_id = (SELECT auth.uid())
        )
    );
