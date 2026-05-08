-- ============================================================
-- Use case 32: CASE expression in policy — CLEAN
-- A column-anchored predicate inside a `CASE ... END`. Pins
-- that extract_column_refs walks CASE branches: SEC005 must
-- find both `visibility` and `user_id` and stay silent.
-- ============================================================

CREATE TABLE app.case_policy (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    visibility TEXT
);
ALTER TABLE app.case_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.case_policy FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with a flat predicate (own column, no
-- CASE expression) so the new policy doesn't change what
-- SEC005's CASE-walk pin demonstrates.
CREATE POLICY case_policy_authenticated_access ON app.case_policy
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY visibility_case ON app.case_policy
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        CASE visibility
            WHEN 'public'  THEN true
            WHEN 'private' THEN user_id = (SELECT current_setting('app.user', true))
            ELSE false
        END
    );
