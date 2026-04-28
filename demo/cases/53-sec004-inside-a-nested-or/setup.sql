-- ============================================================
-- Use case 53: SEC004 inside a nested OR — false-negative pin
-- The rule keys on top-level OR disjuncts (per
-- top_level_disjuncts in ast_utils). When `auth_func() IS NULL`
-- is buried inside a nested OR, the helper's "split top OR
-- only" semantics means SEC004 does NOT fire. Pin the
-- documented limitation so a future change to descend deeper
-- is deliberate (and possibly noisy).
-- ============================================================

CREATE TABLE app.nested_or_check (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    flag TEXT
);
ALTER TABLE app.nested_or_check ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.nested_or_check FORCE ROW LEVEL SECURITY;
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
