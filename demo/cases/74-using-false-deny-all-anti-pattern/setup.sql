-- ============================================================
-- Use case 74: USING (false) deny-all anti-pattern — SEC010
-- (new in 0.0.6)
-- The policy denies every row by writing the denial as a
-- predicate. Misleading: the table looks RLS-protected (it has
-- a policy) but the predicate makes it effectively disabled.
-- The right primitive is `REVOKE ALL ON TABLE x FROM <role>`.
-- SEC005 also fires here (no own-column reference) — a
-- correctly-noisy outcome since the policy is defective on
-- multiple counts.
-- ============================================================

CREATE TABLE app.deny_via_false (
    id BIGSERIAL,
    payload TEXT
);
ALTER TABLE app.deny_via_false ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.deny_via_false FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with a benign own-column predicate so
-- SEC005 stays silent here. The RESTRICTIVE below has the
-- `USING (false)` shape SEC010 catches.
CREATE POLICY deny_via_false_authenticated_access ON app.deny_via_false
    FOR ALL TO app_authenticated
    USING (id IS NOT NULL)
    WITH CHECK (id IS NOT NULL);
CREATE POLICY block_all ON app.deny_via_false
    AS RESTRICTIVE FOR SELECT TO PUBLIC USING (false);
