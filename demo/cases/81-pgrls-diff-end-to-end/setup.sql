-- ============================================================
-- Use case 81: pgrls diff end-to-end smoke
-- An RLS-protected table with a RESTRICTIVE tenant_isolation
-- policy. The companion test:
--   1. Captures a snapshot of the current schema state.
--   2. Drops the RESTRICTIVE policy (a dangerous regression).
--   3. Runs `pgrls diff` against the captured snapshot.
--   4. Asserts the dropped-policy detection fires DANGEROUS.
-- After the test, the policy is recreated so subsequent demos
-- don't see the table without it.
-- ============================================================

CREATE TABLE app.uc81_invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount INT NOT NULL
);
ALTER TABLE app.uc81_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc81_invoices FORCE ROW LEVEL SECURITY;

-- PERMISSIVE policy granting tenant-scoped access. Wrapped via
-- `(SELECT current_setting(...))` so PERF001 stays silent on
-- this policy. The RESTRICTIVE below is what the diff test
-- drops to exercise DIFF_POLICY_DROPPED_RESTRICTIVE.
CREATE POLICY uc81_invoices_authenticated_access ON app.uc81_invoices
    FOR ALL TO app_authenticated
    USING (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    );

CREATE POLICY tenant_isolation ON app.uc81_invoices
    AS RESTRICTIVE
    FOR ALL
    TO PUBLIC
    USING (
        tenant_id = current_setting('request.jwt.claims', true)::jsonb->>'tenant_id'
    );
