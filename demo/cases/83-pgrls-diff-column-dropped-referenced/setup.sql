-- ============================================================
-- Use case 83: pgrls diff REQUIRES_REVIEW — column dropped
-- while still referenced by a policy predicate.
-- The table has RLS, FORCE RLS, and a RESTRICTIVE policy whose
-- USING clause references `doomed_col`. The companion test does
-- NOT apply a live migration — Postgres rejects DROP COLUMN
-- without CASCADE when a policy references the column, and
-- CASCADE would also drop the policy and trigger the wrong
-- detection rule (POLICY_DROPPED_RESTRICTIVE, dangerous). Instead
-- the test captures the live baseline via `pgrls snapshot`, then
-- builds an in-memory head snapshot with `doomed_col` removed
-- from the column list while leaving the policy intact, and runs
-- `pgrls diff base.json head.json` to exercise the file-vs-file
-- path. Result: DIFF_COLUMN_DROPPED_REFERENCED fires
-- (REQUIRES_REVIEW, severity=warning) without disturbing the
-- live DB. No teardown needed.
-- ============================================================

CREATE TABLE app.uc83_invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    doomed_col TEXT NOT NULL,
    amount INT NOT NULL
);
ALTER TABLE app.uc83_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc83_invoices FORCE ROW LEVEL SECURITY;

-- PERMISSIVE policy granting tenant-scoped access. Deliberately
-- does NOT reference `doomed_col` — the case's diff scenario
-- removes that column from the in-memory head snapshot, and
-- the test asserts DIFF_COLUMN_DROPPED_REFERENCED fires on
-- `tenant_isolation` only.
CREATE POLICY uc83_invoices_authenticated_access ON app.uc83_invoices
    FOR ALL TO app_authenticated
    USING (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('request.jwt.claims', true))::jsonb->>'tenant_id'
    );

CREATE POLICY tenant_isolation ON app.uc83_invoices
    AS RESTRICTIVE
    FOR ALL
    TO PUBLIC
    USING (
        tenant_id = current_setting('request.jwt.claims', true)::jsonb->>'tenant_id'
        AND doomed_col IS NOT NULL
    );
