-- ============================================================
-- Use case 84: pgrls diff BREAKING — PERMISSIVE policy dropped.
-- A table with RLS, FORCE RLS, and a PERMISSIVE policy granting
-- access to a public_data role. The companion test:
--   1. Captures a snapshot of the current state.
--   2. Drops the PERMISSIVE policy (a BREAKING change — previously-
--      visible rows may no longer be).
--   3. Runs `pgrls diff` against the captured snapshot.
--   4. Asserts DIFF_POLICY_DROPPED_PERMISSIVE fires with
--      classification BREAKING (severity=warning).
--   5. With default `--fail-on dangerous`, exit 0 (BREAKING is
--      below threshold).
--   6. With `--fail-on breaking`, exit 1.
-- After the test the policy is recreated so subsequent demos see
-- the table in its baseline state.
--
-- Rounds out the demo coverage matrix:
--   case 81 → DANGEROUS (dropped RESTRICTIVE)
--   case 82 → SAFE (added RESTRICTIVE)
--   case 83 → REQUIRES_REVIEW (column dropped while referenced)
--   case 84 → BREAKING (dropped PERMISSIVE)  ← this case
-- ============================================================

CREATE TABLE app.uc84_invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount INT NOT NULL
);
ALTER TABLE app.uc84_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc84_invoices FORCE ROW LEVEL SECURITY;

CREATE POLICY public_read ON app.uc84_invoices
    AS PERMISSIVE
    FOR SELECT
    TO PUBLIC
    USING (
        tenant_id = current_setting('request.jwt.claims', true)::jsonb->>'tenant_id'
    );
