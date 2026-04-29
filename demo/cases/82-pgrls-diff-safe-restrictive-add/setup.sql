-- ============================================================
-- Use case 82: pgrls diff SAFE path — RESTRICTIVE policy added
-- A table with RLS enabled but no policies (a SEC009 violation
-- in its own right, but this case is about the diff path, not
-- the lint path). The companion test:
--   1. Captures a snapshot of the current state (no policy).
--   2. Creates a RESTRICTIVE tenant_isolation policy (a SAFE add).
--   3. Runs `pgrls diff` against the captured snapshot.
--   4. Asserts DIFF_POLICY_ADDED_RESTRICTIVE fires with severity=info.
-- After the test the policy is dropped so subsequent demos see
-- the table in its original baseline state.
-- ============================================================

CREATE TABLE app.uc82_invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount INT NOT NULL
);
ALTER TABLE app.uc82_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc82_invoices FORCE ROW LEVEL SECURITY;
