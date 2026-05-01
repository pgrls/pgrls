-- ============================================================
-- Use case 25: View on top of an RLS-enabled table — CLEAN
-- Table-level rules (SEC001..SEC011, PERF001..PERF002, HYG001..
-- HYG002) only walk relkind IN ('r', 'p'), so views never appear
-- in their output. The view-level rules (VIEW001..VIEW004) DO
-- inspect views, but this fixture is the canonical clean shape:
-- both `security_invoker` and `security_barrier` are set, and the
-- body calls no SECDEF function, so VIEW001 / VIEW002 / VIEW004
-- stay silent and VIEW003 (matview-only) doesn't apply. Net
-- result: no rule mentions `app.documents_view`.
-- ============================================================

CREATE VIEW app.documents_view
    WITH (security_invoker = true, security_barrier = true)
    AS SELECT id, title, created_at FROM app.documents;
