-- ============================================================
-- Use case 25: View on top of an RLS-enabled table —
-- introspector skips
-- Views (relkind='v') aren't RLS-bearing — Postgres applies
-- the underlying table's RLS at evaluation time. The
-- introspector filters to relkind IN ('r', 'p'), so views
-- never enter pgrls's table list and no rule fires on them.
-- ============================================================

CREATE VIEW app.documents_view AS
    SELECT id, title, created_at FROM app.documents;
