-- ============================================================
-- Use case 67: BETWEEN operator — CLEAN
-- `BETWEEN` in pglast represents as a chained AND under
-- A_Expr-AEXPR_BETWEEN. extract_column_refs needs to walk
-- through the operator to find `created_at` on the outer
-- table.
-- ============================================================

CREATE TABLE app.recent_only (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE app.recent_only ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.recent_only FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with a flat tenant predicate (no BETWEEN).
-- The RESTRICTIVE below is what the case pins (BETWEEN walking
-- via extract_column_refs).
CREATE POLICY recent_only_authenticated_access ON app.recent_only
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY recent_window ON app.recent_only
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        AND created_at BETWEEN now() - INTERVAL '30 days' AND now()
    );
