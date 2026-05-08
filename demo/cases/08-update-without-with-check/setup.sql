-- ============================================================
-- Use case 8: UPDATE without WITH CHECK — SEC006
-- USING gates which rows the user can SEE. WITH CHECK gates which
-- rows they can WRITE. Without WITH CHECK on UPDATE, a tenant can
-- "move" a row to another tenant by changing tenant_id.
-- ============================================================

CREATE TABLE app.invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    amount_cents INT
);
ALTER TABLE app.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.invoices FORCE ROW LEVEL SECURITY;
-- Canonical PERMISSIVE policy for tenant-scoped read+write. The
-- buggy RESTRICTIVE UPDATE policy below (no WITH CHECK) is what
-- SEC006 catches; this PERMISSIVE keeps the table from being
-- silently deny-all (SEC012) for non-UPDATE statements.
CREATE POLICY invoices_authenticated_access ON app.invoices
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY update_without_check ON app.invoices
    AS RESTRICTIVE
    FOR UPDATE TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
    -- WITH CHECK omitted — fires SEC006
