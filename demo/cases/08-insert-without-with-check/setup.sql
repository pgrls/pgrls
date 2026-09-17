-- ============================================================
-- Use case 8: INSERT without WITH CHECK — SEC006
-- USING gates which rows the user can SEE. WITH CHECK gates which
-- rows they can WRITE. For INSERT there is no USING to fall back
-- on. A missing WITH CHECK does NOT default to `true`: a permissive
-- INSERT policy with no WITH CHECK contributes nothing to the
-- permissive OR, so it grants no write at all and the canonical
-- policy's tenant check still governs every insert (measured: the
-- cross-tenant insert raises `new row violates row-level security
-- policy`). The bug is a dead policy that looks protective.
--
-- (An UPDATE / ALL policy that omits WITH CHECK is NOT a hole —
-- Postgres reuses its USING expression as the implicit WITH CHECK, so
-- the written row must still satisfy USING. SEC006 flags only the
-- genuinely-open shapes: INSERT, or UPDATE/ALL whose USING is absent
-- or constant-true.)
-- ============================================================

CREATE TABLE app.invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    amount_cents INT
);
ALTER TABLE app.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.invoices FORCE ROW LEVEL SECURITY;
-- Canonical PERMISSIVE policy for tenant-scoped read+write.
CREATE POLICY invoices_authenticated_access ON app.invoices
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
-- Buggy PERMISSIVE INSERT policy with no WITH CHECK. It grants no
-- write whatsoever — a missing WITH CHECK is not `true`, so this
-- policy contributes nothing to the permissive OR and the canonical
-- policy above still decides every insert. A dead policy that reads
-- as if it permitted something. This is what SEC006 catches.
CREATE POLICY invoices_insert_open ON app.invoices
    FOR INSERT TO app_authenticated;
    -- WITH CHECK omitted — fires SEC006
