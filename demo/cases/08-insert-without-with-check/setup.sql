-- ============================================================
-- Use case 8: INSERT without WITH CHECK — SEC006
-- USING gates which rows the user can SEE. WITH CHECK gates which
-- rows they can WRITE. For INSERT there is no USING to fall back
-- on, and permissive WITH CHECKs are OR-combined: a permissive
-- INSERT policy with NO WITH CHECK therefore accepts EVERY inserted
-- row, bypassing the canonical policy's tenant check — a tenant can
-- insert a row stamped with another tenant's id.
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
-- Buggy PERMISSIVE INSERT policy with no WITH CHECK. Permissive
-- WITH CHECKs are OR-combined, so this one (which checks nothing)
-- lets a tenant insert a row for ANY tenant — it defeats the
-- canonical policy's WITH CHECK above. This is what SEC006 catches.
CREATE POLICY invoices_insert_open ON app.invoices
    FOR INSERT TO app_authenticated;
    -- WITH CHECK omitted — fires SEC006
