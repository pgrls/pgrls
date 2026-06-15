-- ============================================================
-- Use case 91: write-side scope drop — SEC040
-- A permissive FOR ALL policy whose USING scopes rows by the tenant
-- key, but whose EXPLICIT WITH CHECK validates only a non-tenant
-- column. Because an explicit WITH CHECK replaces the implicit reuse
-- of USING, the write side drops the tenant scope: a caller can
-- UPDATE a row to change tenant_id and migrate it to another tenant
-- (and, on FOR ALL, INSERT a row stamped for another tenant). SEC040
-- fires on it (warning). The sibling table re-asserts the tenant
-- scope in its WITH CHECK, so SEC040 stays SILENT there — the rule's
-- defining boundary, pinned through live introspection. SEC006 (absent
-- WITH CHECK) and SEC028 (constant-true WITH CHECK) do not fire on
-- either: the clause is present and a real predicate.
-- ============================================================

-- The bug: USING scopes by tenant_id, WITH CHECK only checks status.
CREATE TABLE app.uc91_documents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    body TEXT
);
ALTER TABLE app.uc91_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc91_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY uc91_documents_rw ON app.uc91_documents
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint))
    WITH CHECK (status IN ('draft', 'published'));

-- The fix: WITH CHECK re-asserts the same tenant scope USING enforces,
-- so the written row must still belong to the caller's tenant. SEC040
-- must stay silent here.
CREATE TABLE app.uc91_documents_fixed (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    body TEXT
);
ALTER TABLE app.uc91_documents_fixed ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc91_documents_fixed FORCE ROW LEVEL SECURITY;
CREATE POLICY uc91_documents_fixed_rw ON app.uc91_documents_fixed
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint))
    WITH CHECK (
        tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint)
        AND status IN ('draft', 'published')
    );
