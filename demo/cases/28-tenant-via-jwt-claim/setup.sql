-- ============================================================
-- Use case 28: Tenant via JWT claim — CLEAN
-- Supabase-flavored: the tenant scope comes from the JWT
-- payload via `auth.jwt() ->> 'tenant_id'`. The wrap
-- `(SELECT auth.jwt())` keeps PERF001 silent.
-- ============================================================

CREATE TABLE app.jwt_documents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    title TEXT
);
ALTER TABLE app.jwt_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.jwt_documents FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy mirroring the JWT-tenant predicate. Wrapping
-- via `(SELECT auth.jwt())` keeps PERF001 silent on this policy
-- — the case demonstrates the wrapped form is correct.
CREATE POLICY jwt_documents_authenticated_access ON app.jwt_documents
    FOR ALL TO app_authenticated
    USING (
        tenant_id = ((SELECT auth.jwt()) ->> 'tenant_id')::UUID
    )
    WITH CHECK (
        tenant_id = ((SELECT auth.jwt()) ->> 'tenant_id')::UUID
    );
CREATE POLICY jwt_tenant ON app.jwt_documents
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        tenant_id = ((SELECT auth.jwt()) ->> 'tenant_id')::UUID
    )
    WITH CHECK (
        tenant_id = ((SELECT auth.jwt()) ->> 'tenant_id')::UUID
    );
