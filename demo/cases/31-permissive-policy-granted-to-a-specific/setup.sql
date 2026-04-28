-- ============================================================
-- Use case 31: Permissive policy granted to a specific role
-- (NOT PUBLIC) — CLEAN against SEC003
-- SEC003 fires only when permissive AND TO PUBLIC. Granting
-- to a specific application role (here `app_authenticated`)
-- silences it. Demonstrates the canonical fix for SEC003 in
-- multi-tenant apps that use a service account.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'app_authenticated') THEN
        CREATE ROLE app_authenticated NOLOGIN;
    END IF;
END $$;

CREATE TABLE app.scoped_views (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    payload JSONB
);
ALTER TABLE app.scoped_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.scoped_views FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_floor ON app.scoped_views
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY auth_role_read ON app.scoped_views
    FOR SELECT TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
