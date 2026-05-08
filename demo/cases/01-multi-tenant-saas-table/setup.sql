-- ============================================================
-- Use case 1: Multi-tenant SaaS table — CLEAN
-- The canonical good shape. ENABLE + FORCE + a PERMISSIVE policy
-- (which grants access) + a RESTRICTIVE policy (which narrows it
-- to the current tenant). Postgres composes RLS as
-- `permissive_or | (restrictive_and & ...)`: at least one
-- PERMISSIVE policy must match AND every RESTRICTIVE policy must
-- match. With zero PERMISSIVE policies the disjunction is empty
-- and the table is silently deny-all (SEC012's catch). The pair
-- below grants tenant-scoped access via the PERMISSIVE policy and
-- enforces tenant scoping via the RESTRICTIVE policy.
-- pgrls should NOT flag this table.
-- ============================================================

-- The PERMISSIVE policy targets a specific application role rather
-- than PUBLIC (which would trip SEC003). Mirrors the role-creation
-- pattern uc31 uses; idempotent so re-applying _shared.sql + every
-- case's setup.sql is safe.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'app_authenticated') THEN
        CREATE ROLE app_authenticated NOLOGIN;
    END IF;
END $$;

CREATE TABLE app.documents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read_write ON app.documents
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY tenant_isolation ON app.documents
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));

INSERT INTO app.documents (tenant_id, title, body) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Tenant A: roadmap', 'Q3 plans'),
    ('00000000-0000-0000-0000-000000000001', 'Tenant A: review',  'feedback'),
    ('00000000-0000-0000-0000-000000000002', 'Tenant B: launch',  'go live');
