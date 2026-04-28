-- ============================================================
-- Use case 1: Multi-tenant SaaS table — CLEAN
-- The canonical good shape. ENABLE + FORCE + RESTRICTIVE policy
-- with USING and WITH CHECK. pgrls should NOT flag this table.
-- ============================================================

CREATE TABLE app.documents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app.documents
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));

INSERT INTO app.documents (tenant_id, title, body) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Tenant A: roadmap', 'Q3 plans'),
    ('00000000-0000-0000-0000-000000000001', 'Tenant A: review',  'feedback'),
    ('00000000-0000-0000-0000-000000000002', 'Tenant B: launch',  'go live');
