-- ============================================================
-- Use case 30: Composite tenant key — CLEAN
-- Real-world tenancy is sometimes multi-dimensional: tenant
-- AND environment, or tenant AND region. The policy AND-joins
-- the columns. SEC005 stays silent because both columns are
-- referenced; SEC003 stays silent because RESTRICTIVE.
-- ============================================================

CREATE TABLE app.composite_tenant (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    env TEXT NOT NULL,
    payload JSONB,
    PRIMARY KEY (tenant_id, env, id)
);
ALTER TABLE app.composite_tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.composite_tenant FORCE ROW LEVEL SECURITY;
CREATE POLICY composite_isolation ON app.composite_tenant
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        AND env = (SELECT current_setting('app.env', true))
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        AND env = (SELECT current_setting('app.env', true))
    );
