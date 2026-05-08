-- ============================================================
-- Use case 29: Public-or-tenant mix — CLEAN
-- "Some rows are world-readable (`is_public = true`); others
-- are tenant-scoped." The disjunction is column-anchored on
-- both sides — SEC005 stays silent because the predicate
-- references `is_public` AND `tenant_id`.
-- ============================================================

CREATE TABLE app.kb_articles (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    is_public BOOLEAN NOT NULL DEFAULT false,
    title TEXT
);
ALTER TABLE app.kb_articles ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.kb_articles FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy mirroring the public-or-tenant predicate.
-- Both branches reference real columns (`is_public` boolean,
-- `tenant_id` UUID) so SEC005 stays silent. Both wrapped via
-- `(SELECT ...)` so PERF001 stays silent.
CREATE POLICY kb_articles_authenticated_access ON app.kb_articles
    FOR ALL TO app_authenticated
    USING (
        is_public
        OR tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
    );
CREATE POLICY public_or_tenant ON app.kb_articles
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        is_public
        OR tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
    );
