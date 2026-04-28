-- ============================================================
-- Use case 26: Blog with admin-role override — CLEAN
-- A real-world multi-policy shape. One RESTRICTIVE policy
-- enforces tenant isolation; one PERMISSIVE policy grants
-- read access to admins via auth.role(). Both clauses are
-- wrapped to avoid PERF001. SEC007 stays silent because the
-- table has at least one RESTRICTIVE policy (not all
-- permissive). SEC005 and SEC008 stay silent because both
-- clauses reference table columns and aren't `(true)`.
-- ============================================================

CREATE TABLE app.blog_posts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    author_id UUID NOT NULL,
    title TEXT,
    body TEXT,
    published BOOLEAN NOT NULL DEFAULT false
);
ALTER TABLE app.blog_posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.blog_posts FORCE ROW LEVEL SECURITY;
CREATE POLICY blog_tenant_floor ON app.blog_posts
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY blog_admin_or_author_read ON app.blog_posts
    FOR SELECT TO PUBLIC
    USING (
        (SELECT auth.role()) = 'admin'
        OR author_id = (SELECT current_setting('app.user', true)::UUID)
    );
-- One PERMISSIVE policy is granted to PUBLIC, but the policy is
-- column-anchored (`author_id = ...`), so SEC003 still fires —
-- this is intentional. Use case 31 below shows the way to silence
-- SEC003: grant to a non-PUBLIC role.
