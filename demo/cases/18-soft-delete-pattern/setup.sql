-- ============================================================
-- Use case 18: Soft-delete pattern — CLEAN
-- `deleted_at IS NULL` is a common way to filter out
-- tombstoned rows from default reads. Note that `deleted_at IS
-- NULL` is a column-IS-NULL test, NOT an `auth_func() IS NULL`
-- — SEC004 only flags the latter. Pin that distinction at the
-- demo level.
-- ============================================================

CREATE TABLE app.users_v2 (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    email TEXT NOT NULL,
    deleted_at TIMESTAMPTZ
);
ALTER TABLE app.users_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.users_v2 FORCE ROW LEVEL SECURITY;
-- Canonical PERMISSIVE policy granting tenant-scoped access. The
-- RESTRICTIVE policy below layers a soft-delete filter on top.
-- Together: read your own tenant's non-deleted rows.
CREATE POLICY users_v2_authenticated_access ON app.users_v2
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY hide_deleted ON app.users_v2
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        deleted_at IS NULL
        AND tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
    );
