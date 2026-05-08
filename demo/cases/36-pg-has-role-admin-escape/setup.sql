-- ============================================================
-- Use case 36: pg_has_role admin escape — CLEAN
-- A common production pattern: tenant rows for normal users,
-- but service-level roles (here `pg_read_all_data`, a built-in
-- predefined role since PG 14) get to read everything. Note
-- that `pg_has_role` is NOT in PERF001's default
-- `auth_functions` set, so the unwrapped call is fine.
-- ============================================================

CREATE TABLE app.admin_overrides (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    note TEXT
);
ALTER TABLE app.admin_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.admin_overrides FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy mirroring the tenant-or-admin predicate.
-- `pg_has_role` is not in PERF001's default auth_functions set,
-- so the unwrapped call is fine here too. SEC005 silent
-- (`tenant_id` own-column ref present).
CREATE POLICY admin_overrides_authenticated_access ON app.admin_overrides
    FOR ALL TO app_authenticated
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')
    );
CREATE POLICY tenant_or_admin ON app.admin_overrides
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')
    );
