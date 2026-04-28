-- ============================================================
-- Use case 40: Admin audit log — SEC005 allowlist demo
-- A legitimately session-state-only table: only admins read
-- the audit log, and the predicate is `auth.role() = 'admin'`.
-- The companion test runs pgrls with an inline config that
-- allowlists `app.admin_audit.admin_only_read`, demonstrating
-- the allowlist mechanism for known-good warnings.
-- ============================================================

CREATE TABLE app.admin_audit (
    id BIGSERIAL PRIMARY KEY,
    happened_at TIMESTAMPTZ DEFAULT now(),
    detail JSONB
);
ALTER TABLE app.admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.admin_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_only_read ON app.admin_audit
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING ((SELECT auth.role()) = 'admin');
