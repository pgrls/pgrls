-- ============================================================
-- Use case 50: Read-replica style — SEC022 flags read-only RLS
-- A read-only mirror of canonical data. Two SELECT policies
-- (one tenant floor RESTRICTIVE, one role-specific PERMISSIVE
-- granted to a non-PUBLIC role) and zero write policies.
-- Demonstrates SEC022 (info): the table has working read
-- coverage but no write-side policy, so INSERT/UPDATE/DELETE are
-- denied for non-owner roles. SEC006 stays silent (no write
-- policy to validate) and SEC003 stays silent (the permissive
-- grant is to a specific role, not PUBLIC). For a deliberate
-- read replica this is expected — allowlist the table when the
-- read-only surface is intentional.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'app_replica_reader') THEN
        CREATE ROLE app_replica_reader NOLOGIN;
    END IF;
END $$;

CREATE TABLE app.read_replica (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    snapshot_at TIMESTAMPTZ DEFAULT now(),
    payload JSONB
);
ALTER TABLE app.read_replica ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.read_replica FORCE ROW LEVEL SECURITY;
CREATE POLICY replica_tenant_floor ON app.read_replica
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY replica_reader_grant ON app.read_replica
    FOR SELECT TO app_replica_reader
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
