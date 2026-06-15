-- ============================================================
-- Use case 93: anon-executable SECURITY DEFINER RPC bypasses RLS — SEC042
-- A SECURITY DEFINER function runs as its OWNER. Here the owner is the
-- (superuser) migration role, so the body is RLS-exempt. The first function
-- is left at the default EXECUTE TO PUBLIC, so an unauthenticated PostgREST
-- POST /rpc/... caller runs it and reads every tenant's rows -- SEC042 fires
-- on the live introspected function. The second revokes PUBLIC and grants
-- EXECUTE only to a trusted role, so it is no longer an anonymous endpoint
-- and SEC042 stays SILENT -- the rule's boundary, pinned through live
-- introspection. Both are SECURITY DEFINER, so SEC014 audits both regardless
-- of who can call them (it is not pinned here).
-- ============================================================

CREATE TABLE app.uc93_secrets (
    tenant_id BIGINT NOT NULL,
    body TEXT
);
ALTER TABLE app.uc93_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc93_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY uc93_tenant ON app.uc93_secrets
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::bigint));

-- The bug: SECURITY DEFINER, RLS-exempt owner, default EXECUTE TO PUBLIC. An
-- anonymous caller invokes it and the owner's RLS exemption returns every
-- tenant's rows. SEC042 fires.
CREATE FUNCTION app.uc93_all_secrets() RETURNS SETOF app.uc93_secrets
    LANGUAGE sql SECURITY DEFINER
    AS 'SELECT * FROM app.uc93_secrets';

-- The fix: same SECURITY DEFINER function, but EXECUTE is revoked from PUBLIC
-- and granted only to a trusted role -- no longer anon-reachable, so SEC042
-- stays silent (app_authenticated is not in the low-trust default set).
CREATE FUNCTION app.uc93_trusted_secrets() RETURNS SETOF app.uc93_secrets
    LANGUAGE sql SECURITY DEFINER
    AS 'SELECT * FROM app.uc93_secrets';
REVOKE EXECUTE ON FUNCTION app.uc93_trusted_secrets() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.uc93_trusted_secrets() TO app_authenticated;
