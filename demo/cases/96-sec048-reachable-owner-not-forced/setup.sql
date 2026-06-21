-- ============================================================
-- Use case 96: a low-trust role reaches a non-FORCE'd table owner — SEC048
-- A role that OWNS a table bypasses that table's row-level security unless
-- FORCE ROW LEVEL SECURITY is set (the SEC002 boundary). The BYPASSRLS
-- *attribute* SEC029 covers is never inherited through role membership, but
-- owner *privileges* ARE: a role that is a member of the owning role inherits
-- its ownership (with INHERIT automatically, or with NOINHERIT after a SET
-- ROLE) and so bypasses RLS on the owner's enabled-but-not-FORCE'd tables.
-- SEC048 (warning) is the table-owner analog of SEC029, and co-fires with
-- SEC002 (which reports the table) on the same missing-FORCE misconfig.
--
-- The setup: `demo_table_owner` is a plain NOLOGIN role (no superuser, no
-- BYPASSRLS — so it is distinct from SEC016/SEC029's BYPASSRLS surface, which
-- keeps SEC048 disjoint from SEC029). It OWNS `app.owner_reachable_ledger`,
-- which has RLS ENABLEd but NOT FORCE'd. `app_authenticated` (the demo's
-- ordinary application login role) is GRANTed membership in
-- `demo_table_owner`, so it inherits the owner's RLS bypass and reads every
-- tenant's rows of the ledger regardless of policy. SEC048 fires once, at the
-- member role name `app_authenticated`.
--
-- The fix: ALTER TABLE app.owner_reachable_ledger FORCE ROW LEVEL SECURITY
-- (re-applies RLS even to the owner and its members), or REVOKE the
-- membership, or allowlist the member / owner if the reach is intentional.
-- ============================================================

-- A plain table-owner role: no superuser, no BYPASSRLS. Created defensively
-- (roles are cluster-global; the demo loads every case into one shared DB).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'demo_table_owner'
    ) THEN
        CREATE ROLE demo_table_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

CREATE TABLE app.owner_reachable_ledger (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    amount NUMERIC NOT NULL
);
CREATE INDEX ON app.owner_reachable_ledger (tenant_id);
-- The table is created by the (superuser) migration role, then handed to the
-- plain owner role. RLS is ENABLEd but deliberately NOT FORCE'd — the bug.
ALTER TABLE app.owner_reachable_ledger OWNER TO demo_table_owner;
ALTER TABLE app.owner_reachable_ledger ENABLE ROW LEVEL SECURITY;
CREATE POLICY owner_reachable_ledger_tenant_scope ON app.owner_reachable_ledger
    FOR ALL TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::uuid))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::uuid));

-- The reach: the ordinary application role is a member of the table owner, so
-- it inherits the owner's RLS bypass on the not-FORCE'd table above. SEC048
-- fires on `app_authenticated`.
GRANT demo_table_owner TO app_authenticated;
