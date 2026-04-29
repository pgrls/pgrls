-- ============================================================
-- Use case 80: pgrls.testing pytest plugin — end-to-end smoke
-- A minimal RLS-protected table with a tenant-claim policy.
-- The companion test verifies pgrls.testing's pytest-plugin
-- wiring (PgrlsTestClient.connect + transaction + seed +
-- fetchall) against the demo's connection. RLS-filtering
-- behavior is tested authoritatively by the cross-language
-- conformance fixture at tests/protocol/, not here — the demo's
-- connecting user has bypass privileges.
-- ============================================================

CREATE TABLE app.demo_invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount INT NOT NULL
);
ALTER TABLE app.demo_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.demo_invoices FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON app.demo_invoices
    FOR ALL
    TO PUBLIC
    USING (
        tenant_id = current_setting('request.jwt.claims', true)::jsonb->>'tenant_id'
    )
    WITH CHECK (
        tenant_id = current_setting('request.jwt.claims', true)::jsonb->>'tenant_id'
    );
