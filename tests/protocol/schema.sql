-- Cross-language conformance fixture for pgrls test protocol v1.
-- Any client that conforms to docs/pgrls-test-protocol.md should
-- pass the cases in manifest.json against this schema + seed.

-- NOLOGIN: the protocol contract switches to this role via
-- `SET LOCAL ROLE` inside a single admin connection (no separate
-- login). A TS / Go port mirrors the same pattern.
CREATE ROLE pgrls_protocol_actor NOLOGIN;
GRANT USAGE ON SCHEMA public TO pgrls_protocol_actor;

CREATE TABLE protocol_invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount INT NOT NULL
);
ALTER TABLE protocol_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_invoices FORCE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON protocol_invoices TO pgrls_protocol_actor;
GRANT USAGE ON SEQUENCE protocol_invoices_id_seq TO pgrls_protocol_actor;

CREATE POLICY tenant_isolation ON protocol_invoices
    FOR ALL
    TO pgrls_protocol_actor
    USING (
        tenant_id = current_setting('request.jwt.claims', true)::jsonb->>'tenant_id'
    )
    WITH CHECK (
        tenant_id = current_setting('request.jwt.claims', true)::jsonb->>'tenant_id'
    );
