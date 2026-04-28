-- ============================================================
-- Use case 48: E-commerce orders + items via FK tenant — CLEAN
-- Two related tables. Items inherit tenant scope through the
-- parent order via a SubLink lookup. Pins that the SubLink
-- walk reaches `tenant_id` on the outer table even when the
-- inner table's only correlation is the parent FK.
-- ============================================================

CREATE TABLE app.ec_orders (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    customer_email TEXT,
    total_cents INT
);
ALTER TABLE app.ec_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.ec_orders FORCE ROW LEVEL SECURITY;
CREATE POLICY orders_tenant ON app.ec_orders
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));

CREATE TABLE app.ec_order_items (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES app.ec_orders(id),
    sku TEXT,
    qty INT
);
ALTER TABLE app.ec_order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.ec_order_items FORCE ROW LEVEL SECURITY;
CREATE POLICY items_via_order ON app.ec_order_items
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        EXISTS (
            SELECT 1 FROM app.ec_orders o
            WHERE o.id = order_id
              AND o.tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM app.ec_orders o
            WHERE o.id = order_id
              AND o.tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        )
    );
