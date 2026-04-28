-- ============================================================
-- Use case 3: Missing RLS — SEC001
-- Tenant table where someone enabled the policies elsewhere but
-- forgot the table-level switch. Every authenticated role can
-- read every row.
-- ============================================================

CREATE TABLE app.legacy_orders (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    total_cents INT
);

INSERT INTO app.legacy_orders (tenant_id, total_cents) VALUES
    ('00000000-0000-0000-0000-000000000001', 1000),
    ('00000000-0000-0000-0000-000000000002', 2500),
    ('00000000-0000-0000-0000-000000000002', 4200);
