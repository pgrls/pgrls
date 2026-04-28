-- ============================================================
-- Use case 13: Partitioned parent — CLEAN
-- Time-partitioned table with RLS+FORCE+RESTRICTIVE policy on the
-- parent. Children inherit the policy at query time. SEC001 walks
-- each child's partition_of chain and suppresses the violation
-- (the parent has RLS), so neither parent nor children fire.
-- ============================================================

CREATE TABLE app.events (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    payload JSONB
) PARTITION BY RANGE (ts);

CREATE TABLE app.events_2025 PARTITION OF app.events
    FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE app.events_2026 PARTITION OF app.events
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

ALTER TABLE app.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.events FORCE ROW LEVEL SECURITY;
CREATE POLICY events_tenant ON app.events
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));

INSERT INTO app.events (tenant_id, ts, payload) VALUES
    ('00000000-0000-0000-0000-000000000001', '2025-06-01', '{"e":"login"}'),
    ('00000000-0000-0000-0000-000000000001', '2026-03-15', '{"e":"upload"}'),
    ('00000000-0000-0000-0000-000000000002', '2026-04-20', '{"e":"export"}');
