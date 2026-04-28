-- ============================================================
-- Use case 23: Three-level partition with RLS at root — CLEAN
-- Sub-partitioning (PARTITION BY ... PARTITION BY ...). SEC001
-- walks ancestors iteratively, so leaves whose chain reaches
-- the RLS-enabled root inherit coverage at any depth.
-- ============================================================

CREATE TABLE app.deep_events (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    bucket TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    payload JSONB
) PARTITION BY LIST (bucket);

CREATE TABLE app.deep_events_t1 PARTITION OF app.deep_events
    FOR VALUES IN ('t1') PARTITION BY RANGE (ts);
CREATE TABLE app.deep_events_t1_2026 PARTITION OF app.deep_events_t1
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

ALTER TABLE app.deep_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.deep_events FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_tenant ON app.deep_events
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
