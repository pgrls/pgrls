-- ============================================================
-- Use case 24: Partition with RLS pushed down to the leaf —
-- mixed coverage
-- The parent has no RLS but the leaf does. Per the AGENTS.md
-- guidance, this is the right pattern when direct child access
-- is part of the threat model: each leaf carries its own
-- protection, so direct queries against leaves can't bypass
-- a parent-level policy. SEC001 fires on the parent (no RLS
-- there) but is silent on the leaf (rls_enabled=true on the
-- leaf itself).
-- ============================================================

CREATE TABLE app.leaf_metrics (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    value DOUBLE PRECISION
) PARTITION BY RANGE (ts);

CREATE TABLE app.leaf_metrics_2026 PARTITION OF app.leaf_metrics
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

ALTER TABLE app.leaf_metrics_2026 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.leaf_metrics_2026 FORCE ROW LEVEL SECURITY;
CREATE POLICY leaf_tenant ON app.leaf_metrics_2026
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
