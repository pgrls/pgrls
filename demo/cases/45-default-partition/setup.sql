-- ============================================================
-- Use case 45: Default partition — CLEAN
-- `PARTITION OF parent DEFAULT` is the catch-all partition.
-- Postgres still records it in pg_inherits with
-- relispartition = true, so introspect.py picks it up like
-- any partition; SEC001's ancestor walk reaches the
-- RLS-enabled root from the default leaf the same way.
-- ============================================================

CREATE TABLE app.region_metrics (
    id BIGSERIAL,
    region TEXT NOT NULL,
    value DOUBLE PRECISION
) PARTITION BY LIST (region);
CREATE TABLE app.region_metrics_us PARTITION OF app.region_metrics
    FOR VALUES IN ('us');
CREATE TABLE app.region_metrics_default PARTITION OF app.region_metrics DEFAULT;
ALTER TABLE app.region_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.region_metrics FORCE ROW LEVEL SECURITY;
CREATE POLICY region_visibility ON app.region_metrics
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (region = (SELECT current_setting('app.region', true)));
