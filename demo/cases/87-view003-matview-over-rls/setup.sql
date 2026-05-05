-- ============================================================
-- Use case 87: Materialized view over RLS table — VIEW003
-- A matview captures rows by running its body at REFRESH time,
-- under the refresher's privileges. Queries against the matview
-- read from its own physical heap and do NOT re-evaluate RLS on
-- `app.uc87_users`, regardless of any flag. Architectural fix
-- (per-tenant refresh or per-tenant matview) is the operator's
-- call — the rule's job is to surface the gap. Matviews early-exit
-- VIEW001 / VIEW002, so neither co-fires here.
-- ============================================================

CREATE TABLE app.uc87_users (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    plan TEXT
);
ALTER TABLE app.uc87_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc87_users FORCE ROW LEVEL SECURITY;
CREATE POLICY p_uc87 ON app.uc87_users
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant_id', true))::UUID
    );

CREATE MATERIALIZED VIEW app.uc87_user_summary AS
    SELECT plan, count(*) AS n FROM app.uc87_users GROUP BY plan;
