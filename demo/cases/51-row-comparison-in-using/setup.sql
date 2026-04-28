-- ============================================================
-- Use case 51: ROW comparison in USING — CLEAN
-- `(tenant_id, env) = (..., ...)` is a row-level equality.
-- pglast represents this as a RowCompareExpr / RowExpr, which
-- extract_column_refs needs to walk through to see `tenant_id`
-- and `env`. Pin the AST path.
-- ============================================================

CREATE TABLE app.row_comparison (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    env TEXT NOT NULL,
    payload TEXT
);
ALTER TABLE app.row_comparison ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.row_comparison FORCE ROW LEVEL SECURITY;
CREATE POLICY row_eq ON app.row_comparison
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        (tenant_id, env) = (
            (SELECT current_setting('app.tenant', true)::UUID),
            (SELECT current_setting('app.env', true))
        )
    );
