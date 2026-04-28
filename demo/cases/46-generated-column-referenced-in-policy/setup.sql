-- ============================================================
-- Use case 46: Generated column referenced in policy — CLEAN
-- `GENERATED ALWAYS AS (...) STORED` columns appear in
-- pg_attribute alongside regular columns. Policies can
-- reference them; HYG001 sees them as present. Pin that the
-- generated column is treated like any other.
-- ============================================================

CREATE TABLE app.gen_cols (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    user_id_norm TEXT GENERATED ALWAYS AS (lower(user_id)) STORED
);
ALTER TABLE app.gen_cols ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.gen_cols FORCE ROW LEVEL SECURITY;
CREATE POLICY gen_owner ON app.gen_cols
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id_norm = lower((SELECT current_setting('app.user', true))));
