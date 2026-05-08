-- ============================================================
-- Use case 66: HYG001 walks JSON `->>` operator — CLEAN
-- `payload->>'visibility'` references the outer column
-- `payload`, not a column named "visibility". Pin that
-- HYG001's column-ref walk does NOT confuse JSON keys with
-- column names — the only column ref here is `payload`, which
-- exists, so HYG001 stays silent.
-- ============================================================

CREATE TABLE app.json_access (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    payload JSONB
);
ALTER TABLE app.json_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.json_access FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with a flat per-user predicate. The case
-- pins HYG001's JSON-operator walk on the RESTRICTIVE below;
-- this PERMISSIVE keeps SEC012 silent without affecting that.
CREATE POLICY json_access_authenticated_access ON app.json_access
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY json_filter ON app.json_access
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT current_setting('app.user', true))
        AND payload->>'visibility' = 'public'
    );
