-- ============================================================
-- Use case 58: PERF001 with auth wrapped in COALESCE — fires
-- `COALESCE(auth.uid(), '00000000-0000-0000-0000-000000000000')`
-- — find_func_calls must walk function args to spot auth.uid
-- inside another function call.
-- ============================================================

CREATE TABLE app.coalesce_auth (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID
);
ALTER TABLE app.coalesce_auth ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.coalesce_auth FORCE ROW LEVEL SECURITY;
CREATE POLICY coalesced ON app.coalesce_auth
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = COALESCE(auth.uid(), '00000000-0000-0000-0000-000000000000'::UUID)
    );
