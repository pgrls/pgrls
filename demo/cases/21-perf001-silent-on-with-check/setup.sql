-- ============================================================
-- Use case 21: PERF001 silent on WITH CHECK — pin USING-only contract
-- An INSERT policy whose only auth call is in WITH CHECK. PERF001
-- is documented as USING-only (Postgres optimizes WITH CHECK
-- differently). Pinned by the demo so a future regression that
-- extends PERF001 to WITH CHECK fails this test loudly.
-- ============================================================

CREATE TABLE app.audit_inserts (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    event TEXT,
    happened_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE app.audit_inserts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_inserts FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with auth.uid() WRAPPED so PERF001 doesn't
-- fire on it. The RESTRICTIVE policy below has unwrapped
-- auth.uid() in WITH CHECK only — the demo pins that PERF001
-- is USING-only and stays silent on that policy.
CREATE POLICY audit_inserts_authenticated_access ON app.audit_inserts
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT auth.uid()))
    WITH CHECK (user_id = (SELECT auth.uid()));
CREATE POLICY insert_self_only ON app.audit_inserts
    AS RESTRICTIVE
    FOR INSERT TO PUBLIC
    WITH CHECK (user_id = auth.uid());
