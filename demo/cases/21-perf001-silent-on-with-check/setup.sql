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
CREATE POLICY insert_self_only ON app.audit_inserts
    AS RESTRICTIVE
    FOR INSERT TO PUBLIC
    WITH CHECK (user_id = auth.uid());
