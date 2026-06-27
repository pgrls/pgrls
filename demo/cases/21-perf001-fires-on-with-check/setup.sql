-- ============================================================
-- Use case 21: PERF001 fires on an unwrapped auth call in WITH CHECK
-- An INSERT policy whose only auth call is in WITH CHECK. A bare
-- auth.uid() there is re-evaluated once per written row — a 1000-row
-- INSERT calls it 1000x, the (SELECT …) wrap calls it once — so
-- PERF001 flags WITH CHECK exactly like USING. The PERMISSIVE policy
-- below wraps both clauses and stays silent, pinning that the wrap
-- clears the finding on the write side too.
-- ============================================================

CREATE TABLE app.audit_inserts (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    event TEXT,
    happened_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE app.audit_inserts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_inserts FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy with auth.uid() WRAPPED in both clauses, so
-- PERF001 stays silent on it.
CREATE POLICY audit_inserts_authenticated_access ON app.audit_inserts
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT auth.uid()))
    WITH CHECK (user_id = (SELECT auth.uid()));
-- RESTRICTIVE policy with an UNWRAPPED auth.uid() in WITH CHECK only —
-- PERF001 fires on it (per-row eval on every INSERT).
CREATE POLICY insert_self_only ON app.audit_inserts
    AS RESTRICTIVE
    FOR INSERT TO PUBLIC
    WITH CHECK (user_id = auth.uid());
