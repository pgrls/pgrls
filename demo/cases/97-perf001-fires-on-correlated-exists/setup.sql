-- ============================================================
-- Use case 97: PERF001 fires on an auth call nested in a CORRELATED
-- subquery. A bare auth.uid() inside a correlated EXISTS — the subquery
-- references the outer row (`d2.folder_id = uc97_documents.folder_id`) —
-- is re-evaluated once per outer row scanned, exactly like a top-level
-- call, so PERF001 flags it and `pgrls fix` wraps the nested call. An
-- UNCORRELATED subquery runs once and is left alone; that scoping is
-- pinned by the unit tests and the corpus `sec004-is-null-in-subquery-safe`
-- case. This exercises the introspection path: Postgres deparses the
-- stored policy with the outer reference qualified, which is what
-- subselect_is_correlated keys on.
-- ============================================================

CREATE TABLE app.uc97_documents (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    folder_id UUID
);
ALTER TABLE app.uc97_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.uc97_documents FORCE ROW LEVEL SECURITY;
-- CORRELATED EXISTS with an UNWRAPPED auth.uid() inside → PERF001 fires.
CREATE POLICY uc97_same_folder_read ON app.uc97_documents
    FOR SELECT TO app_authenticated
    USING (EXISTS (
        SELECT 1 FROM app.uc97_documents d2
        WHERE d2.folder_id = uc97_documents.folder_id
          AND d2.owner_id = auth.uid()
    ));
-- The same auth call WRAPPED in `(SELECT …)` → PERF001 stays silent.
CREATE POLICY uc97_owner_all ON app.uc97_documents
    AS RESTRICTIVE FOR ALL TO app_authenticated
    USING (owner_id = (SELECT auth.uid()))
    WITH CHECK (owner_id = (SELECT auth.uid()));
