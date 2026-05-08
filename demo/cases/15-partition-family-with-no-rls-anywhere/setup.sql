-- ============================================================
-- Use case 15: Partition family with no RLS anywhere —
-- SEC001 visible-root variant
-- Both parent and child are in scope and lack RLS. SEC001 fires
-- on the child with a message that names the parent
-- (`is a partition of app.bare_metrics`) so the maintainer fixes
-- the parent rather than enabling RLS only on this leaf.
-- ============================================================

CREATE TABLE app.bare_metrics (
    id BIGSERIAL,
    tenant_id UUID,
    ts TIMESTAMPTZ NOT NULL,
    value DOUBLE PRECISION
) PARTITION BY RANGE (ts);

CREATE TABLE app.bare_metrics_2026 PARTITION OF app.bare_metrics
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
-- No ENABLE ROW LEVEL SECURITY anywhere in this family.


-- ============================================================
-- Use case 16: Correlated EXISTS membership — CLEAN
-- The classic team/membership-table pattern. The policy joins
-- to `team_members` via a correlated EXISTS, referencing
-- `team_id` from the outer `team_documents` table. SEC005
-- must NOT fire here — the policy IS row-scoped through the
-- join. A regression in the SubLink walk would silently turn
-- this into a false positive (the C2 fix from 0.0.4).
--
-- NOTE on column naming: the membership table uses
-- `member_team_id` rather than `team_id` to keep the inner
-- subquery's name resolution unambiguous. With both columns
-- named `team_id`, Postgres would resolve the bare `team_id`
-- to the inner table's column (silent tautology) — not what
-- the author meant. Distinct names make the correlation
-- explicit.
-- ============================================================
CREATE TABLE app.team_members (
    member_team_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT,
    PRIMARY KEY (member_team_id, user_id)
);
ALTER TABLE app.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.team_members FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy granting per-user access. The RESTRICTIVE
-- below is what uc16's correlated-EXISTS pin lives on.
CREATE POLICY team_members_authenticated_access ON app.team_members
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY team_members_self ON app.team_members
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));

CREATE TABLE app.team_documents (
    id BIGSERIAL PRIMARY KEY,
    team_id UUID NOT NULL,
    title TEXT NOT NULL
);
ALTER TABLE app.team_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.team_documents FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy mirroring the correlated-EXISTS shape so
-- the case still demonstrates uc16's SubLink walk, just on
-- the PERMISSIVE side too. Same predicate as the RESTRICTIVE.
CREATE POLICY team_documents_authenticated_access ON app.team_documents
    FOR ALL TO app_authenticated
    USING (
        EXISTS (
            SELECT 1 FROM app.team_members tm
            WHERE tm.member_team_id = team_id
              AND tm.user_id = (SELECT current_setting('app.user', true))
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM app.team_members tm
            WHERE tm.member_team_id = team_id
              AND tm.user_id = (SELECT current_setting('app.user', true))
        )
    );
CREATE POLICY team_member_visibility ON app.team_documents
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        EXISTS (
            SELECT 1 FROM app.team_members tm
            WHERE tm.member_team_id = team_id
              AND tm.user_id = (SELECT current_setting('app.user', true))
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM app.team_members tm
            WHERE tm.member_team_id = team_id
              AND tm.user_id = (SELECT current_setting('app.user', true))
        )
    );
