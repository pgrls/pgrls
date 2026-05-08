-- ============================================================
-- Use case 12: Orphaned column reference — HYG001
-- A policy references a column that has been dropped. Postgres 16
-- refuses real DROP COLUMN while a policy depends on it, so the
-- fixture simulates the orphan by editing pg_attribute directly
-- — the same internal state older Postgres versions could leave.
-- ============================================================

CREATE TABLE app.comments (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    archived BOOLEAN DEFAULT false
);
ALTER TABLE app.comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.comments FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy granting per-user access. Deliberately does
-- NOT reference `archived` — that column is dropped at the end
-- of this fixture, and HYG001 should fire on `archived_filter`
-- only (the policy with the orphan reference). Pinning the
-- one-policy-fires invariant is the whole point of this case.
CREATE POLICY comments_authenticated_access ON app.comments
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY archived_filter ON app.comments
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        (SELECT current_setting('app.user', true)) = user_id
        AND NOT archived
    );

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.comments'::regclass
      AND attname = 'archived';
