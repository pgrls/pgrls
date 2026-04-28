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
