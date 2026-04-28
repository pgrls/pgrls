-- ============================================================
-- Use case 22: HYG001 catches dropped column in WITH CHECK
-- Same orphan-column pattern as use case 12 but the only
-- reference to the dropped column is in WITH CHECK. Pin that
-- HYG001 walks both clauses, not just USING.
-- ============================================================

CREATE TABLE app.posts_v2 (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    moderation_status TEXT
);
ALTER TABLE app.posts_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.posts_v2 FORCE ROW LEVEL SECURITY;
CREATE POLICY only_approved_writes ON app.posts_v2
    AS RESTRICTIVE
    FOR INSERT TO PUBLIC
    WITH CHECK (
        user_id = (SELECT current_setting('app.user', true))
        AND moderation_status = 'approved'
    );

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.posts_v2'::regclass
      AND attname = 'moderation_status';
