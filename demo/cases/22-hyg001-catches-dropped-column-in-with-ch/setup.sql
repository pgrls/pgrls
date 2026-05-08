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
-- PERMISSIVE policies for SELECT and INSERT so the table isn't
-- silently deny-all (SEC012). The orphan-column reference lives
-- in the RESTRICTIVE WITH CHECK below; HYG001 still flags it
-- regardless of any other policies on the table.
CREATE POLICY posts_v2_authenticated_select ON app.posts_v2
    FOR SELECT TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY posts_v2_authenticated_insert ON app.posts_v2
    FOR INSERT TO app_authenticated
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
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
