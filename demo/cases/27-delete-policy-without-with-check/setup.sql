-- ============================================================
-- Use case 27: DELETE policy without WITH CHECK — CLEAN
-- DELETE policies have no WITH CHECK clause by design — you're
-- removing rows, not validating writes. SEC006 explicitly
-- skips DELETE; pin the contract so a future regression that
-- extends SEC006 to DELETE fails this case loudly.
-- ============================================================

CREATE TABLE app.todos_archive (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    body TEXT
);
ALTER TABLE app.todos_archive ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.todos_archive FORCE ROW LEVEL SECURITY;
CREATE POLICY archive_owner_delete ON app.todos_archive
    AS RESTRICTIVE
    FOR DELETE TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
