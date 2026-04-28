-- ============================================================
-- Use case 56: HYG001 with `gone IS TRUE` (BoolTest) — fires
-- A BoolTest wraps a column ref. extract_column_refs needs to
-- walk through the BoolTest to see the orphaned column.
-- ============================================================

CREATE TABLE app.booltest_orphan (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    gone BOOLEAN
);
ALTER TABLE app.booltest_orphan ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.booltest_orphan FORCE ROW LEVEL SECURITY;
CREATE POLICY bt_check ON app.booltest_orphan
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT current_setting('app.user', true))
        AND gone IS TRUE
    );

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.booltest_orphan'::regclass
      AND attname = 'gone';
