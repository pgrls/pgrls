-- ============================================================
-- Use case 37: HYG001 — per-policy isolation
-- Two policies on the same table; one references a dropped
-- column, the other does not. Pin that HYG001 fires only on
-- the offending policy and leaves the clean one alone — a
-- regression that broadens the scope to "any policy on a
-- table with any orphan" would fail this assertion loudly.
-- ============================================================

CREATE TABLE app.partial_orphan (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    gone TEXT
);
ALTER TABLE app.partial_orphan ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partial_orphan FORCE ROW LEVEL SECURITY;
CREATE POLICY clean_owner ON app.partial_orphan
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY orphan_filter ON app.partial_orphan
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (gone = 'x');

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.partial_orphan'::regclass
      AND attname = 'gone';
