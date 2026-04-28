-- ============================================================
-- Use case 73: RLS enabled, no policies — SEC009 (new in 0.0.6)
-- A migration enabled RLS planning to add policies later, then
-- forgot. The table now silently rejects every query — looks
-- "RLS protected" but is actually deny-all. SEC009 catches the
-- forgotten step.
-- ============================================================

CREATE TABLE app.deny_all_log (
    id BIGSERIAL,
    event TEXT
);
ALTER TABLE app.deny_all_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.deny_all_log FORCE ROW LEVEL SECURITY;
-- No CREATE POLICY here. SEC009 fires.
