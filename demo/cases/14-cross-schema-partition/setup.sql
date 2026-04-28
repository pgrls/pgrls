-- ============================================================
-- Use case 14: Cross-schema partition — SEC001 unscoped variant
-- The parent lives in `private` (NOT in the scanned schemas);
-- the child lives in `app`. With `--schemas app`, pgrls cannot
-- see the parent's RLS state, so SEC001 fires on the child with
-- the differentiated "leaves the scanned schemas" message.
-- ============================================================

CREATE TABLE private.audit_log (
    id BIGSERIAL,
    happened_at TIMESTAMPTZ NOT NULL,
    actor_id TEXT,
    action TEXT
) PARTITION BY RANGE (happened_at);

ALTER TABLE private.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_owner ON private.audit_log
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (actor_id = (SELECT current_setting('app.user', true)));

CREATE TABLE app.audit_log_2026 PARTITION OF private.audit_log
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
