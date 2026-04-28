-- ============================================================
-- Use case 52: SEC003 fires once per offending policy
-- Two PERMISSIVE policies on the same table, both granted to
-- PUBLIC. Pin that SEC003 emits one violation per policy
-- (not per table), so a multi-policy table with two violations
-- shows both lines in the output.
-- ============================================================

CREATE TABLE app.multi_perm (
    id BIGSERIAL PRIMARY KEY,
    title TEXT,
    body TEXT
);
ALTER TABLE app.multi_perm ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.multi_perm FORCE ROW LEVEL SECURITY;
CREATE POLICY perm_a ON app.multi_perm
    FOR SELECT TO PUBLIC USING (length(title) > 0);
CREATE POLICY perm_b ON app.multi_perm
    FOR SELECT TO PUBLIC USING (length(body) > 0);
