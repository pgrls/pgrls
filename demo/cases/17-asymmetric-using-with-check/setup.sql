-- ============================================================
-- Use case 17: Asymmetric USING / WITH CHECK — CLEAN
-- Read your team's tickets, write only your own. A common
-- real-world shape: USING and WITH CHECK do different things
-- on purpose. pgrls accepts this — none of the rules complain
-- about asymmetry as long as both clauses are present and
-- reference table columns.
-- ============================================================

CREATE TABLE app.tickets (
    id BIGSERIAL PRIMARY KEY,
    team_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    subject TEXT
);
ALTER TABLE app.tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tickets FORCE ROW LEVEL SECURITY;
CREATE POLICY read_team_write_own ON app.tickets
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (team_id = (SELECT current_setting('app.team', true)::UUID))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
