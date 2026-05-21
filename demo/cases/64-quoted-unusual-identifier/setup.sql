-- ============================================================
-- Use case 64: Quoted/unusual identifier — CLEAN
-- Postgres allows mixed-case and reserved-word identifiers
-- via double-quoting. The introspector pulls names from
-- pg_class as plain strings; the lint output and allowlist
-- both treat them as plain strings (no extra quoting). Pin
-- that this round-trip works.
-- ============================================================

CREATE TABLE app."MixedCase Table" (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL
);
ALTER TABLE app."MixedCase Table" ENABLE ROW LEVEL SECURITY;
ALTER TABLE app."MixedCase Table" FORCE ROW LEVEL SECURITY;
-- PERMISSIVE policy on the quoted-identifier table. Pins that
-- the round-trip works for unusual names (the case's whole
-- point) including for the new authenticated-access policy.
CREATE POLICY "MixedCase authenticated access" ON app."MixedCase Table"
    FOR ALL TO app_authenticated
    USING (user_id = (SELECT current_setting('app.user', true)))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY mixed_owner ON app."MixedCase Table"
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
