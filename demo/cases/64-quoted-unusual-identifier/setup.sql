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
    user_id TEXT
);
ALTER TABLE app."MixedCase Table" ENABLE ROW LEVEL SECURITY;
ALTER TABLE app."MixedCase Table" FORCE ROW LEVEL SECURITY;
CREATE POLICY mixed_owner ON app."MixedCase Table"
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
