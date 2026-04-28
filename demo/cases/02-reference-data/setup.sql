-- ============================================================
-- Use case 2: Reference data — ALLOWLISTED
-- World-readable lookup table with no RLS. Demonstrates the
-- pgrls.toml allowlist mechanism. SEC001 is silenced for this
-- table only, by name, in [lint.rules.SEC001].
-- ============================================================

CREATE TABLE app.countries (
    code CHAR(2) PRIMARY KEY,
    name TEXT NOT NULL
);
INSERT INTO app.countries (code, name) VALUES
    ('US', 'United States'),
    ('CA', 'Canada'),
    ('GB', 'United Kingdom');
