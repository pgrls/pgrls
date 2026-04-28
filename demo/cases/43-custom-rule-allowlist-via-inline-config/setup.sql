-- ============================================================
-- Use case 43: Custom rule allowlist via inline config —
-- SEC003 intentional public read
-- A read-only metadata table that the application
-- intentionally exposes to PUBLIC. The companion test runs
-- pgrls with `[lint.rules.SEC003].allowlist =
-- ["app.public_metadata.metadata_read"]`. SEC003 still fires
-- without the override.
-- ============================================================

CREATE TABLE app.public_metadata (
    id BIGSERIAL PRIMARY KEY,
    key TEXT NOT NULL,
    value TEXT
);
ALTER TABLE app.public_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.public_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY metadata_read ON app.public_metadata
    FOR SELECT TO PUBLIC
    USING (key NOT LIKE 'private.%');
