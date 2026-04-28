-- ============================================================
-- Use case 42: Multi-schema scan — `tenant` schema
-- pgrls accepts multiple schemas in `database.schemas` (or
-- via `--schemas a,b`). This adds a `tenant` schema with a
-- single bad table; the companion test runs pgrls with
-- `--schemas app,tenant` and asserts SEC001 fires on
-- `tenant.tenant_orphans`.
-- ============================================================

CREATE SCHEMA tenant;
CREATE TABLE tenant.tenant_orphans (
    id BIGSERIAL PRIMARY KEY,
    name TEXT
);
