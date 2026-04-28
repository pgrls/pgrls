-- ============================================================
-- Use case 65: SEC001 allowlist by qualified vs unqualified —
-- both forms work
-- The default config allowlists `app.countries` (qualified).
-- pgrls also accepts unqualified names. Test under a config
-- that allowlists `legacy_orders` (uc03) by unqualified name —
-- SEC001 silences for it the same way.
-- ============================================================

-- (No new fixture — uses uc03's app.legacy_orders.)
