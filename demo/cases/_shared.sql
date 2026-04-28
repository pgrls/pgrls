-- pgrls demo fixture.
--
-- 15 use cases that together exercise every rule shipping in 0.0.4
-- (SEC001-SEC008, PERF001, HYG001) plus the partition-aware paths.
-- Each block is labeled with the rule(s) it is meant to demonstrate
-- and whether the example is intentionally violating or clean.
--
-- The fixture is idempotent: it drops the demo schemas at the top so
-- you can re-apply it freely.

DROP SCHEMA IF EXISTS app CASCADE;
DROP SCHEMA IF EXISTS private CASCADE;
DROP SCHEMA IF EXISTS auth CASCADE;
DROP SCHEMA IF EXISTS tenant CASCADE;  -- created by uc42's setup.sql
CREATE SCHEMA app;
CREATE SCHEMA private;

-- Stub Supabase-style auth functions so use cases 19-21 can call
-- `auth.uid()` etc. without running a real Supabase stack. The
-- function bodies just read GUCs, which mirrors how Supabase wires
-- the JWT claims into the session.
CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS UUID
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claim.sub', true)::UUID $$;
CREATE FUNCTION auth.role() RETURNS TEXT
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claim.role', true) $$;
CREATE FUNCTION auth.jwt() RETURNS JSONB
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claims', true)::JSONB $$;
