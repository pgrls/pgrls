-- pgrls demo fixture.
--
-- This shared schema is consumed by 84 use cases (cases/01–84) that
-- together exercise every lint rule (SEC001–SEC011, PERF001–PERF002,
-- HYG001–HYG002), the `pgrls.testing` pytest plugin (case 80), and
-- the four `pgrls diff` classifications (cases 81–84: DANGEROUS,
-- SAFE, REQUIRES_REVIEW, BREAKING). Per-case `setup.sql` files add
-- their own fixtures on top of this shared base.
--
-- Each block here is labeled with the rule(s) it demonstrates and
-- whether the example is intentionally violating or clean.
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
