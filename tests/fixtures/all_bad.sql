-- One fixture that triggers every rule shipping in this release.
-- Each block carries a comment naming the rule(s) it targets.

-- SEC001: RLS disabled.
CREATE TABLE public.allbad_sec001 (id INT);

-- SEC002 + SEC009: RLS enabled, FORCE missing, AND no policies
-- defined. The empty policy list is what SEC009 catches. The
-- missing FORCE is what SEC002 catches. Same shape exercises both.
CREATE TABLE public.allbad_sec002 (id INT);
ALTER TABLE public.allbad_sec002 ENABLE ROW LEVEL SECURITY;

-- SEC003 + SEC005 + SEC007 + SEC008: permissive policy granted to PUBLIC
-- with USING (true). One block, four rules — true has no own-col ref
-- (SEC005), the table has only permissive policies (SEC007), and the
-- USING is a literal true (SEC008).
CREATE TABLE public.allbad_sec003 (id INT);
ALTER TABLE public.allbad_sec003 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec003 FORCE ROW LEVEL SECURITY;
CREATE POLICY public_perm ON public.allbad_sec003
    FOR SELECT TO PUBLIC USING (true);

-- SEC004 + PERF001: inverted auth check, with current_setting unwrapped
-- in USING. RESTRICTIVE keeps SEC003 quiet on this table.
CREATE TABLE public.allbad_sec004 (id INT, user_id TEXT);
ALTER TABLE public.allbad_sec004 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec004 FORCE ROW LEVEL SECURITY;
CREATE POLICY inverted ON public.allbad_sec004
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        current_setting('app.user_id', true) IS NULL
        OR user_id = current_setting('app.user_id', true)
    );

-- SEC006: UPDATE policy missing WITH CHECK. (current_setting is also
-- unwrapped here, so PERF001 fires on this policy too — that's
-- intentional, the combined fixture is meant to exercise every rule.)
CREATE TABLE public.allbad_sec006 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_sec006 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec006 FORCE ROW LEVEL SECURITY;
CREATE POLICY update_no_check ON public.allbad_sec006
    AS RESTRICTIVE
    FOR UPDATE TO PUBLIC
    USING (tenant_id = current_setting('app.t', true));

-- HYG001: orphaned column reference. Postgres 16 prevents real DROP COLUMN
-- when a policy depends on it, so simulate the orphaned state by marking
-- the column as dropped in pg_attribute (same internal state an older
-- Postgres version would have left).
CREATE TABLE public.allbad_hyg001 (id INT, gone TEXT);
ALTER TABLE public.allbad_hyg001 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_hyg001 FORCE ROW LEVEL SECURITY;
CREATE POLICY orphan ON public.allbad_hyg001
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC USING (gone = 'x');
UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'public.allbad_hyg001'::regclass
      AND attname = 'gone';

-- SEC010 + SEC005: deny-all anti-pattern. USING (false) denies
-- every row through the policy form (the right primitive is REVOKE
-- ALL ON TABLE x FROM <role>). SEC005 also fires because the
-- predicate has no own-column reference.
CREATE TABLE public.allbad_sec010 (id INT);
ALTER TABLE public.allbad_sec010 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec010 FORCE ROW LEVEL SECURITY;
CREATE POLICY block_all ON public.allbad_sec010
    AS RESTRICTIVE FOR SELECT TO PUBLIC USING (false);

-- SEC011: policy expression has an `OR true` branch. Common shape
-- of a leftover debug bypass that admits every row regardless of
-- the rest of the predicate.
CREATE TABLE public.allbad_sec011 (id INT, owner_id TEXT);
ALTER TABLE public.allbad_sec011 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec011 FORCE ROW LEVEL SECURITY;
CREATE POLICY or_true_bypass ON public.allbad_sec011
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (owner_id = 'x' OR true);

-- PERF002: policy expression uses a VOLATILE function. `random()`
-- in USING re-evaluates per row, producing non-deterministic
-- visibility. STABLE alternatives (`now()`, `current_setting`)
-- don't fire — only the volatile set does.
CREATE TABLE public.allbad_perf002 (id INT, score FLOAT);
ALTER TABLE public.allbad_perf002 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_perf002 FORCE ROW LEVEL SECURITY;
CREATE POLICY randomized ON public.allbad_perf002
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (score < random());

-- HYG002: policy named like a placeholder (`todo_*`). Common
-- shape of a forgotten scaffold from an unfinished migration.
CREATE TABLE public.allbad_hyg002 (id INT, owner_id TEXT);
ALTER TABLE public.allbad_hyg002 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_hyg002 FORCE ROW LEVEL SECURITY;
CREATE POLICY todo_replace_me_later ON public.allbad_hyg002
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (owner_id = 'x');

-- VIEW001: view over RLS-protected table without `security_invoker`.
-- The base table has RLS enabled and a RESTRICTIVE policy with an
-- own-column reference and a wrapped `current_setting` (so SEC001,
-- SEC005, SEC007, SEC008, SEC009, PERF001 stay silent on it). The
-- view itself runs with the owner's privileges and bypasses RLS,
-- which is exactly what VIEW001 catches.
--
-- The view is created `WITH (security_barrier = true)` so VIEW002
-- stays silent here — VIEW002's own block below pins that rule's
-- behavior on a separately-named view.
CREATE TABLE public.allbad_view001_base (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_view001_base ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_view001_base FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_floor ON public.allbad_view001_base
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE INDEX allbad_view001_base_tenant_idx
    ON public.allbad_view001_base (tenant_id);
CREATE VIEW public.allbad_view001
    WITH (security_barrier = true) AS
    SELECT * FROM public.allbad_view001_base;

-- VIEW002: view over RLS-protected table without `security_barrier`.
-- The view is created `WITH (security_invoker = true)` so VIEW001
-- stays silent — pinning VIEW002 firing on a distinct table+view
-- pair makes the rule_loc contract test catch a rule drifting onto
-- the wrong view. The base table mirrors VIEW001's policy shape.
CREATE TABLE public.allbad_view002_base (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_view002_base ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_view002_base FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_floor ON public.allbad_view002_base
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE INDEX allbad_view002_base_tenant_idx
    ON public.allbad_view002_base (tenant_id);
CREATE VIEW public.allbad_view002
    WITH (security_invoker = true) AS
    SELECT * FROM public.allbad_view002_base;

-- VIEW003: materialized view over RLS-protected table. Matviews
-- capture rows at REFRESH time per the refresher's privileges and
-- do NOT honor RLS on subsequent queries — VIEW001/VIEW002 don't
-- apply (matviews lack `security_invoker` / `security_barrier`
-- reloptions, and both rules early-exit on `is_materialized=True`).
-- The base table mirrors VIEW001/VIEW002's policy shape so SEC and
-- PERF rules stay silent on it.
CREATE TABLE public.allbad_view003_base (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_view003_base ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_view003_base FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_floor ON public.allbad_view003_base
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE INDEX allbad_view003_base_tenant_idx
    ON public.allbad_view003_base (tenant_id);
CREATE MATERIALIZED VIEW public.allbad_view003 AS
    SELECT * FROM public.allbad_view003_base;

-- VIEW004: view that calls a SECURITY DEFINER function that reads
-- an RLS-protected table. The function bypasses RLS via the
-- function owner's privileges, so even though the view is
-- configured `security_invoker = true` + `security_barrier = true`
-- (silencing VIEW001 and VIEW002), the SECDEF call inside the body
-- is the leak vector — that's the gap VIEW004 catches.
--
-- The view is a regular (non-materialized) view so VIEW003 stays
-- silent. The view's `references` does NOT include
-- `allbad_view004_base` (pg_depend tracks function-result deps via
-- pg_proc, not pg_class), so VIEW001 has nothing to flag here.
-- The base table mirrors the other VIEW blocks' policy shape so
-- the SEC and PERF rules stay silent on it.
CREATE TABLE public.allbad_view004_base (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_view004_base ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_view004_base FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_floor ON public.allbad_view004_base
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE INDEX allbad_view004_base_tenant_idx
    ON public.allbad_view004_base (tenant_id);
CREATE FUNCTION public.allbad_view004_read()
    RETURNS SETOF public.allbad_view004_base
    LANGUAGE sql SECURITY DEFINER AS
    'SELECT * FROM public.allbad_view004_base';
CREATE VIEW public.allbad_view004
    WITH (security_invoker = true, security_barrier = true) AS
    SELECT * FROM public.allbad_view004_read();

-- SEC013: trigger on an RLS-protected table. Triggers fire as the
-- table OWNER, so the trigger function body bypasses the invoking
-- role's RLS policies, a quiet privilege-escalation vector that
-- this rule prompts the operator to audit. The base table mirrors
-- the other RLS-on blocks (RESTRICTIVE policy with wrapped
-- `current_setting`) so SEC001/SEC002/SEC005/SEC007/SEC008/SEC009/
-- PERF001 stay silent on it. SEC012 also fires on this table
-- because the policy set is RESTRICTIVE-only (mirroring the
-- VIEW001-VIEW004 base tables) and SEC012 carries no rule_loc pin
-- so the extra firing is silent-by-design.
--
-- The trigger function is `pg_catalog.suppress_redundant_updates_trigger`,
-- a Postgres built-in that takes no arguments and returns TRIGGER.
-- Used here because conftest.apply_sql does a naive split on the
-- SQL terminator and can't handle PL/pgSQL bodies. A built-in
-- trigger function sidesteps the need to declare a user function
-- inside this fixture. The `tgisinternal` distinction is about
-- WHO created the trigger, not which function it calls. This
-- CREATE TRIGGER is user-issued, so `tgisinternal = false` and
-- SEC013 sees it just like any user-authored trigger calling a
-- plpgsql function.
CREATE TABLE public.allbad_sec013 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_sec013 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec013 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_floor ON public.allbad_sec013
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE INDEX allbad_sec013_tenant_idx ON public.allbad_sec013 (tenant_id);
CREATE TRIGGER audit_writes
    BEFORE UPDATE ON public.allbad_sec013
    FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();

-- PERF003: policy predicate column without a leading-column index.
-- The other RLS-enabled tables in this fixture all carry an index
-- on their policy filter column so PERF003 doesn't fire on them.
-- This dedicated block keeps PERF003 pinned to exactly one
-- location for the rule_loc contract in test_cli.
CREATE TABLE public.allbad_perf003 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_perf003 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_perf003 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_unindexed ON public.allbad_perf003
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));

-- SEC016: a non-superuser role carrying the BYPASSRLS attribute.
-- Such a role skips every RLS policy on every table. Unlike every
-- other block in this fixture, this one creates a *role* — roles
-- are cluster-global and are NOT reset by the per-test schema
-- teardown. `DROP ROLE IF EXISTS` makes a re-run idempotent, and
-- the test that applies this fixture drops the role in a `finally`
-- so a stray BYPASSRLS role can't leak into the shared container
-- and trip SEC016 in the clean-DB e2e test. The role is left
-- NOLOGIN (the CREATE ROLE default) — SEC016 fires on any
-- non-superuser BYPASSRLS role regardless of login capability.
DROP ROLE IF EXISTS allbad_sec016_role;
CREATE ROLE allbad_sec016_role BYPASSRLS;

-- SEC017: a function carrying the LEAKPROOF attribute. The planner
-- may evaluate a LEAKPROOF function below a security barrier (the
-- RLS qual, or a security_barrier view filter). If it is not
-- genuinely side-channel-free it leaks RLS-protected rows. It is
-- created SECURITY INVOKER (the CREATE FUNCTION default) so that
-- SEC014 and SEC015 — which flag SECURITY DEFINER functions — stay
-- silent on it, leaving only SEC017 to fire here. Unlike the
-- SEC016 role above, a function is schema-scoped, so the per-test
-- `DROP SCHEMA public CASCADE` reset cleans it up with no manual
-- teardown needed.
CREATE FUNCTION public.allbad_sec017_leaky(int) RETURNS boolean
    LANGUAGE sql LEAKPROOF AS 'SELECT $1 > 0';

-- SEC018: policy compares a column against current_user.
-- current_user identifies the session's Postgres role, a constant
-- under a shared application pool role — so `owner_role =
-- current_user` gives no per-tenant isolation. The base table
-- mirrors the other RLS-on blocks (a RESTRICTIVE policy with an
-- own-column reference and an indexed predicate column) so
-- SEC001/SEC002/SEC005/SEC006/SEC007/SEC008/SEC009/PERF003 stay
-- silent on it and only SEC018 fires. SEC012 also fires here
-- (RESTRICTIVE-only policy set, like the VIEW and SEC013 base tables) and
-- carries no rule_loc pin, so that extra firing is silent-by-design.
CREATE TABLE public.allbad_sec018 (id INT, owner_role TEXT);
ALTER TABLE public.allbad_sec018 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec018 FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_is_current_user ON public.allbad_sec018
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (owner_role = current_user);
CREATE INDEX allbad_sec018_owner_idx
    ON public.allbad_sec018 (owner_role);
