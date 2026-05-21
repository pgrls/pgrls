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
-- USING is a literal true (SEC008). SEC022 also fires here — the lone
-- policy is FOR SELECT, so the table has read coverage but no
-- write-side policy. SEC022's rule_loc pin targets the dedicated
-- allbad_sec022 block below, so this extra firing is silent-by-design.
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

-- SEC019: policy reads tenant context via one-argument
-- current_setting(). The one-arg form raises on an unset GUC. The
-- two-arg current_setting('app.tenant', true) form returns NULL
-- instead. SEC019 is info-severity. The current_setting call is
-- wrapped in (SELECT ...) so PERF001 stays silent (it flags only
-- UNWRAPPED auth calls). The base table mirrors the other RLS-on
-- blocks (RESTRICTIVE policy, own-column reference, indexed
-- predicate column) so SEC001/SEC002/SEC005/SEC006/SEC007/SEC008/
-- SEC009/PERF003 stay silent and only SEC019 fires. SEC012 also
-- fires (RESTRICTIVE-only set) and carries no rule_loc pin, so
-- that extra firing is silent-by-design.
CREATE TABLE public.allbad_sec019 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_sec019 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec019 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.allbad_sec019
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant')));
CREATE INDEX allbad_sec019_tenant_idx
    ON public.allbad_sec019 (tenant_id);

-- SEC020: policy pairs a restrictive USING with WITH CHECK (true).
-- USING limits which rows the caller can read, but WITH CHECK
-- (true) accepts every row it writes, so the caller can write rows
-- it could never read back (an INSERT or UPDATE into another
-- tenant's space). The base table mirrors the other RLS-on blocks
-- (RESTRICTIVE policy, own-column USING, indexed predicate column)
-- so SEC001/SEC002/SEC005/SEC006/SEC007/SEC008/SEC009/PERF003 stay
-- silent and only SEC020 fires. SEC012 also fires here (the policy
-- set is RESTRICTIVE-only, like the SEC018/SEC019 base tables) and
-- carries no rule_loc pin, so that extra firing is silent-by-design.
CREATE TABLE public.allbad_sec020 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_sec020 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec020 FORCE ROW LEVEL SECURITY;
CREATE POLICY open_write_check ON public.allbad_sec020
    AS RESTRICTIVE FOR ALL TO PUBLIC
    USING (tenant_id IS NOT NULL)
    WITH CHECK (true);
CREATE INDEX allbad_sec020_tenant_idx
    ON public.allbad_sec020 (tenant_id);

-- SEC021: policy compares an identity column against a hardcoded
-- literal. USING (tenant_id = 1) pins the policy to one tenant, so
-- every session gets the same fixed rows instead of being scoped
-- to its own tenant. SEC021 is info-severity (it uses a column-
-- name heuristic). The base table mirrors the other RLS-on blocks
-- (RESTRICTIVE policy, own-column USING, indexed predicate column)
-- so SEC001/SEC002/SEC005/SEC006/SEC007/SEC008/SEC009/PERF003 stay
-- silent and only SEC021 fires. SEC012 also fires (RESTRICTIVE-only
-- set) and carries no rule_loc pin, so that extra firing is
-- silent-by-design.
CREATE TABLE public.allbad_sec021 (id INT, tenant_id INT);
ALTER TABLE public.allbad_sec021 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec021 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_pinned ON public.allbad_sec021
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = 1);
CREATE INDEX allbad_sec021_tenant_idx
    ON public.allbad_sec021 (tenant_id);

-- HYG003: two policies on the table are exact duplicates of each
-- other, identical in command, roles, and USING predicate and
-- differing only in name. A copy-paste or migration leftover: the
-- second policy is dead weight. HYG003 is info-severity. The base
-- table mirrors the other RLS-on blocks (RESTRICTIVE policies,
-- own-column USING, indexed predicate column) so SEC001/SEC002/
-- SEC005/SEC006/SEC007/SEC008/SEC009/PERF003 stay silent and only
-- HYG003 fires. SEC012 also fires (the policy set is
-- RESTRICTIVE-only) and carries no rule_loc pin, so that extra
-- firing is silent-by-design.
CREATE TABLE public.allbad_hyg003 (id INT, tenant_id INT);
ALTER TABLE public.allbad_hyg003 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_hyg003 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope_a ON public.allbad_hyg003
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id IS NOT NULL);
CREATE POLICY tenant_scope_b ON public.allbad_hyg003
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id IS NOT NULL);
CREATE INDEX allbad_hyg003_tenant_idx
    ON public.allbad_hyg003 (tenant_id);

-- SEC022: every policy on an RLS-enabled table is FOR SELECT, so the
-- table has working read coverage but no write-side policy — INSERT
-- is denied and UPDATE / DELETE silently affect zero rows. SEC022 is
-- info-severity. The table pairs a PERMISSIVE FOR SELECT policy (so
-- reads actually work and SEC022's premise holds — a restrictive-only
-- table denies reads too and is SEC012's surface instead) with a
-- RESTRICTIVE FOR SELECT floor (so SEC007 stays silent). Both
-- predicates reference an indexed own column through a wrapped
-- current_setting, so SEC001/SEC002/SEC005/SEC008/SEC009/PERF001/
-- PERF003 stay silent, and the two policies differ in permissive kind
-- so HYG003 sees no duplicate. SEC003 also fires here (the permissive
-- policy is granted TO PUBLIC) — its rule_loc pin targets the
-- allbad_sec003 block, so that extra firing is silent-by-design.
CREATE TABLE public.allbad_sec022 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_sec022 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec022 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON public.allbad_sec022
    FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE POLICY tenant_floor ON public.allbad_sec022
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE INDEX allbad_sec022_tenant_idx
    ON public.allbad_sec022 (tenant_id);

-- SEC023: a policy whose TO clause names a role carrying the
-- BYPASSRLS attribute (allbad_sec016_role, created in the SEC016
-- block above). A BYPASSRLS role skips every RLS policy, so the
-- policy's USING predicate is never evaluated for it — the TO
-- reference is inert. The base table mirrors the other RLS-on
-- blocks (a RESTRICTIVE policy with an own-column USING through a
-- wrapped current_setting, and an indexed predicate column) so
-- SEC001/SEC002/SEC005/SEC008/SEC009/PERF001/PERF003 stay silent
-- and only SEC023 fires here. SEC012 also fires (the policy set is
-- RESTRICTIVE-only, like the other base tables) and carries no
-- rule_loc pin, so that extra firing is silent-by-design.
--
-- Granting a policy TO a role records a SHARED_DEPENDENCY_POLICY
-- entry, so DROP ROLE is blocked while this policy exists — the
-- combined-fixture test's `finally` drops the public schema
-- (cascading this policy away) before dropping the role.
CREATE TABLE public.allbad_sec023 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_sec023 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec023 FORCE ROW LEVEL SECURITY;
CREATE POLICY bypassed_grant ON public.allbad_sec023
    AS RESTRICTIVE FOR SELECT TO allbad_sec016_role
    USING (tenant_id = (SELECT current_setting('app.tenant', true)));
CREATE INDEX allbad_sec023_tenant_idx
    ON public.allbad_sec023 (tenant_id);

-- SEC024: policy reads tenant context via an unqualified
-- current_setting() parameter name. A customized run-time
-- parameter must be qualified (`app.tenant`) — the unqualified
-- `tenant` here can never be SET, so the policy silently matches
-- no rows. The two-argument current_setting form keeps SEC019
-- silent (SEC019 flags the one-argument overload), and the call
-- is wrapped in (SELECT ...) so PERF001 stays silent. The base
-- table mirrors the other RLS-on blocks (RESTRICTIVE policy,
-- own-column reference, indexed predicate column) so SEC001/
-- SEC002/SEC005/SEC007/SEC008/SEC009/PERF003 stay silent and only
-- SEC024 fires. SEC012 also fires (RESTRICTIVE-only policy set)
-- and carries no rule_loc pin, so that extra firing is
-- silent-by-design.
CREATE TABLE public.allbad_sec024 (id INT, tenant_id TEXT);
ALTER TABLE public.allbad_sec024 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec024 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.allbad_sec024
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('tenant', true)));
CREATE INDEX allbad_sec024_tenant_idx
    ON public.allbad_sec024 (tenant_id);

-- SEC025: policy predicate references a table that has RLS
-- disabled. The ACL table allbad_sec025_acl has no RLS enabled
-- (SEC001 also fires on it — silent-by-design, the SEC001 pin
-- targets allbad_sec001), and the policy on allbad_sec025 reads
-- from it through a sub-select. An attacker who can write to
-- allbad_sec025_acl can grant themselves access through this
-- policy. The base RLS table mirrors the other RLS-on blocks
-- (RESTRICTIVE policy, own-column USING, indexed predicate
-- column) so SEC001/SEC002/SEC005/SEC008/SEC009/PERF001/PERF003
-- stay silent and only SEC025 fires on the policy. SEC012 also
-- fires (RESTRICTIVE-only policy set) and carries no rule_loc
-- pin, so that extra firing is silent-by-design.
CREATE TABLE public.allbad_sec025_acl (user_id INT, tenant_id INT);
CREATE TABLE public.allbad_sec025 (id INT, tenant_id INT);
ALTER TABLE public.allbad_sec025 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec025 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.allbad_sec025
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (
        tenant_id IN (
            SELECT tenant_id FROM public.allbad_sec025_acl
        )
    );
CREATE INDEX allbad_sec025_tenant_idx
    ON public.allbad_sec025 (tenant_id);

-- SEC026: policy predicate uses LIKE pattern matching against an
-- auth-context value. A malicious GUC set to '%' would match every
-- row, defeating the per-row isolation entirely. The standard fix
-- is `lower(user_email) = lower(current_setting('app.email', true))`
-- or just a plain `=`. Base RLS state mirrors the other RLS-on
-- blocks (RESTRICTIVE policy, own-column USING, indexed predicate
-- column, qualified GUC name, two-arg current_setting wrapped in a
-- SELECT) so SEC001/SEC002/SEC005/SEC008/SEC009/SEC019/SEC024/
-- PERF001/PERF003 stay silent and only SEC026 fires on the policy.
-- SEC012 also fires (RESTRICTIVE-only policy set) and carries no
-- rule_loc pin, so that extra firing is silent-by-design.
CREATE TABLE public.allbad_sec026 (id INT, user_email TEXT);
ALTER TABLE public.allbad_sec026 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec026 FORCE ROW LEVEL SECURITY;
CREATE POLICY email_pattern ON public.allbad_sec026
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (
        user_email LIKE (SELECT current_setting('app.email', true))
    );
CREATE INDEX allbad_sec026_email_idx
    ON public.allbad_sec026 (user_email);

-- SEC027: RLS table has a principal column (owner_id) that no
-- policy scopes by. The policy keys on tenant_id only, so every
-- user within a tenant can read every other user's rows — a
-- per-user leak inside a single tenant. owner_id is present on the
-- table but referenced by no policy. Base RLS state mirrors the
-- other RLS-on blocks (RESTRICTIVE policy, own-column USING on
-- tenant_id, indexed predicate column, qualified GUC name, two-arg
-- current_setting wrapped in a SELECT) so SEC001/SEC002/SEC005/
-- SEC008/SEC009/SEC019/SEC024/PERF001/PERF003 stay silent and only
-- SEC027 fires on the table. SEC012 also fires (RESTRICTIVE-only
-- policy set) and carries no rule_loc pin, so that extra firing is
-- silent-by-design.
CREATE TABLE public.allbad_sec027 (id INT, tenant_id INT, owner_id INT);
ALTER TABLE public.allbad_sec027 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec027 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.allbad_sec027
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true))::int);
CREATE INDEX allbad_sec027_tenant_idx
    ON public.allbad_sec027 (tenant_id);

-- SEC028: permissive write policy with WITH CHECK (true) accepts
-- every write the command covers. FOR INSERT has no USING, so the
-- write side is open with nothing to contrast — SEC020's asymmetry
-- needs a real USING, SEC006 needs WITH CHECK absent. Granted TO
-- postgres (not PUBLIC) so SEC003 stays quiet. Two extra firings
-- are silent-by-design (each pinned on its own block): SEC005
-- (the constant-true WITH CHECK references no own column) and
-- SEC007 (the table's only policy is permissive — no RESTRICTIVE
-- floor). Those shapes are intrinsic to the minimal SEC028 trigger
-- (a literal-true WITH CHECK can't reference a column).
CREATE TABLE public.allbad_sec028 (id INT, tenant_id INT);
ALTER TABLE public.allbad_sec028 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec028 FORCE ROW LEVEL SECURITY;
CREATE POLICY open_insert ON public.allbad_sec028
    FOR INSERT TO postgres
    WITH CHECK (true);

-- SEC029: a role that can SET ROLE to a BYPASSRLS role. BYPASSRLS
-- is a role attribute and is NOT inherited through membership, so
-- allbad_sec029_member does not bypass RLS automatically (SEC016
-- stays quiet on it — it has no BYPASSRLS of its own). But it is a
-- member of allbad_sec016_role (the BYPASSRLS role created in the
-- SEC016 block above), so it can `SET ROLE allbad_sec016_role` and
-- bypass every policy from there — an RLS-bypass path SEC029
-- surfaces. The member role and the membership grant are dropped in
-- the combined-fixture test's teardown alongside allbad_sec016_role
-- (roles are cluster-global).
DROP ROLE IF EXISTS allbad_sec029_member;
CREATE ROLE allbad_sec029_member;
GRANT allbad_sec016_role TO allbad_sec029_member;

-- SEC030: a policy scopes row access by a NULLABLE discriminator
-- column. tenant_id has no NOT NULL constraint, so a row with a NULL
-- tenant_id is invisible to every tenant under `=` today and is a
-- latent cross-tenant leak the moment a NULL-tolerant predicate
-- appears. The auth value is wrapped in `(SELECT current_setting())`
-- (PERF001's recommended form) — SEC030 detects it through the scalar
-- sub-select while keeping tenant_id as the direct operand. Base RLS
-- state mirrors the other RLS-on blocks (RESTRICTIVE policy, own-column
-- USING, indexed predicate column, qualified GUC name, two-arg
-- current_setting wrapped in a SELECT) so SEC001/SEC002/SEC005/SEC008/
-- SEC009/SEC019/SEC024/PERF001/PERF003 stay silent and only SEC030
-- fires here. SEC012 also fires (RESTRICTIVE-only policy set) and
-- SEC022 (FOR SELECT-only) — neither carries a rule_loc pin, so those
-- extra firings are silent-by-design.
CREATE TABLE public.allbad_sec030 (id INT, tenant_id INT);
ALTER TABLE public.allbad_sec030 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec030 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.allbad_sec030
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true))::int);
CREATE INDEX allbad_sec030_tenant_idx
    ON public.allbad_sec030 (tenant_id);

-- SEC031: a RESTRICTIVE policy whose USING is constant `true`.
-- Restrictive policies AND-combine, so `USING (true)` restricts
-- nothing — a no-op security floor that looks like a boundary but
-- enforces none. The PERMISSIVE companion `perm_real` carries a real
-- own-column predicate (`id > 0`) and is granted TO postgres, so it
-- keeps SEC012 (restrictive-only deny-all) and SEC003 (permissive to
-- PUBLIC) quiet and is not itself a finding. Its predicate column
-- `id` is indexed so PERF003 stays silent (matching the SEC030 block
-- convention). Two extra firings are silent-by-design (each pinned on
-- its own block): SEC005 (the constant-true restrictive policy
-- references no own column) and SEC022 (both policies are FOR SELECT —
-- no write-side policy). Those shapes are intrinsic to the minimal
-- SEC031 trigger.
CREATE TABLE public.allbad_sec031 (id INT);
ALTER TABLE public.allbad_sec031 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec031 FORCE ROW LEVEL SECURITY;
CREATE POLICY perm_real ON public.allbad_sec031
    FOR SELECT TO postgres
    USING (id > 0);
CREATE POLICY restrictive_noop ON public.allbad_sec031
    AS RESTRICTIVE FOR SELECT TO PUBLIC
    USING (true);
CREATE INDEX allbad_sec031_id_idx ON public.allbad_sec031 (id);

-- SEC032: a table with a policy but NO `ENABLE ROW LEVEL SECURITY`.
-- The policy sits dormant in pg_policy and enforces nothing — the
-- table is wide open despite looking RLS-managed. SEC001 cedes this
-- table to SEC032 (it has policies), so only SEC032 fires here. The
-- policy is granted TO postgres (not PUBLIC) so SEC003 stays quiet,
-- references the own column `id` so SEC005 stays quiet, and `id` is
-- indexed so PERF003 stays quiet. RLS being off keeps SEC022 / SEC009
-- silent too.
CREATE TABLE public.allbad_sec032 (id INT);
CREATE POLICY dormant ON public.allbad_sec032
    FOR SELECT TO postgres
    USING (id > 0);
CREATE INDEX allbad_sec032_id_idx ON public.allbad_sec032 (id);
