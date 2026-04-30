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
CREATE VIEW public.allbad_view002
    WITH (security_invoker = true) AS
    SELECT * FROM public.allbad_view002_base;
