-- A small Supabase-style schema for `pgrls matrix --prove`: three API roles,
-- an auth.uid() that reads the JWT subject, and five tables. Two policies
-- carry real bugs, one table is reachable through a definer view, one uses a
-- pattern the prover cannot decide, and one is correct.

CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN BYPASSRLS;

CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS text LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '') $$;
GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role;

-- Correct: each user reads their own profile.
CREATE TABLE public.profiles (user_id text PRIMARY KEY, display_name text);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY own_profile ON public.profiles FOR SELECT
  USING (user_id = auth.uid());

-- Bug 1: the inverted auth check. Meant as "signed-in users see their own
-- notes", it also admits every row to a session with no JWT at all.
CREATE TABLE public.notes (id int, tenant_id text, body text);
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_notes ON public.notes FOR SELECT
  USING (auth.uid() IS NULL OR tenant_id = auth.uid());

-- Bug 2: a "public" flag added for a share link, with no tenant check on it.
CREATE TABLE public.invoices (id int, tenant_id text, amount numeric, is_public bool);
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_invoices ON public.invoices FOR SELECT
  USING (tenant_id = auth.uid() OR is_public);

-- Correctly scoped table, but a dashboard view owned by the superuser runs
-- as its owner (security_invoker is off), so anon reaches the rows through it.
CREATE TABLE public.orders (id int, tenant_id text, total numeric);
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_orders ON public.orders FOR SELECT
  USING (tenant_id = auth.uid());
CREATE VIEW public.order_summaries AS SELECT id, tenant_id, total FROM public.orders;
GRANT SELECT ON public.order_summaries TO anon;

-- Team membership through a sub-select: the prover cannot decide it, so the
-- cell is UNKNOWN rather than a guess.
CREATE TABLE public.memberships (user_id text, team_id text);
ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY own_memberships ON public.memberships FOR SELECT
  USING (user_id = auth.uid());
CREATE TABLE public.team_docs (id int, team_id text, title text);
ALTER TABLE public.team_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_docs FORCE ROW LEVEL SECURITY;
CREATE POLICY team_docs_members ON public.team_docs FOR SELECT
  USING (team_id IN (SELECT m.team_id FROM public.memberships m
                     WHERE m.user_id = auth.uid()));

GRANT SELECT ON public.profiles, public.notes, public.invoices, public.orders,
                public.memberships, public.team_docs
  TO anon, authenticated, service_role;
