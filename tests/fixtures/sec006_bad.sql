-- Each fixture table gets a CREATE INDEX on its policy filter
-- column so PERF003 doesn't fire and muddle SEC006's rule-set
-- assertion. sec006_insert's WITH CHECK is `true` (no col ref) so
-- it needs no index. The other three filter on `tenant_id`.

-- SEC006: INSERT policy with no WITH CHECK.
CREATE TABLE public.sec006_insert (id INT, tenant_id TEXT);
ALTER TABLE public.sec006_insert ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_insert FORCE ROW LEVEL SECURITY;
CREATE POLICY insert_bad ON public.sec006_insert
    FOR INSERT
    TO PUBLIC
    WITH CHECK (true);

-- update_bad / all_bad: permissive UPDATE/ALL with a *real* USING and no
-- WITH CHECK. SEC006 must NOT fire here: Postgres reuses the USING
-- expression as the implicit WITH CHECK, so the written row must still
-- satisfy `tenant_id = …` — the write side is constrained, not open.
-- They stay in this fixture to exercise SEC003/SEC007/PERF001/SEC030 and
-- to pin the reuse-suppression regression (SEC006 silent on this shape).
CREATE TABLE public.sec006_update (id INT, tenant_id TEXT);
ALTER TABLE public.sec006_update ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_update FORCE ROW LEVEL SECURITY;
CREATE POLICY update_bad ON public.sec006_update
    FOR UPDATE
    TO PUBLIC
    USING (tenant_id = current_setting('app.t', true));
CREATE INDEX sec006_update_tenant_idx ON public.sec006_update (tenant_id);

CREATE TABLE public.sec006_all (id INT, tenant_id TEXT);
ALTER TABLE public.sec006_all ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_all FORCE ROW LEVEL SECURITY;
CREATE POLICY all_bad ON public.sec006_all
    FOR ALL
    TO PUBLIC
    USING (tenant_id = current_setting('app.t', true));
CREATE INDEX sec006_all_tenant_idx ON public.sec006_all (tenant_id);

-- SEC006 DOES fire on a genuinely-open write: a permissive INSERT policy
-- with no WITH CHECK has no USING for Postgres to reuse, so it admits
-- every inserted row. `tenant_id` is NOT NULL and the policy carries no
-- predicate, so PERF001/PERF003/SEC030 stay silent and SEC006 is the
-- write-side finding on this table.
CREATE TABLE public.sec006_open (id INT, tenant_id TEXT NOT NULL);
ALTER TABLE public.sec006_open ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_open FORCE ROW LEVEL SECURITY;
CREATE POLICY open_insert ON public.sec006_open
    FOR INSERT
    TO PUBLIC;

-- Clean: RESTRICTIVE UPDATE policy with WITH CHECK present —
-- SEC006 does not fire. RESTRICTIVE type keeps SEC003 from
-- firing, and a PERMISSIVE-postgres companion keeps SEC012 quiet.
-- tenant_id is NOT NULL: a genuinely clean RLS table scopes by a
-- non-nullable discriminator, so SEC030 stays silent here.
CREATE TABLE public.sec006_clean (id INT, tenant_id TEXT NOT NULL);
ALTER TABLE public.sec006_clean ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_clean FORCE ROW LEVEL SECURITY;
CREATE POLICY update_ok ON public.sec006_clean
    AS RESTRICTIVE
    FOR UPDATE
    TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.t', true)))
    WITH CHECK (tenant_id = (SELECT current_setting('app.t', true)));
CREATE POLICY update_permit ON public.sec006_clean
    FOR UPDATE
    TO postgres
    USING (tenant_id = (SELECT current_setting('app.t', true)))
    WITH CHECK (tenant_id = (SELECT current_setting('app.t', true)));
CREATE INDEX sec006_clean_tenant_idx ON public.sec006_clean (tenant_id);
