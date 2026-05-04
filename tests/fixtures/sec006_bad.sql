-- SEC006: INSERT policy with no WITH CHECK.
CREATE TABLE public.sec006_insert (id INT, tenant_id TEXT);
ALTER TABLE public.sec006_insert ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_insert FORCE ROW LEVEL SECURITY;
CREATE POLICY insert_bad ON public.sec006_insert
    FOR INSERT
    TO PUBLIC
    WITH CHECK (true);

-- SEC006 fires on UPDATE with USING-only (UPDATE can omit WITH CHECK).
CREATE TABLE public.sec006_update (id INT, tenant_id TEXT);
ALTER TABLE public.sec006_update ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_update FORCE ROW LEVEL SECURITY;
CREATE POLICY update_bad ON public.sec006_update
    FOR UPDATE
    TO PUBLIC
    USING (tenant_id = current_setting('app.t', true));

-- SEC006 fires on ALL with USING-only.
CREATE TABLE public.sec006_all (id INT, tenant_id TEXT);
ALTER TABLE public.sec006_all ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec006_all FORCE ROW LEVEL SECURITY;
CREATE POLICY all_bad ON public.sec006_all
    FOR ALL
    TO PUBLIC
    USING (tenant_id = current_setting('app.t', true));

-- Clean: RESTRICTIVE UPDATE policy with WITH CHECK present —
-- SEC006 does not fire. RESTRICTIVE type keeps SEC003 from
-- firing, and a PERMISSIVE-postgres companion keeps SEC012 quiet.
CREATE TABLE public.sec006_clean (id INT, tenant_id TEXT);
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
