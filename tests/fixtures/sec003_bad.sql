-- SEC003: a permissive policy granted to PUBLIC. The USING clause
-- references an own column to keep this fixture targeted on SEC003 —
-- otherwise SEC005 (no own-col ref) and SEC008 (USING true) would also
-- fire and muddle the assertions.
CREATE TABLE public.sec003_target (id INT);
ALTER TABLE public.sec003_target ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec003_target FORCE ROW LEVEL SECURITY;
CREATE POLICY public_read ON public.sec003_target
    FOR SELECT
    TO PUBLIC
    USING (id IS NOT NULL);

-- Same shape but RESTRICTIVE — should NOT fire SEC003. The
-- companion PERMISSIVE-postgres policy keeps SEC012 quiet
-- (Postgres needs at least one PERMISSIVE policy or the table
-- is silent deny-all).
CREATE TABLE public.sec003_clean (id INT);
ALTER TABLE public.sec003_clean ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec003_clean FORCE ROW LEVEL SECURITY;
CREATE POLICY restricted_read ON public.sec003_clean
    AS RESTRICTIVE
    FOR SELECT
    TO PUBLIC
    USING (id IS NOT NULL);
CREATE POLICY permit_read ON public.sec003_clean
    FOR SELECT
    TO postgres
    USING (id IS NOT NULL);
