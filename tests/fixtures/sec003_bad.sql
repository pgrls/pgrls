-- SEC003: a permissive policy granted to PUBLIC. The USING clause
-- references an own column to keep this fixture targeted on SEC003 —
-- otherwise SEC005 (no own-col ref) and SEC008 (USING true) would also
-- fire and muddle the assertions.
-- PRIMARY KEY on `id` creates an implicit B-tree so PERF003
-- doesn't fire on the `id IS NOT NULL` policy predicate. SEC003
-- targets PERMISSIVE-to-PUBLIC state, not index health.
CREATE TABLE public.sec003_target (id INT PRIMARY KEY);
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
CREATE TABLE public.sec003_clean (id INT PRIMARY KEY);
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
