-- SEC003: a permissive policy granted to PUBLIC.
CREATE TABLE public.sec003_target (id INT);
ALTER TABLE public.sec003_target ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec003_target FORCE ROW LEVEL SECURITY;
CREATE POLICY public_read ON public.sec003_target
    FOR SELECT
    TO PUBLIC
    USING (true);

-- Same shape but RESTRICTIVE — should NOT fire SEC003.
CREATE TABLE public.sec003_clean (id INT);
ALTER TABLE public.sec003_clean ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec003_clean FORCE ROW LEVEL SECURITY;
CREATE POLICY restricted_read ON public.sec003_clean
    AS RESTRICTIVE
    FOR SELECT
    TO PUBLIC
    USING (true);
