-- SEC004: the Lovable CVE pattern. A SELECT policy with
-- `current_setting(...) IS NULL OR ...` — anonymous clients pass through.
-- We use current_setting in the fixture because it doesn't require the
-- Supabase auth schema to exist on a stock Postgres image.
CREATE TABLE public.sec004_target (id INT, user_id TEXT);
ALTER TABLE public.sec004_target ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec004_target FORCE ROW LEVEL SECURITY;
CREATE POLICY inverted_auth ON public.sec004_target
    FOR SELECT
    TO PUBLIC
    USING (
        current_setting('app.user_id', true) IS NULL
        OR user_id = current_setting('app.user_id', true)
    );

-- Clean: positive auth check, no IS NULL disjunct. RESTRICTIVE
-- keeps SEC003 quiet, and the PERMISSIVE-postgres companion
-- keeps SEC012 quiet.
CREATE TABLE public.sec004_clean (id INT, user_id TEXT);
ALTER TABLE public.sec004_clean ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec004_clean FORCE ROW LEVEL SECURITY;
CREATE POLICY positive_auth ON public.sec004_clean
    AS RESTRICTIVE
    FOR SELECT
    TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user_id', true)));
CREATE POLICY permit_auth ON public.sec004_clean
    FOR SELECT
    TO postgres
    USING (user_id = (SELECT current_setting('app.user_id', true)));
