-- SEC002: RLS enabled but FORCE missing.
-- Both tables carry a RESTRICTIVE token policy so SEC009 (RLS
-- enabled, no policies) and SEC003 (permissive PUBLIC) don't fire
-- and confound the SEC002 assertions.
CREATE TABLE public.sec002_target (id INT);
ALTER TABLE public.sec002_target ENABLE ROW LEVEL SECURITY;
-- Note: no ALTER TABLE ... FORCE ROW LEVEL SECURITY.
CREATE POLICY sec002_target_p ON public.sec002_target
    AS RESTRICTIVE FOR SELECT TO PUBLIC USING (id > 0);

CREATE TABLE public.sec002_clean (id INT);
ALTER TABLE public.sec002_clean ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sec002_clean FORCE ROW LEVEL SECURITY;
CREATE POLICY sec002_clean_p ON public.sec002_clean
    AS RESTRICTIVE FOR SELECT TO PUBLIC USING (id > 0);
