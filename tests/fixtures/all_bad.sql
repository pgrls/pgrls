-- One fixture that triggers every rule shipping in this release.
-- Each block carries a comment naming the rule it targets.

-- SEC001: RLS disabled.
CREATE TABLE public.allbad_sec001 (id INT);

-- SEC002: RLS enabled, FORCE missing.
CREATE TABLE public.allbad_sec002 (id INT);
ALTER TABLE public.allbad_sec002 ENABLE ROW LEVEL SECURITY;

-- SEC003: permissive policy granted to PUBLIC.
CREATE TABLE public.allbad_sec003 (id INT);
ALTER TABLE public.allbad_sec003 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.allbad_sec003 FORCE ROW LEVEL SECURITY;
CREATE POLICY public_perm ON public.allbad_sec003
    FOR SELECT TO PUBLIC USING (true);

-- SEC004: inverted auth check.
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

-- SEC006: UPDATE policy missing WITH CHECK.
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
