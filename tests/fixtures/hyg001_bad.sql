-- HYG001: a policy whose USING references a column that has since been
-- dropped. Postgres 16+ prevents DROP COLUMN when a policy depends on it,
-- so we simulate the orphaned state by marking the column as dropped
-- directly in pg_attribute — the same internal state an older Postgres
-- version would have left behind.
CREATE TABLE public.hyg001_target (id INT, tenant_id TEXT, gone TEXT);
ALTER TABLE public.hyg001_target ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hyg001_target FORCE ROW LEVEL SECURITY;
CREATE POLICY orphaned ON public.hyg001_target
    FOR SELECT
    TO PUBLIC
    USING (gone = 'x');
-- The fake-drop hack below sets `attisdropped = true` on the
-- `gone` column. After that, introspection's index query
-- (`_INDEXES_SQL`, with `AND NOT a.attisdropped`) yields the
-- empty string for any index position referencing `gone`. PERF003
-- also filters out policy refs to columns not in `Table.columns`,
-- so the `gone` ref in the orphaned policy never reaches the
-- leading-column-index check. No index needed here — both
-- defenses (introspection filter + PERF003 live_columns filter)
-- keep the rule silent on this fixture.
UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'public.hyg001_target'::regclass
      AND attname = 'gone';

-- Clean: policy refs only existing columns. RESTRICTIVE keeps
-- SEC003 quiet, and the PERMISSIVE-postgres companion keeps
-- SEC012 quiet.
CREATE TABLE public.hyg001_clean (id INT, tenant_id TEXT);
ALTER TABLE public.hyg001_clean ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hyg001_clean FORCE ROW LEVEL SECURITY;
CREATE POLICY clean_ref ON public.hyg001_clean
    AS RESTRICTIVE
    FOR SELECT
    TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.t', true)));
CREATE POLICY clean_permit ON public.hyg001_clean
    FOR SELECT
    TO postgres
    USING (tenant_id = (SELECT current_setting('app.t', true)));
-- Index tenant_id so PERF003 doesn't fire on the clean fixture.
CREATE INDEX hyg001_clean_tenant_idx ON public.hyg001_clean (tenant_id);
