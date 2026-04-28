-- ============================================================
-- Use case 49: GDPR-style classification with ARRAY — CLEAN
-- A row's `visible_to` array names the audience tags that may
-- read it. Combined with classification levels in a CASE, the
-- policy walks ARRAY ANY plus CASE branches plus column refs.
-- ============================================================

CREATE TABLE app.gdpr_records (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    classification TEXT NOT NULL,  -- 'public' | 'internal' | 'restricted'
    visible_to TEXT[] NOT NULL DEFAULT ARRAY['public']::TEXT[],
    payload JSONB
);
ALTER TABLE app.gdpr_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.gdpr_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_plus_classification ON app.gdpr_records
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        AND CASE classification
            WHEN 'public'     THEN true
            WHEN 'internal'   THEN (SELECT current_setting('app.role', true)) <> 'guest'
            WHEN 'restricted' THEN (SELECT current_setting('app.role', true)) = ANY(visible_to)
            ELSE false
        END
    );
