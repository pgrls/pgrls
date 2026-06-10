-- ============================================================
-- Use case 90: anonymous-role write policy — SEC039
-- A permissive WRITE policy granting the unauthenticated `anon`
-- role lets anonymous PostgREST/Supabase clients modify rows.
-- SEC039 fires on the INSERT policy. The sibling FOR SELECT TO
-- anon policy is a deliberate public-read pattern, so SEC039
-- stays SILENT on it — the rule's defining write-only scope,
-- pinned here through live introspection. (`TO anon` is a real
-- role, not the PUBLIC pseudo-role, so this is distinct from
-- SEC003's concern.)
-- ============================================================

-- The Supabase unauthenticated role (the demo otherwise uses
-- app_authenticated). NOLOGIN, no BYPASSRLS — a plain role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN;
    END IF;
END
$$;

CREATE TABLE app.public_submissions (
    id BIGSERIAL PRIMARY KEY,
    is_published BOOLEAN NOT NULL DEFAULT false,
    body TEXT
);
ALTER TABLE app.public_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.public_submissions FORCE ROW LEVEL SECURITY;

-- Legitimate public READ of published rows. Anonymous browsing is
-- intended here, so SEC039 must NOT fire on this policy.
CREATE POLICY public_submissions_anon_read ON app.public_submissions
    FOR SELECT TO anon
    USING (is_published);

-- The bug: anonymous clients can INSERT. SEC039 fires (error) —
-- restrict TO app_authenticated and revoke anon's write grant, or
-- route the write through a SECURITY DEFINER function.
CREATE POLICY public_submissions_anon_write ON app.public_submissions
    FOR INSERT TO anon
    WITH CHECK (body IS NOT NULL);
