-- pgrls demo fixture.
--
-- 15 use cases that together exercise every rule shipping in 0.0.4
-- (SEC001-SEC008, PERF001, HYG001) plus the partition-aware paths.
-- Each block is labeled with the rule(s) it is meant to demonstrate
-- and whether the example is intentionally violating or clean.
--
-- The fixture is idempotent: it drops the demo schemas at the top so
-- you can re-apply it freely.

DROP SCHEMA IF EXISTS app CASCADE;
DROP SCHEMA IF EXISTS private CASCADE;
DROP SCHEMA IF EXISTS auth CASCADE;
CREATE SCHEMA app;
CREATE SCHEMA private;

-- Stub Supabase-style auth functions so use cases 19-21 can call
-- `auth.uid()` etc. without running a real Supabase stack. The
-- function bodies just read GUCs, which mirrors how Supabase wires
-- the JWT claims into the session.
CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS UUID
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claim.sub', true)::UUID $$;
CREATE FUNCTION auth.role() RETURNS TEXT
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claim.role', true) $$;
CREATE FUNCTION auth.jwt() RETURNS JSONB
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claims', true)::JSONB $$;


-- ============================================================
-- Use case 01: Multi-tenant SaaS table — CLEAN
-- The canonical good shape. ENABLE + FORCE + RESTRICTIVE policy
-- with USING and WITH CHECK. pgrls should NOT flag this table.
-- ============================================================
CREATE TABLE app.documents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app.documents
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));

INSERT INTO app.documents (tenant_id, title, body) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Tenant A: roadmap', 'Q3 plans'),
    ('00000000-0000-0000-0000-000000000001', 'Tenant A: review',  'feedback'),
    ('00000000-0000-0000-0000-000000000002', 'Tenant B: launch',  'go live');


-- ============================================================
-- Use case 02: Reference data — ALLOWLISTED
-- World-readable lookup table with no RLS. Demonstrates the
-- pgrls.toml allowlist mechanism. SEC001 is silenced for this
-- table only, by name, in [lint.rules.SEC001].
-- ============================================================
CREATE TABLE app.countries (
    code CHAR(2) PRIMARY KEY,
    name TEXT NOT NULL
);
INSERT INTO app.countries (code, name) VALUES
    ('US', 'United States'),
    ('CA', 'Canada'),
    ('GB', 'United Kingdom');


-- ============================================================
-- Use case 03: Missing RLS — SEC001
-- Tenant table where someone enabled the policies elsewhere but
-- forgot the table-level switch. Every authenticated role can
-- read every row.
-- ============================================================
CREATE TABLE app.legacy_orders (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    total_cents INT
);

INSERT INTO app.legacy_orders (tenant_id, total_cents) VALUES
    ('00000000-0000-0000-0000-000000000001', 1000),
    ('00000000-0000-0000-0000-000000000002', 2500),
    ('00000000-0000-0000-0000-000000000002', 4200);


-- ============================================================
-- Use case 04: RLS but no FORCE — SEC002
-- ENABLE without FORCE. The table owner role bypasses RLS, which
-- masks broken policies in dev/CI when the migration tool is the
-- owner.
-- ============================================================
CREATE TABLE app.notes (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    content TEXT
);
ALTER TABLE app.notes ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE app.notes FORCE ROW LEVEL SECURITY;  -- intentionally omitted
CREATE POLICY notes_owner ON app.notes
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));


-- ============================================================
-- Use case 05: Permissive PUBLIC — SEC003
-- Permissive (default) policy granted to PUBLIC. Permissive
-- policies OR with every other policy on the table; this single
-- entry can wash out tenant policies that someone adds later.
-- ============================================================
CREATE TABLE app.posts (
    id BIGSERIAL PRIMARY KEY,
    author_id TEXT,
    body TEXT
);
ALTER TABLE app.posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.posts FORCE ROW LEVEL SECURITY;
CREATE POLICY everyone_reads ON app.posts
    FOR SELECT TO PUBLIC
    USING (true);  -- also fires SEC005, SEC007, SEC008


-- ============================================================
-- Use case 06: Inverted auth — SEC004
-- A top-level OR with `current_setting() IS NULL`. When the
-- session variable isn't set (fresh connection, misconfigured
-- pool), the predicate is true for every row. This is the shape
-- of the public Lovable RLS CVE.
-- ============================================================
CREATE TABLE app.accounts (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    balance_cents INT
);
ALTER TABLE app.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY allow_unset_user ON app.accounts
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        current_setting('app.user', true) IS NULL
        OR user_id = current_setting('app.user', true)
    );  -- also fires PERF001 (current_setting unwrapped)


-- ============================================================
-- Use case 07: Session-state-only policy — SEC005
-- Policy expression has no own-column reference. The predicate
-- evaluates the same for every row in the table, so the table is
-- gated by who-asks rather than by which-row.
-- ============================================================
CREATE TABLE app.singletons (
    key TEXT PRIMARY KEY,
    value JSONB
);
ALTER TABLE app.singletons ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.singletons FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_only ON app.singletons
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (current_setting('app.role', true) = 'admin');
    -- also fires PERF001


-- ============================================================
-- Use case 08: UPDATE without WITH CHECK — SEC006
-- USING gates which rows the user can SEE. WITH CHECK gates which
-- rows they can WRITE. Without WITH CHECK on UPDATE, a tenant can
-- "move" a row to another tenant by changing tenant_id.
-- ============================================================
CREATE TABLE app.invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    amount_cents INT
);
ALTER TABLE app.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY update_without_check ON app.invoices
    AS RESTRICTIVE
    FOR UPDATE TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
    -- WITH CHECK omitted — fires SEC006


-- ============================================================
-- Use case 09: All policies permissive — SEC007 (info)
-- Single permissive policy, no restrictive floor. A restrictive
-- policy combines with AND, which gives you a hard floor (e.g.
-- "tenant_id must match") that no future permissive policy can
-- bypass via OR.
-- ============================================================
CREATE TABLE app.tags (
    id BIGSERIAL PRIMARY KEY,
    name TEXT
);
ALTER TABLE app.tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tags FORCE ROW LEVEL SECURITY;
CREATE POLICY tags_visible ON app.tags
    FOR SELECT TO PUBLIC
    USING (true);  -- also fires SEC003, SEC005, SEC008


-- ============================================================
-- Use case 10: USING (true) — SEC008
-- A policy whose USING is the literal `true` adds no protection;
-- it is almost always a leftover from prototyping. Wrapped here
-- in an isolated table (RESTRICTIVE so SEC003 doesn't fire).
-- ============================================================
CREATE TABLE app.feature_flags (
    name TEXT PRIMARY KEY,
    enabled BOOLEAN
);
ALTER TABLE app.feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.feature_flags FORCE ROW LEVEL SECURITY;
CREATE POLICY public_flags ON app.feature_flags
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (true);  -- also fires SEC005


-- ============================================================
-- Use case 11: Unwrapped auth in USING — PERF001
-- `current_setting(...)` (or `auth.uid()` etc.) called inline is
-- re-evaluated per row. Wrap in `(SELECT ...)` so Postgres caches
-- it once per statement.
-- ============================================================
CREATE TABLE app.messages (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    body TEXT
);
ALTER TABLE app.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.messages FORCE ROW LEVEL SECURITY;
CREATE POLICY messages_owner ON app.messages
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = current_setting('app.user', true));  -- not wrapped


-- ============================================================
-- Use case 12: Orphaned column reference — HYG001
-- A policy references a column that has been dropped. Postgres 16
-- refuses real DROP COLUMN while a policy depends on it, so the
-- fixture simulates the orphan by editing pg_attribute directly
-- — the same internal state older Postgres versions could leave.
-- ============================================================
CREATE TABLE app.comments (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    archived BOOLEAN DEFAULT false
);
ALTER TABLE app.comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.comments FORCE ROW LEVEL SECURITY;
CREATE POLICY archived_filter ON app.comments
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        (SELECT current_setting('app.user', true)) = user_id
        AND NOT archived
    );

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.comments'::regclass
      AND attname = 'archived';


-- ============================================================
-- Use case 13: Partitioned parent — CLEAN
-- Time-partitioned table with RLS+FORCE+RESTRICTIVE policy on the
-- parent. Children inherit the policy at query time. SEC001 walks
-- each child's partition_of chain and suppresses the violation
-- (the parent has RLS), so neither parent nor children fire.
-- ============================================================
CREATE TABLE app.events (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    payload JSONB
) PARTITION BY RANGE (ts);

CREATE TABLE app.events_2025 PARTITION OF app.events
    FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE app.events_2026 PARTITION OF app.events
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

ALTER TABLE app.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.events FORCE ROW LEVEL SECURITY;
CREATE POLICY events_tenant ON app.events
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));

INSERT INTO app.events (tenant_id, ts, payload) VALUES
    ('00000000-0000-0000-0000-000000000001', '2025-06-01', '{"e":"login"}'),
    ('00000000-0000-0000-0000-000000000001', '2026-03-15', '{"e":"upload"}'),
    ('00000000-0000-0000-0000-000000000002', '2026-04-20', '{"e":"export"}');


-- ============================================================
-- Use case 14: Cross-schema partition — SEC001 unscoped variant
-- The parent lives in `private` (NOT in the scanned schemas);
-- the child lives in `app`. With `--schemas app`, pgrls cannot
-- see the parent's RLS state, so SEC001 fires on the child with
-- the differentiated "leaves the scanned schemas" message.
-- ============================================================
CREATE TABLE private.audit_log (
    id BIGSERIAL,
    happened_at TIMESTAMPTZ NOT NULL,
    actor_id TEXT,
    action TEXT
) PARTITION BY RANGE (happened_at);

ALTER TABLE private.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_owner ON private.audit_log
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (actor_id = (SELECT current_setting('app.user', true)));

CREATE TABLE app.audit_log_2026 PARTITION OF private.audit_log
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');


-- ============================================================
-- Use case 15: Partition family with no RLS anywhere —
-- SEC001 visible-root variant
-- Both parent and child are in scope and lack RLS. SEC001 fires
-- on the child with a message that names the parent
-- (`is a partition of app.bare_metrics`) so the maintainer fixes
-- the parent rather than enabling RLS only on this leaf.
-- ============================================================
CREATE TABLE app.bare_metrics (
    id BIGSERIAL,
    tenant_id UUID,
    ts TIMESTAMPTZ NOT NULL,
    value DOUBLE PRECISION
) PARTITION BY RANGE (ts);

CREATE TABLE app.bare_metrics_2026 PARTITION OF app.bare_metrics
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
-- No ENABLE ROW LEVEL SECURITY anywhere in this family.


-- ============================================================
-- Use case 16: Correlated EXISTS membership — CLEAN
-- The classic team/membership-table pattern. The policy joins
-- to `team_members` via a correlated EXISTS, referencing
-- `team_id` from the outer `team_documents` table. SEC005
-- must NOT fire here — the policy IS row-scoped through the
-- join. A regression in the SubLink walk would silently turn
-- this into a false positive (the C2 fix from 0.0.4).
--
-- NOTE on column naming: the membership table uses
-- `member_team_id` rather than `team_id` to keep the inner
-- subquery's name resolution unambiguous. With both columns
-- named `team_id`, Postgres would resolve the bare `team_id`
-- to the inner table's column (silent tautology) — not what
-- the author meant. Distinct names make the correlation
-- explicit.
-- ============================================================
CREATE TABLE app.team_members (
    member_team_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT,
    PRIMARY KEY (member_team_id, user_id)
);
ALTER TABLE app.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.team_members FORCE ROW LEVEL SECURITY;
CREATE POLICY team_members_self ON app.team_members
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));

CREATE TABLE app.team_documents (
    id BIGSERIAL PRIMARY KEY,
    team_id UUID NOT NULL,
    title TEXT NOT NULL
);
ALTER TABLE app.team_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.team_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY team_member_visibility ON app.team_documents
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        EXISTS (
            SELECT 1 FROM app.team_members tm
            WHERE tm.member_team_id = team_id
              AND tm.user_id = (SELECT current_setting('app.user', true))
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM app.team_members tm
            WHERE tm.member_team_id = team_id
              AND tm.user_id = (SELECT current_setting('app.user', true))
        )
    );


-- ============================================================
-- Use case 17: Asymmetric USING / WITH CHECK — CLEAN
-- Read your team's tickets, write only your own. A common
-- real-world shape: USING and WITH CHECK do different things
-- on purpose. pgrls accepts this — none of the rules complain
-- about asymmetry as long as both clauses are present and
-- reference table columns.
-- ============================================================
CREATE TABLE app.tickets (
    id BIGSERIAL PRIMARY KEY,
    team_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    subject TEXT
);
ALTER TABLE app.tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tickets FORCE ROW LEVEL SECURITY;
CREATE POLICY read_team_write_own ON app.tickets
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (team_id = (SELECT current_setting('app.team', true)::UUID))
    WITH CHECK (user_id = (SELECT current_setting('app.user', true)));


-- ============================================================
-- Use case 18: Soft-delete pattern — CLEAN
-- `deleted_at IS NULL` is a common way to filter out
-- tombstoned rows from default reads. Note that `deleted_at IS
-- NULL` is a column-IS-NULL test, NOT an `auth_func() IS NULL`
-- — SEC004 only flags the latter. Pin that distinction at the
-- demo level.
-- ============================================================
CREATE TABLE app.users_v2 (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    email TEXT NOT NULL,
    deleted_at TIMESTAMPTZ
);
ALTER TABLE app.users_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.users_v2 FORCE ROW LEVEL SECURITY;
CREATE POLICY hide_deleted ON app.users_v2
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        deleted_at IS NULL
        AND tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
    );


-- ============================================================
-- Use case 19: Supabase auth.uid() inverted — SEC004
-- The exact shape of the public Lovable RLS CVE: a top-level
-- OR with `auth.uid() IS NULL` lets anonymous connections see
-- every row. Distinct from use case 06 only in the function
-- name; pgrls's default `auth_functions` list covers both.
-- ============================================================
CREATE TABLE app.profiles (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    display_name TEXT
);
ALTER TABLE app.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY allow_anon ON app.profiles
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (auth.uid() IS NULL OR user_id = auth.uid());
    -- also fires PERF001 (auth.uid unwrapped)


-- ============================================================
-- Use case 20: Supabase auth.uid() unwrapped — PERF001
-- Inline `auth.uid()` is re-evaluated per row. Wrap as
-- `(SELECT auth.uid())` to let Postgres cache the result
-- once per statement.
-- ============================================================
CREATE TABLE app.todos (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    body TEXT
);
ALTER TABLE app.todos ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.todos FORCE ROW LEVEL SECURITY;
CREATE POLICY todos_owner ON app.todos
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.uid());  -- not wrapped


-- ============================================================
-- Use case 21: PERF001 silent on WITH CHECK — pin USING-only contract
-- An INSERT policy whose only auth call is in WITH CHECK. PERF001
-- is documented as USING-only (Postgres optimizes WITH CHECK
-- differently). Pinned by the demo so a future regression that
-- extends PERF001 to WITH CHECK fails this test loudly.
-- ============================================================
CREATE TABLE app.audit_inserts (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    event TEXT,
    happened_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE app.audit_inserts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_inserts FORCE ROW LEVEL SECURITY;
CREATE POLICY insert_self_only ON app.audit_inserts
    AS RESTRICTIVE
    FOR INSERT TO PUBLIC
    WITH CHECK (user_id = auth.uid());


-- ============================================================
-- Use case 22: HYG001 catches dropped column in WITH CHECK
-- Same orphan-column pattern as use case 12 but the only
-- reference to the dropped column is in WITH CHECK. Pin that
-- HYG001 walks both clauses, not just USING.
-- ============================================================
CREATE TABLE app.posts_v2 (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    moderation_status TEXT
);
ALTER TABLE app.posts_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.posts_v2 FORCE ROW LEVEL SECURITY;
CREATE POLICY only_approved_writes ON app.posts_v2
    AS RESTRICTIVE
    FOR INSERT TO PUBLIC
    WITH CHECK (
        user_id = (SELECT current_setting('app.user', true))
        AND moderation_status = 'approved'
    );

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.posts_v2'::regclass
      AND attname = 'moderation_status';


-- ============================================================
-- Use case 23: Three-level partition with RLS at root — CLEAN
-- Sub-partitioning (PARTITION BY ... PARTITION BY ...). SEC001
-- walks ancestors iteratively, so leaves whose chain reaches
-- the RLS-enabled root inherit coverage at any depth.
-- ============================================================
CREATE TABLE app.deep_events (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    bucket TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    payload JSONB
) PARTITION BY LIST (bucket);

CREATE TABLE app.deep_events_t1 PARTITION OF app.deep_events
    FOR VALUES IN ('t1') PARTITION BY RANGE (ts);
CREATE TABLE app.deep_events_t1_2026 PARTITION OF app.deep_events_t1
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

ALTER TABLE app.deep_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.deep_events FORCE ROW LEVEL SECURITY;
CREATE POLICY deep_tenant ON app.deep_events
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));


-- ============================================================
-- Use case 24: Partition with RLS pushed down to the leaf —
-- mixed coverage
-- The parent has no RLS but the leaf does. Per the AGENTS.md
-- guidance, this is the right pattern when direct child access
-- is part of the threat model: each leaf carries its own
-- protection, so direct queries against leaves can't bypass
-- a parent-level policy. SEC001 fires on the parent (no RLS
-- there) but is silent on the leaf (rls_enabled=true on the
-- leaf itself).
-- ============================================================
CREATE TABLE app.leaf_metrics (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    value DOUBLE PRECISION
) PARTITION BY RANGE (ts);

CREATE TABLE app.leaf_metrics_2026 PARTITION OF app.leaf_metrics
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

ALTER TABLE app.leaf_metrics_2026 ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.leaf_metrics_2026 FORCE ROW LEVEL SECURITY;
CREATE POLICY leaf_tenant ON app.leaf_metrics_2026
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));


-- ============================================================
-- Use case 25: View on top of an RLS-enabled table —
-- introspector skips
-- Views (relkind='v') aren't RLS-bearing — Postgres applies
-- the underlying table's RLS at evaluation time. The
-- introspector filters to relkind IN ('r', 'p'), so views
-- never enter pgrls's table list and no rule fires on them.
-- ============================================================
CREATE VIEW app.documents_view AS
    SELECT id, title, created_at FROM app.documents;


-- ============================================================
-- Use case 26: Blog with admin-role override — CLEAN
-- A real-world multi-policy shape. One RESTRICTIVE policy
-- enforces tenant isolation; one PERMISSIVE policy grants
-- read access to admins via auth.role(). Both clauses are
-- wrapped to avoid PERF001. SEC007 stays silent because the
-- table has at least one RESTRICTIVE policy (not all
-- permissive). SEC005 and SEC008 stay silent because both
-- clauses reference table columns and aren't `(true)`.
-- ============================================================
CREATE TABLE app.blog_posts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    author_id UUID NOT NULL,
    title TEXT,
    body TEXT,
    published BOOLEAN NOT NULL DEFAULT false
);
ALTER TABLE app.blog_posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.blog_posts FORCE ROW LEVEL SECURITY;
CREATE POLICY blog_tenant_floor ON app.blog_posts
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY blog_admin_or_author_read ON app.blog_posts
    FOR SELECT TO PUBLIC
    USING (
        (SELECT auth.role()) = 'admin'
        OR author_id = (SELECT current_setting('app.user', true)::UUID)
    );
-- One PERMISSIVE policy is granted to PUBLIC, but the policy is
-- column-anchored (`author_id = ...`), so SEC003 still fires —
-- this is intentional. Use case 31 below shows the way to silence
-- SEC003: grant to a non-PUBLIC role.


-- ============================================================
-- Use case 27: DELETE policy without WITH CHECK — CLEAN
-- DELETE policies have no WITH CHECK clause by design — you're
-- removing rows, not validating writes. SEC006 explicitly
-- skips DELETE; pin the contract so a future regression that
-- extends SEC006 to DELETE fails this case loudly.
-- ============================================================
CREATE TABLE app.todos_archive (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    body TEXT
);
ALTER TABLE app.todos_archive ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.todos_archive FORCE ROW LEVEL SECURITY;
CREATE POLICY archive_owner_delete ON app.todos_archive
    AS RESTRICTIVE
    FOR DELETE TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));


-- ============================================================
-- Use case 28: Tenant via JWT claim — CLEAN
-- Supabase-flavored: the tenant scope comes from the JWT
-- payload via `auth.jwt() ->> 'tenant_id'`. The wrap
-- `(SELECT auth.jwt())` keeps PERF001 silent.
-- ============================================================
CREATE TABLE app.jwt_documents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    title TEXT
);
ALTER TABLE app.jwt_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.jwt_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY jwt_tenant ON app.jwt_documents
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        tenant_id = ((SELECT auth.jwt()) ->> 'tenant_id')::UUID
    )
    WITH CHECK (
        tenant_id = ((SELECT auth.jwt()) ->> 'tenant_id')::UUID
    );


-- ============================================================
-- Use case 29: Public-or-tenant mix — CLEAN
-- "Some rows are world-readable (`is_public = true`); others
-- are tenant-scoped." The disjunction is column-anchored on
-- both sides — SEC005 stays silent because the predicate
-- references `is_public` AND `tenant_id`.
-- ============================================================
CREATE TABLE app.kb_articles (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    is_public BOOLEAN NOT NULL DEFAULT false,
    title TEXT
);
ALTER TABLE app.kb_articles ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.kb_articles FORCE ROW LEVEL SECURITY;
CREATE POLICY public_or_tenant ON app.kb_articles
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        is_public
        OR tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
    );


-- ============================================================
-- Use case 30: Composite tenant key — CLEAN
-- Real-world tenancy is sometimes multi-dimensional: tenant
-- AND environment, or tenant AND region. The policy AND-joins
-- the columns. SEC005 stays silent because both columns are
-- referenced; SEC003 stays silent because RESTRICTIVE.
-- ============================================================
CREATE TABLE app.composite_tenant (
    id BIGSERIAL,
    tenant_id UUID NOT NULL,
    env TEXT NOT NULL,
    payload JSONB,
    PRIMARY KEY (tenant_id, env, id)
);
ALTER TABLE app.composite_tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.composite_tenant FORCE ROW LEVEL SECURITY;
CREATE POLICY composite_isolation ON app.composite_tenant
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        AND env = (SELECT current_setting('app.env', true))
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        AND env = (SELECT current_setting('app.env', true))
    );


-- ============================================================
-- Use case 31: Permissive policy granted to a specific role
-- (NOT PUBLIC) — CLEAN against SEC003
-- SEC003 fires only when permissive AND TO PUBLIC. Granting
-- to a specific application role (here `app_authenticated`)
-- silences it. Demonstrates the canonical fix for SEC003 in
-- multi-tenant apps that use a service account.
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'app_authenticated') THEN
        CREATE ROLE app_authenticated NOLOGIN;
    END IF;
END $$;

CREATE TABLE app.scoped_views (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    payload JSONB
);
ALTER TABLE app.scoped_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.scoped_views FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_floor ON app.scoped_views
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY auth_role_read ON app.scoped_views
    FOR SELECT TO app_authenticated
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));


-- ============================================================
-- Use case 32: CASE expression in policy — CLEAN
-- A column-anchored predicate inside a `CASE ... END`. Pins
-- that extract_column_refs walks CASE branches: SEC005 must
-- find both `visibility` and `user_id` and stay silent.
-- ============================================================
CREATE TABLE app.case_policy (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    visibility TEXT
);
ALTER TABLE app.case_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.case_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY visibility_case ON app.case_policy
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        CASE visibility
            WHEN 'public'  THEN true
            WHEN 'private' THEN user_id = (SELECT current_setting('app.user', true))
            ELSE false
        END
    );


-- ============================================================
-- Use case 33: Classic INHERITS (non-declarative) — partition_of
-- stays None
-- Pre-declarative table inheritance still uses pg_inherits,
-- but `cc.relispartition` is false on the child. The
-- `_PARTITION_PARENTS_SQL` filter in introspect.py keys on
-- `relispartition = true`, so this child does NOT get a
-- `partition_of`, and SEC001 fires on both parent and child
-- with the standalone classic message.
-- ============================================================
CREATE TABLE app.legacy_parent (
    id BIGSERIAL PRIMARY KEY,
    payload TEXT
);
CREATE TABLE app.legacy_child (
    extra TEXT
) INHERITS (app.legacy_parent);


-- ============================================================
-- Use case 34: SEC004 nested IS NULL inside AND — CLEAN
-- The rule fires only on TOP-LEVEL OR disjuncts where one is
-- `auth_func() IS NULL`. A nested `... AND auth.uid() IS NULL`
-- (or `IS NULL` on a non-auth function) must NOT trip SEC004.
-- ============================================================
CREATE TABLE app.flags_table (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    flag_name TEXT
);
ALTER TABLE app.flags_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.flags_table FORCE ROW LEVEL SECURITY;
CREATE POLICY flags_owner ON app.flags_table
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT auth.uid())
        AND flag_name IS NOT NULL
    );


-- ============================================================
-- Use case 35: SEC005 with literal `USING (1=1)` — fires
-- Not the literal Boolean true but evaluates to it. SEC008's
-- detector keys on the literal Boolean `A_Const`, so the
-- (1=1) shape only fires SEC005 (no own-column reference);
-- SEC008 does NOT fire. Pin the asymmetry.
-- ============================================================
CREATE TABLE app.always_open (
    id BIGSERIAL PRIMARY KEY,
    label TEXT
);
ALTER TABLE app.always_open ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.always_open FORCE ROW LEVEL SECURITY;
CREATE POLICY trivially_open ON app.always_open
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (1 = 1);


-- ============================================================
-- Use case 36: pg_has_role admin escape — CLEAN
-- A common production pattern: tenant rows for normal users,
-- but service-level roles (here `pg_read_all_data`, a built-in
-- predefined role since PG 14) get to read everything. Note
-- that `pg_has_role` is NOT in PERF001's default
-- `auth_functions` set, so the unwrapped call is fine.
-- ============================================================
CREATE TABLE app.admin_overrides (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    note TEXT
);
ALTER TABLE app.admin_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.admin_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_or_admin ON app.admin_overrides
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')
    )
    WITH CHECK (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        OR pg_has_role(current_user, 'pg_read_all_data', 'MEMBER')
    );


-- ============================================================
-- Use case 37: HYG001 — per-policy isolation
-- Two policies on the same table; one references a dropped
-- column, the other does not. Pin that HYG001 fires only on
-- the offending policy and leaves the clean one alone — a
-- regression that broadens the scope to "any policy on a
-- table with any orphan" would fail this assertion loudly.
-- ============================================================
CREATE TABLE app.partial_orphan (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    gone TEXT
);
ALTER TABLE app.partial_orphan ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partial_orphan FORCE ROW LEVEL SECURITY;
CREATE POLICY clean_owner ON app.partial_orphan
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));
CREATE POLICY orphan_filter ON app.partial_orphan
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (gone = 'x');

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.partial_orphan'::regclass
      AND attname = 'gone';


-- ============================================================
-- Use case 38: PERF001 with `auth.jwt() ->> 'sub'` unwrapped
-- The JSON-text operator wraps a function call. PERF001 walks
-- through `JsonbExtractPathText` (or the `->>` operator's
-- arguments) to find unwrapped auth functions. Pin that.
-- ============================================================
CREATE TABLE app.jwt_unwrapped (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT
);
ALTER TABLE app.jwt_unwrapped ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.jwt_unwrapped FORCE ROW LEVEL SECURITY;
CREATE POLICY jwt_unwrapped_owner ON app.jwt_unwrapped
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.jwt() ->> 'sub');


-- ============================================================
-- Use case 39: Custom auth function — config-driven detection
-- An app-defined function (`app.current_user_id()`) wrapping
-- a session GUC. By default PERF001 doesn't know about it, so
-- this table is silent. The companion test invokes pgrls with
-- a one-off config that adds `app.current_user_id` to
-- PERF001's `auth_functions` list — at which point PERF001
-- catches the unwrapped call here.
-- ============================================================
CREATE FUNCTION app.current_user_id() RETURNS UUID
    LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('app.user', true)::UUID $$;

CREATE TABLE app.user_workspaces (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID
);
ALTER TABLE app.user_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.user_workspaces FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_owner ON app.user_workspaces
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = app.current_user_id());


-- ============================================================
-- Use case 40: Admin audit log — SEC005 allowlist demo
-- A legitimately session-state-only table: only admins read
-- the audit log, and the predicate is `auth.role() = 'admin'`.
-- The companion test runs pgrls with an inline config that
-- allowlists `app.admin_audit.admin_only_read`, demonstrating
-- the allowlist mechanism for known-good warnings.
-- ============================================================
CREATE TABLE app.admin_audit (
    id BIGSERIAL PRIMARY KEY,
    happened_at TIMESTAMPTZ DEFAULT now(),
    detail JSONB
);
ALTER TABLE app.admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.admin_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_only_read ON app.admin_audit
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING ((SELECT auth.role()) = 'admin');


-- ============================================================
-- Use case 41: Disabled rule — SEC007 turned off via --disable
-- The companion test runs `pgrls lint --disable SEC007` and
-- asserts SEC007 doesn't fire on `app.tags` (use case 09)
-- even though it would in the default run.
-- (No new fixture required — uses tags from uc09.)
-- ============================================================


-- ============================================================
-- Use case 42: Multi-schema scan — `tenant` schema
-- pgrls accepts multiple schemas in `database.schemas` (or
-- via `--schemas a,b`). This adds a `tenant` schema with a
-- single bad table; the companion test runs pgrls with
-- `--schemas app,tenant` and asserts SEC001 fires on
-- `tenant.tenant_orphans`.
-- ============================================================
CREATE SCHEMA tenant;
CREATE TABLE tenant.tenant_orphans (
    id BIGSERIAL PRIMARY KEY,
    name TEXT
);


-- ============================================================
-- Use case 43: Custom rule allowlist via inline config —
-- SEC003 intentional public read
-- A read-only metadata table that the application
-- intentionally exposes to PUBLIC. The companion test runs
-- pgrls with `[lint.rules.SEC003].allowlist =
-- ["app.public_metadata.metadata_read"]`. SEC003 still fires
-- without the override.
-- ============================================================
CREATE TABLE app.public_metadata (
    id BIGSERIAL PRIMARY KEY,
    key TEXT NOT NULL,
    value TEXT
);
ALTER TABLE app.public_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.public_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY metadata_read ON app.public_metadata
    FOR SELECT TO PUBLIC
    USING (key NOT LIKE 'private.%');


-- ============================================================
-- Use case 44: SQLValueFunction `current_user` in policy —
-- CLEAN against PERF001
-- `current_user` is in SEC004's default auth_functions set
-- but NOT in PERF001's. Postgres evaluates SQLValueFunctions
-- like `current_user` cheaply, so wrapping buys nothing — the
-- rule deliberately omits them. Pin the asymmetry from a real
-- DB rather than only the unit test in test_perf001.py.
-- ============================================================
CREATE TABLE app.current_user_check (
    id BIGSERIAL PRIMARY KEY,
    visibility TEXT
);
ALTER TABLE app.current_user_check ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.current_user_check FORCE ROW LEVEL SECURITY;
CREATE POLICY only_admin_role ON app.current_user_check
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (current_user = 'postgres' OR visibility = 'public');


-- ============================================================
-- Use case 45: Default partition — CLEAN
-- `PARTITION OF parent DEFAULT` is the catch-all partition.
-- Postgres still records it in pg_inherits with
-- relispartition = true, so introspect.py picks it up like
-- any partition; SEC001's ancestor walk reaches the
-- RLS-enabled root from the default leaf the same way.
-- ============================================================
CREATE TABLE app.region_metrics (
    id BIGSERIAL,
    region TEXT NOT NULL,
    value DOUBLE PRECISION
) PARTITION BY LIST (region);
CREATE TABLE app.region_metrics_us PARTITION OF app.region_metrics
    FOR VALUES IN ('us');
CREATE TABLE app.region_metrics_default PARTITION OF app.region_metrics DEFAULT;
ALTER TABLE app.region_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.region_metrics FORCE ROW LEVEL SECURITY;
CREATE POLICY region_visibility ON app.region_metrics
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (region = (SELECT current_setting('app.region', true)));


-- ============================================================
-- Use case 46: Generated column referenced in policy — CLEAN
-- `GENERATED ALWAYS AS (...) STORED` columns appear in
-- pg_attribute alongside regular columns. Policies can
-- reference them; HYG001 sees them as present. Pin that the
-- generated column is treated like any other.
-- ============================================================
CREATE TABLE app.gen_cols (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    user_id_norm TEXT GENERATED ALWAYS AS (lower(user_id)) STORED
);
ALTER TABLE app.gen_cols ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.gen_cols FORCE ROW LEVEL SECURITY;
CREATE POLICY gen_owner ON app.gen_cols
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id_norm = lower((SELECT current_setting('app.user', true))));


-- ============================================================
-- Use case 47: ARRAY column with ANY() — CLEAN
-- `<scalar> = ANY(array_col)` is a common pattern for tag-
-- based access ("rows whose visible_to array contains the
-- caller"). The column ref `tags` is on the RHS of `= ANY`.
-- Pin that extract_column_refs walks ArrayExpr / ANY
-- correctly so SEC005 stays silent.
-- ============================================================
CREATE TABLE app.array_tags (
    id BIGSERIAL PRIMARY KEY,
    tags TEXT[]
);
ALTER TABLE app.array_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.array_tags FORCE ROW LEVEL SECURITY;
CREATE POLICY in_tags ON app.array_tags
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        (SELECT current_setting('app.user', true)) = ANY(tags)
    );


-- ============================================================
-- Use case 48: E-commerce orders + items via FK tenant — CLEAN
-- Two related tables. Items inherit tenant scope through the
-- parent order via a SubLink lookup. Pins that the SubLink
-- walk reaches `tenant_id` on the outer table even when the
-- inner table's only correlation is the parent FK.
-- ============================================================
CREATE TABLE app.ec_orders (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    customer_email TEXT,
    total_cents INT
);
ALTER TABLE app.ec_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.ec_orders FORCE ROW LEVEL SECURITY;
CREATE POLICY orders_tenant ON app.ec_orders
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID))
    WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));

CREATE TABLE app.ec_order_items (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT NOT NULL REFERENCES app.ec_orders(id),
    sku TEXT,
    qty INT
);
ALTER TABLE app.ec_order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.ec_order_items FORCE ROW LEVEL SECURITY;
CREATE POLICY items_via_order ON app.ec_order_items
    AS RESTRICTIVE
    FOR ALL TO PUBLIC
    USING (
        EXISTS (
            SELECT 1 FROM app.ec_orders o
            WHERE o.id = order_id
              AND o.tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM app.ec_orders o
            WHERE o.id = order_id
              AND o.tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        )
    );


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


-- ============================================================
-- Use case 50: Read-replica style — SELECT-only policies clean
-- A read-only mirror of canonical data. Two SELECT policies
-- (one tenant floor RESTRICTIVE, one role-specific PERMISSIVE
-- granted to a non-PUBLIC role) and zero write policies.
-- Demonstrates that pgrls is silent on a clean read-only shape
-- — neither SEC006 (no writes to validate) nor SEC003 (the
-- permissive grant is to a specific role) fires.
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'app_replica_reader') THEN
        CREATE ROLE app_replica_reader NOLOGIN;
    END IF;
END $$;

CREATE TABLE app.read_replica (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    snapshot_at TIMESTAMPTZ DEFAULT now(),
    payload JSONB
);
ALTER TABLE app.read_replica ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.read_replica FORCE ROW LEVEL SECURITY;
CREATE POLICY replica_tenant_floor ON app.read_replica
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));
CREATE POLICY replica_reader_grant ON app.read_replica
    FOR SELECT TO app_replica_reader
    USING (tenant_id = (SELECT current_setting('app.tenant', true)::UUID));


-- ============================================================
-- Use case 51: ROW comparison in USING — CLEAN
-- `(tenant_id, env) = (..., ...)` is a row-level equality.
-- pglast represents this as a RowCompareExpr / RowExpr, which
-- extract_column_refs needs to walk through to see `tenant_id`
-- and `env`. Pin the AST path.
-- ============================================================
CREATE TABLE app.row_comparison (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    env TEXT NOT NULL,
    payload TEXT
);
ALTER TABLE app.row_comparison ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.row_comparison FORCE ROW LEVEL SECURITY;
CREATE POLICY row_eq ON app.row_comparison
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        (tenant_id, env) = (
            (SELECT current_setting('app.tenant', true)::UUID),
            (SELECT current_setting('app.env', true))
        )
    );


-- ============================================================
-- Use case 52: SEC003 fires once per offending policy
-- Two PERMISSIVE policies on the same table, both granted to
-- PUBLIC. Pin that SEC003 emits one violation per policy
-- (not per table), so a multi-policy table with two violations
-- shows both lines in the output.
-- ============================================================
CREATE TABLE app.multi_perm (
    id BIGSERIAL PRIMARY KEY,
    title TEXT,
    body TEXT
);
ALTER TABLE app.multi_perm ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.multi_perm FORCE ROW LEVEL SECURITY;
CREATE POLICY perm_a ON app.multi_perm
    FOR SELECT TO PUBLIC USING (length(title) > 0);
CREATE POLICY perm_b ON app.multi_perm
    FOR SELECT TO PUBLIC USING (length(body) > 0);


-- ============================================================
-- Use case 53: SEC004 inside a nested OR — false-negative pin
-- The rule keys on top-level OR disjuncts (per
-- top_level_disjuncts in ast_utils). When `auth_func() IS NULL`
-- is buried inside a nested OR, the helper's "split top OR
-- only" semantics means SEC004 does NOT fire. Pin the
-- documented limitation so a future change to descend deeper
-- is deliberate (and possibly noisy).
-- ============================================================
CREATE TABLE app.nested_or_check (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    flag TEXT
);
ALTER TABLE app.nested_or_check ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.nested_or_check FORCE ROW LEVEL SECURITY;
CREATE POLICY nested_or ON app.nested_or_check
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        flag = 'system'
        OR (
            (SELECT auth.uid()) IS NULL
            OR user_id = (SELECT auth.uid())
        )
    );


-- ============================================================
-- Use case 54: SEC005 with TypeCast wrapping a column ref —
-- CLEAN
-- `email::text = ...` parses as a TypeCast over a ColumnRef.
-- extract_column_refs needs to walk through TypeCast.arg to
-- still see `email`. Pin that the cast doesn't hide the col.
-- ============================================================
CREATE TABLE app.typecast_email (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255)
);
ALTER TABLE app.typecast_email ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.typecast_email FORCE ROW LEVEL SECURITY;
CREATE POLICY by_email_text ON app.typecast_email
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (email::text = (SELECT current_setting('app.user', true)));


-- ============================================================
-- Use case 55: SEC008 with `USING (NOT false)` — CLEAN
-- Logically equivalent to `USING (true)` but the AST is a
-- BoolExpr (NOT) over an A_Const, NOT a literal Boolean.
-- SEC008's detector keys on the literal True A_Const, so this
-- shape stays silent. Pin the asymmetry so the detector
-- doesn't drift toward semantic equivalence.
-- ============================================================
CREATE TABLE app.not_false_table (
    id BIGSERIAL PRIMARY KEY,
    label TEXT
);
ALTER TABLE app.not_false_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.not_false_table FORCE ROW LEVEL SECURITY;
CREATE POLICY not_false ON app.not_false_table
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (NOT false);


-- ============================================================
-- Use case 56: HYG001 with `gone IS TRUE` (BoolTest) — fires
-- A BoolTest wraps a column ref. extract_column_refs needs to
-- walk through the BoolTest to see the orphaned column.
-- ============================================================
CREATE TABLE app.booltest_orphan (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    gone BOOLEAN
);
ALTER TABLE app.booltest_orphan ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.booltest_orphan FORCE ROW LEVEL SECURITY;
CREATE POLICY bt_check ON app.booltest_orphan
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT current_setting('app.user', true))
        AND gone IS TRUE
    );

UPDATE pg_catalog.pg_attribute
    SET attisdropped = true
    WHERE attrelid = 'app.booltest_orphan'::regclass
      AND attname = 'gone';


-- ============================================================
-- Use case 57: PERF001 with auth wrapped in TypeCast — fires
-- `auth.uid()::text` casts the function result; PERF001 still
-- needs to see the unwrapped call inside. Pins
-- find_func_calls walking through TypeCast.arg.
-- ============================================================
CREATE TABLE app.typecast_auth (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT
);
ALTER TABLE app.typecast_auth ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.typecast_auth FORCE ROW LEVEL SECURITY;
CREATE POLICY auth_cast ON app.typecast_auth
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = auth.uid()::text);


-- ============================================================
-- Use case 58: PERF001 with auth wrapped in COALESCE — fires
-- `COALESCE(auth.uid(), '00000000-0000-0000-0000-000000000000')`
-- — find_func_calls must walk function args to spot auth.uid
-- inside another function call.
-- ============================================================
CREATE TABLE app.coalesce_auth (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID
);
ALTER TABLE app.coalesce_auth ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.coalesce_auth FORCE ROW LEVEL SECURITY;
CREATE POLICY coalesced ON app.coalesce_auth
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = COALESCE(auth.uid(), '00000000-0000-0000-0000-000000000000'::UUID)
    );


-- ============================================================
-- Use case 59-63: Configuration scenarios (no new fixture
-- needed — companion tests use the existing tables).
-- ============================================================
-- 59: fail_on=warning gates exit on PERF001 (which fires in
--     several places already).
-- 60: fail_on=info gates exit on SEC007 (info severity).
-- 61: --format=json emits machine-readable JSON instead of
--     text.
-- 62: Multiple disabled rules at once.
-- 63: Bad allowlist type produces a clear error from the CLI.


-- ============================================================
-- Use case 64: Quoted/unusual identifier — CLEAN
-- Postgres allows mixed-case and reserved-word identifiers
-- via double-quoting. The introspector pulls names from
-- pg_class as plain strings; the lint output and allowlist
-- both treat them as plain strings (no extra quoting). Pin
-- that this round-trip works.
-- ============================================================
CREATE TABLE app."MixedCase Table" (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT
);
ALTER TABLE app."MixedCase Table" ENABLE ROW LEVEL SECURITY;
ALTER TABLE app."MixedCase Table" FORCE ROW LEVEL SECURITY;
CREATE POLICY mixed_owner ON app."MixedCase Table"
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (user_id = (SELECT current_setting('app.user', true)));


-- ============================================================
-- Use case 65: SEC001 allowlist by qualified vs unqualified —
-- both forms work
-- The default config allowlists `app.countries` (qualified).
-- pgrls also accepts unqualified names. Test under a config
-- that allowlists `legacy_orders` (uc03) by unqualified name —
-- SEC001 silences for it the same way.
-- ============================================================
-- (No new fixture — uses uc03's app.legacy_orders.)


-- ============================================================
-- Use case 66: HYG001 walks JSON `->>` operator — fires
-- `payload->>'gone'` references the outer column `payload`,
-- not a column named "gone". Pin that HYG001's column-ref
-- walk does NOT confuse JSON keys with column names — the
-- only column ref here is `payload`, which exists, so HYG001
-- stays silent.
-- ============================================================
CREATE TABLE app.json_access (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    payload JSONB
);
ALTER TABLE app.json_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.json_access FORCE ROW LEVEL SECURITY;
CREATE POLICY json_filter ON app.json_access
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        user_id = (SELECT current_setting('app.user', true))
        AND payload->>'visibility' = 'public'
    );


-- ============================================================
-- Use case 67: BETWEEN operator — CLEAN
-- `BETWEEN` in pglast represents as a chained AND under
-- A_Expr-AEXPR_BETWEEN. extract_column_refs needs to walk
-- through the operator to find `created_at` on the outer
-- table.
-- ============================================================
CREATE TABLE app.recent_only (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE app.recent_only ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.recent_only FORCE ROW LEVEL SECURITY;
CREATE POLICY recent_window ON app.recent_only
    AS RESTRICTIVE
    FOR SELECT TO PUBLIC
    USING (
        tenant_id = (SELECT current_setting('app.tenant', true)::UUID)
        AND created_at BETWEEN now() - INTERVAL '30 days' AND now()
    );


-- ============================================================
-- Use case 73: RLS enabled, no policies — SEC009 (new in 0.0.6)
-- A migration enabled RLS planning to add policies later, then
-- forgot. The table now silently rejects every query — looks
-- "RLS protected" but is actually deny-all. SEC009 catches the
-- forgotten step.
-- ============================================================
CREATE TABLE app.deny_all_log (
    id BIGSERIAL,
    event TEXT
);
ALTER TABLE app.deny_all_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.deny_all_log FORCE ROW LEVEL SECURITY;
-- No CREATE POLICY here. SEC009 fires.


-- ============================================================
-- Use case 74: USING (false) deny-all anti-pattern — SEC010
-- (new in 0.0.6)
-- The policy denies every row by writing the denial as a
-- predicate. Misleading: the table looks RLS-protected (it has
-- a policy) but the predicate makes it effectively disabled.
-- The right primitive is `REVOKE ALL ON TABLE x FROM <role>`.
-- SEC005 also fires here (no own-column reference) — a
-- correctly-noisy outcome since the policy is defective on
-- multiple counts.
-- ============================================================
CREATE TABLE app.deny_via_false (
    id BIGSERIAL,
    payload TEXT
);
ALTER TABLE app.deny_via_false ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.deny_via_false FORCE ROW LEVEL SECURITY;
CREATE POLICY block_all ON app.deny_via_false
    AS RESTRICTIVE FOR SELECT TO PUBLIC USING (false);


-- ============================================================
-- Use case 75: SARIF formatter — no new fixture
-- The companion test runs the demo DB through
-- `pgrls lint --format sarif` and validates the shape:
-- top-level $schema, the single run, tool.driver.name='pgrls',
-- rule descriptors, severity-to-level mapping, and
-- logicalLocations.fullyQualifiedName for each result.
-- ============================================================
