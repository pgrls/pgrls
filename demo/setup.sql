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
