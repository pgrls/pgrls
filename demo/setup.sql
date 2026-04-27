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
CREATE SCHEMA app;
CREATE SCHEMA private;


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
