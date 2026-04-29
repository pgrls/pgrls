"""Shared fixtures for pgrls.testing's own unit tests.

`testing_pg_conn` is a function-scoped psycopg connection against
the same testcontainer the top-level conftest provides via
`pg_conn`. Before yielding, it ensures an RLS-protected fixture
schema (`rls_widgets` table, `widget_owner` policy) and a
non-superuser actor role (`pgrls_test_actor`) exist. The schema
gets reset between tests by the parent `pg_conn` fixture's
DROP/CREATE SCHEMA cycle, so this conftest re-creates it on each
test entry — cheap (single transaction) and bulletproof.
"""
from __future__ import annotations

from collections.abc import Generator

import psycopg
import pytest
from psycopg import sql


_ACTOR_ROLE = "pgrls_test_actor"


_SCHEMA_DDL = """
CREATE TABLE rls_widgets (
    id BIGSERIAL PRIMARY KEY,
    owner TEXT NOT NULL,
    label TEXT
);
ALTER TABLE rls_widgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rls_widgets FORCE ROW LEVEL SECURITY;

CREATE POLICY widget_owner ON rls_widgets
    USING (
        owner = current_setting('request.jwt.claims', true)::jsonb->>'sub'
    )
    WITH CHECK (
        owner = current_setting('request.jwt.claims', true)::jsonb->>'sub'
    );

GRANT USAGE ON SCHEMA public TO pgrls_test_actor;
GRANT SELECT, INSERT, UPDATE, DELETE ON rls_widgets TO pgrls_test_actor;
GRANT USAGE ON SEQUENCE rls_widgets_id_seq TO pgrls_test_actor;

-- Audit-log shape: actor can INSERT freely; SELECT and UPDATE
-- are gated by an admin-only predicate. An UPDATE ... RETURNING
-- by a non-admin actor finds no rows that pass USING — Postgres
-- silently returns zero rows (no violation error). This is the
-- canonical "silently dropped" shape for RLS.
--
-- Note: INSERT ... RETURNING canNOT silently drop in Postgres —
-- when the SELECT policy's USING fails on the new row, the
-- engine raises "new row violates row-level security policy"
-- rather than returning zero rows. UPDATE/DELETE ... RETURNING
-- do silently drop because USING acts as a row filter, not a
-- post-write check.
CREATE TABLE rls_audit (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    event TEXT NOT NULL
);
ALTER TABLE rls_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE rls_audit FORCE ROW LEVEL SECURITY;

-- Permissive INSERT policy: anybody authenticated can write.
CREATE POLICY audit_write ON rls_audit
    FOR INSERT TO pgrls_test_actor
    WITH CHECK (true);
-- Permissive SELECT policy: only admins can read (claim role='admin').
CREATE POLICY audit_admin_read ON rls_audit
    FOR SELECT TO pgrls_test_actor
    USING (
        current_setting('request.jwt.claims', true)::jsonb->>'role' = 'admin'
    );
-- Permissive UPDATE policy: only admins can update — USING acts
-- as a silent row filter, so non-admins get 0 rows back from
-- UPDATE ... RETURNING with no error.
CREATE POLICY audit_admin_update ON rls_audit
    FOR UPDATE TO pgrls_test_actor
    USING (
        current_setting('request.jwt.claims', true)::jsonb->>'role' = 'admin'
    )
    WITH CHECK (true);

GRANT INSERT ON rls_audit TO pgrls_test_actor;
GRANT SELECT ON rls_audit TO pgrls_test_actor;
GRANT UPDATE ON rls_audit TO pgrls_test_actor;
GRANT USAGE ON SEQUENCE rls_audit_id_seq TO pgrls_test_actor;
"""


@pytest.fixture
def testing_pg_conn(
    pg_conn: psycopg.Connection,
) -> Generator[psycopg.Connection, None, None]:
    # Ensure the actor role exists. Roles are cluster-global —
    # `pg_conn`'s schema reset doesn't touch them — so DROP+CREATE
    # gives idempotent state per test.
    actor = sql.Identifier(_ACTOR_ROLE)
    with pg_conn.cursor() as cur:
        cur.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(actor))
        cur.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(actor))
        cur.execute(_SCHEMA_DDL)
    yield pg_conn
    # Cleanup: drop the role we created. Drop schema first to
    # clear any policy dependencies on the role (`TO <role>`
    # clauses register the role as a dependency target); then
    # REVOKE remaining grants and DROP ROLE.
    with pg_conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
        cur.execute("CREATE SCHEMA public")
        cur.execute("GRANT ALL ON SCHEMA public TO postgres")
        cur.execute("GRANT ALL ON SCHEMA public TO public")
        cur.execute(
            sql.SQL(
                "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}"
            ).format(actor)
        )
        cur.execute(
            sql.SQL(
                "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {}"
            ).format(actor)
        )
        cur.execute(
            sql.SQL("REVOKE ALL ON SCHEMA public FROM {}").format(actor)
        )
        cur.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(actor))
