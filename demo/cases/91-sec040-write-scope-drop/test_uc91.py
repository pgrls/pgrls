"""Use case 91: write-side scope drop — SEC040."""
from __future__ import annotations

import psycopg
import pytest


def test_uc91_scope_dropping_policy_fires_sec040(lint_output: str) -> None:
    # USING scopes by tenant_id but the explicit WITH CHECK validates only
    # status. A FOR ALL insert is governed by WITH CHECK alone, so a caller
    # can INSERT a row stamped with another tenant's id. SEC040 (warning)
    # fires on the live introspected policy.
    assert (
        "SEC040  app.uc91_documents.uc91_documents_rw\n"
        in lint_output
    )


def test_uc91_scope_reasserting_policy_does_not_fire_sec040(
    lint_output: str,
) -> None:
    # SEC040's defining boundary: when WITH CHECK re-asserts the same tenant
    # scope USING enforces, the write side is closed and SEC040 stays SILENT.
    # Pins the exemption through the production introspection path (the unit
    # tests pin it on hand-built ASTs).
    assert (
        "SEC040  app.uc91_documents_fixed.uc91_documents_fixed_rw\n"
        not in lint_output
    )


def _stamp_row_for_another_tenant(conn: psycopg.Connection, table: str) -> int:
    """As app_authenticated scoped to tenant 1, INSERT a row stamped for
    tenant 2 — WITHOUT `RETURNING`. Returns the affected row count.

    The `RETURNING`-free shape is the whole point: reading the new row back
    re-triggers the SELECT-applicable policy, which re-checks the row and
    blocks the write. Only a non-RETURNING insert (bulk, `Prefer:
    return=minimal`, `ON CONFLICT DO NOTHING`) is governed by WITH CHECK
    alone.

    The GRANTs run inside the caller's transaction and roll back with it, so
    the demo schema's lint-visible grant state is untouched (a permanent
    grant here would change what the grant-gated rules see). `id` is explicit
    to avoid needing a sequence grant.
    """
    with conn.cursor() as cur:
        cur.execute("GRANT USAGE ON SCHEMA app TO app_authenticated")
        cur.execute(f"GRANT INSERT ON {table} TO app_authenticated")
        cur.execute("SET LOCAL ROLE app_authenticated")
        cur.execute("SELECT set_config('app.tenant_id', '1', true)")
        cur.execute(
            f"INSERT INTO {table} (id, tenant_id, status, body) "
            "VALUES (9101, 2, 'draft', 'cross-tenant')"
        )
        return cur.rowcount


def test_uc91_the_cross_tenant_write_is_real(demo_db: str) -> None:
    """SEC040's premise, EXECUTED — not merely asserted.

    The rule claims a caller can INSERT a row stamped with another tenant's
    id once the explicit WITH CHECK drops USING's tenant scope. Prove it
    against live Postgres: tenant 1 stamps a row for tenant 2, and it lands.

    This is the shape of test that would have caught SEC006's original false
    positive, where the rule assumed a write hole Postgres actually closes
    (it reuses USING as the implicit WITH CHECK). A rule that fires is worth
    nothing if the shape it names isn't exploitable — so assert the exploit,
    not just the finding.
    """
    with psycopg.connect(demo_db) as conn:
        with conn.transaction(force_rollback=True):
            assert _stamp_row_for_another_tenant(conn, "app.uc91_documents") == 1


def test_uc91_the_fix_actually_blocks_the_cross_tenant_write(
    demo_db: str,
) -> None:
    """The other half: SEC040's remediation must really close the hole.

    Re-asserting the tenant scope in WITH CHECK makes the identical insert
    fail (SQLSTATE 42501 — "new row violates row-level security policy").
    Without this, "add the scope to WITH CHECK" is advice we never checked.

    `match=` is load-bearing: 42501 is also "permission denied", so a bare
    `raises(InsufficientPrivilege)` would pass if the GRANT above silently
    failed — proving nothing. Pin the RLS rejection specifically.
    """
    with psycopg.connect(demo_db) as conn:
        with conn.transaction(force_rollback=True):
            with pytest.raises(
                psycopg.errors.InsufficientPrivilege,
                match="row-level security",
            ):
                _stamp_row_for_another_tenant(
                    conn, "app.uc91_documents_fixed"
                )
