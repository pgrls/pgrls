"""Tests for `Schema.to_sql()` — the v0.5+ DDL emitter that
re-creates a captured schema in an empty Postgres for the
migration-as-input flow (`pgrls diff --apply`).

Two layers of coverage:

* Pure-string unit tests pin the exact emitted SQL shape so a
  future refactor that changes the output (introduces formatting
  drift, reorders statements, drops a clause) fails loudly.
* Integration tests round-trip the emitted SQL against a real
  Postgres testcontainer: emit → execute → re-introspect → diff
  against the original Schema. The `diff_schemas(...) == []`
  invariant is the soundness pin.
"""
from __future__ import annotations

import pytest

from pgrls.model import (
    Column,
    ColumnGrant,
    Grant,
    Policy,
    SNAPSHOT_VERSION,
    Schema,
    Table,
)


def _t(
    name: str = "t",
    *,
    schema: str = "public",
    rls: bool = True,
    force: bool = True,
    policies: tuple[Policy, ...] = (),
    column_details: tuple[Column, ...] = (
        Column(name="id", data_type="integer", is_nullable=False),
    ),
    grants: tuple[Grant, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
        columns=tuple(c.name for c in column_details),
        column_details=column_details,
        grants=grants,
    )


def _p(
    name: str = "p",
    *,
    command: str = "ALL",
    permissive: bool = True,
    roles: tuple[str, ...] = ("PUBLIC",),
    using_sql: str | None = None,
    with_check_sql: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=roles,
        using_sql=using_sql,
        with_check_sql=with_check_sql,
    )


# ---------------------------------------------------------------------------
# Pre-flight: missing column_details aborts with a clear error
# ---------------------------------------------------------------------------


def test_to_sql_raises_when_column_details_missing():
    # Schema with a Table that has `columns` but empty
    # `column_details` — typical v3/v4 baseline. Emitter cannot
    # fabricate types; surface a clear single error listing the
    # affected tables.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="users",
                rls_enabled=True,
                force_rls=True,
                policies=(),
                columns=("id", "email"),
                column_details=(),  # missing — pre-v0.5 baseline
            ),
        )
    )
    with pytest.raises(ValueError, match="column_details") as excinfo:
        schema.to_sql()
    assert "public.users" in str(excinfo.value)


def test_to_sql_lists_all_missing_tables_in_one_error():
    # Multiple tables missing column_details → single error names
    # all of them, so the user fixes once instead of replay-hunting.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="a",
                rls_enabled=False,
                force_rls=False,
                policies=(),
                columns=("id",),
                column_details=(),
            ),
            Table(
                schema="public",
                name="b",
                rls_enabled=False,
                force_rls=False,
                policies=(),
                columns=("id",),
                column_details=(),
            ),
        )
    )
    with pytest.raises(ValueError) as excinfo:
        schema.to_sql()
    msg = str(excinfo.value)
    assert "public.a" in msg
    assert "public.b" in msg


# ---------------------------------------------------------------------------
# Output shape — string-level pins
# ---------------------------------------------------------------------------


def test_to_sql_emits_create_schema_for_each_distinct_schema():
    schema = Schema(
        tables=(
            _t("a", schema="public"),
            _t("b", schema="app"),
            _t("c", schema="public"),
        )
    )
    sql = schema.to_sql()
    # Both schemas appear, idempotent form. quote_ident only quotes
    # identifiers that need it; lowercase-only names render bare.
    assert "CREATE SCHEMA IF NOT EXISTS public;" in sql
    assert "CREATE SCHEMA IF NOT EXISTS app;" in sql
    # Sorted: app before public.
    assert sql.index("app") < sql.index("public")


def test_to_sql_emits_create_table_with_columns_and_types():
    schema = Schema(
        tables=(
            _t(
                "users",
                column_details=(
                    Column(name="id", data_type="integer", is_nullable=False),
                    Column(name="email", data_type="text", is_nullable=True),
                ),
            ),
        )
    )
    sql = schema.to_sql()
    assert (
        "CREATE TABLE public.users (id integer NOT NULL, email text);"
        in sql
    )


def test_to_sql_emits_rls_enable_when_rls_enabled():
    schema = Schema(tables=(_t(rls=True, force=False),))
    sql = schema.to_sql()
    assert "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;" in sql
    assert "FORCE" not in sql


def test_to_sql_emits_force_rls_when_force_set():
    schema = Schema(tables=(_t(rls=True, force=True),))
    sql = schema.to_sql()
    assert "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;" in sql
    assert "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;" in sql


def test_to_sql_omits_rls_alters_when_rls_disabled():
    schema = Schema(tables=(_t(rls=False, force=False),))
    sql = schema.to_sql()
    assert "ROW LEVEL SECURITY" not in sql


def test_to_sql_emits_create_policy_with_all_clauses():
    pol = _p(
        name="tenant_lock",
        command="SELECT",
        permissive=False,
        roles=("authenticated",),
        using_sql="tenant_id = current_setting('app.tenant')::uuid",
        with_check_sql="tenant_id = current_setting('app.tenant')::uuid",
    )
    schema = Schema(tables=(_t(policies=(pol,)),))
    sql = schema.to_sql()
    assert (
        "CREATE POLICY tenant_lock ON public.t "
        "AS RESTRICTIVE FOR SELECT TO authenticated "
        "USING (tenant_id = current_setting('app.tenant')::uuid) "
        "WITH CHECK (tenant_id = current_setting('app.tenant')::uuid);"
        in sql
    )


def test_to_sql_rejects_trailing_comment_in_using_predicate():
    # Regression (round-10 #3): a snapshot predicate ending in `--`
    # passes the isolated `SELECT 1 WHERE (<sql>)` probe (the comment
    # eats the probe's own closing paren) but, once emitted as
    # `USING (<sql>) WITH CHECK (…)` on one line, comments out the
    # closing paren and the entire WITH CHECK clause — silently dropping
    # the write-side check / breaking diff --apply. to_sql() must refuse.
    pol = _p(
        command="ALL",
        using_sql="true)--",
        with_check_sql="tenant_id = current_setting('app.t')::uuid",
    )
    schema = Schema(tables=(_t(policies=(pol,)),))
    with pytest.raises(ValueError, match="single SQL expression"):
        schema.to_sql()


def test_to_sql_allows_double_dash_inside_string_literal():
    # Guard against over-rejection: a `--` INSIDE a string literal is
    # part of the value, not a comment, so the predicate is safe to emit.
    pol = _p(
        command="SELECT",
        using_sql="note <> 'a--b'",
    )
    schema = Schema(tables=(_t(policies=(pol,)),))
    sql = schema.to_sql()
    assert "USING (note <> 'a--b')" in sql


def test_to_sql_omits_as_permissive_default():
    # PERMISSIVE is the Postgres default; omit the explicit
    # `AS PERMISSIVE` keyword for cleanliness.
    pol = _p(
        permissive=True,
        roles=("PUBLIC",),
        using_sql="true",
    )
    schema = Schema(tables=(_t(policies=(pol,)),))
    sql = schema.to_sql()
    assert "AS PERMISSIVE" not in sql
    assert "AS RESTRICTIVE" not in sql


def test_to_sql_omits_for_all_default():
    # FOR ALL is the Postgres default; omit it for cleaner output.
    pol = _p(command="ALL", using_sql="true")
    schema = Schema(tables=(_t(policies=(pol,)),))
    sql = schema.to_sql()
    assert "FOR ALL" not in sql
    assert "FOR " not in sql or "WITH CHECK" in sql  # smoke check


def test_to_sql_emits_grant_per_role_pair():
    schema = Schema(
        tables=(
            _t(
                grants=(
                    Grant(role="PUBLIC", privileges=("SELECT",)),
                    Grant(role="app_user", privileges=("SELECT", "INSERT")),
                ),
            ),
        )
    )
    sql = schema.to_sql()
    assert "GRANT SELECT ON public.t TO PUBLIC;" in sql
    assert "GRANT SELECT, INSERT ON public.t TO app_user;" in sql


def test_to_sql_emits_column_grant_per_role_pair():
    # R16 #5 (coverage): the column-grant emit path (replayed verbatim by
    # `diff --apply` to build the baseline) had no to_sql assertion. Each
    # privilege carries its own parenthesized column; PUBLIC renders bare;
    # a named role and multiple privileges round-trip.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(),
                columns=("id", "ssn"),
                column_details=(
                    Column(name="id", data_type="integer", is_nullable=False),
                    Column(name="ssn", data_type="text", is_nullable=True),
                ),
                column_grants=(
                    ColumnGrant(
                        role="PUBLIC", column="ssn", privileges=("SELECT",)
                    ),
                    ColumnGrant(
                        role="app_user",
                        column="ssn",
                        privileges=("SELECT", "UPDATE"),
                    ),
                ),
            ),
        )
    )
    sql = schema.to_sql()
    assert "GRANT SELECT (ssn) ON public.t TO PUBLIC;" in sql
    assert (
        "GRANT SELECT (ssn), UPDATE (ssn) ON public.t TO app_user;" in sql
    )


def test_to_sql_quotes_reserved_column_and_role_in_column_grant():
    # The column and role of a column grant route through quote_ident, so
    # a reserved-keyword column ("select") and a mixed-case role ("Reader")
    # must be double-quoted — otherwise the emitted DDL is unparseable and
    # aborts the all-or-nothing `diff --apply` baseline transaction.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(),
                columns=("id", "select"),
                column_details=(
                    Column(name="id", data_type="integer", is_nullable=False),
                    Column(name="select", data_type="text", is_nullable=True),
                ),
                column_grants=(
                    ColumnGrant(
                        role="Reader", column="select", privileges=("SELECT",)
                    ),
                ),
            ),
        )
    )
    sql = schema.to_sql()
    assert 'GRANT SELECT ("select") ON public.t TO "Reader";' in sql


def test_to_sql_renders_public_role_unquoted():
    # PUBLIC is the Postgres pseudo-role; emit it bare (not quoted)
    # so Postgres parses it correctly. Named roles are quoted.
    pol = _p(roles=("PUBLIC",), using_sql="true")
    schema = Schema(tables=(_t(policies=(pol,)),))
    sql = schema.to_sql()
    assert "TO PUBLIC " in sql or sql.endswith("TO PUBLIC USING (true);\n")


def test_to_sql_omits_using_when_unset():
    pol = _p(using_sql=None, with_check_sql="id IS NOT NULL", command="INSERT")
    schema = Schema(tables=(_t(policies=(pol,)),))
    sql = schema.to_sql()
    assert "USING" not in sql.split("CREATE POLICY")[1]
    assert "WITH CHECK (id IS NOT NULL)" in sql


def test_to_sql_output_terminates_with_newline():
    schema = Schema(tables=(_t(),))
    assert schema.to_sql().endswith("\n")


def test_to_sql_empty_schema_returns_empty_newline_terminated():
    sql = Schema(tables=()).to_sql()
    # Empty Schema → empty string + trailing newline.
    assert sql == "\n"


def test_to_sql_is_deterministic_byte_identical_across_calls():
    # Calling to_sql twice on the same Schema yields the same bytes.
    # Pin this so a future change that uses a set-iteration order
    # doesn't introduce non-determinism that breaks reproducible
    # builds and golden-file comparisons.
    pol1 = _p(name="p1", roles=("alpha",), using_sql="true")
    pol2 = _p(name="p2", roles=("beta",), using_sql="true")
    schema = Schema(
        tables=(_t("u", policies=(pol1, pol2)),)
    )
    assert schema.to_sql() == schema.to_sql()


# ---------------------------------------------------------------------------
# Integration: round-trip through real Postgres
# ---------------------------------------------------------------------------


def test_to_sql_round_trips_through_real_postgres(pg_url, apply_sql):
    # End-to-end soundness: capture a schema via introspect, emit
    # SQL via to_sql(), apply it to a fresh DB, re-introspect.
    # `diff_schemas(original, restored) == []` confirms the emitter
    # preserves every diff-relevant field.
    import psycopg

    from pgrls.diff import diff_schemas
    from pgrls.introspect import introspect

    # Set up an interesting baseline.
    apply_sql(
        """
        DROP ROLE IF EXISTS pgrls_to_sql_role;
        CREATE ROLE pgrls_to_sql_role NOLOGIN;
        CREATE TABLE public.invoices (
            id BIGSERIAL,
            tenant_id UUID NOT NULL,
            amount NUMERIC(12, 2),
            paid_at TIMESTAMPTZ
        );
        ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_read ON public.invoices
            FOR ALL TO pgrls_to_sql_role
            USING (tenant_id = (SELECT current_setting('app.tenant', true)::uuid))
            WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::uuid));
        CREATE POLICY tenant_lock ON public.invoices
            AS RESTRICTIVE FOR ALL TO PUBLIC
            USING (tenant_id = (SELECT current_setting('app.tenant', true)::uuid))
            WITH CHECK (tenant_id = (SELECT current_setting('app.tenant', true)::uuid));
        GRANT SELECT, INSERT ON public.invoices TO pgrls_to_sql_role;
        """
    )

    # Capture the original schema.
    with psycopg.connect(pg_url) as conn:
        original = introspect(conn, schemas=["public"])

    # Spin up an ephemeral Postgres for the round-trip. The default
    # testcontainers user is `test`; the original schema's grants
    # / policies reference `postgres` (the pg_url fixture's user)
    # and `pgrls_to_sql_role`. Pre-create both in the new container
    # so the to_sql output applies cleanly. `Schema.to_sql()`
    # deliberately doesn't emit role-creation — that's the
    # caller's responsibility.
    #
    # CRITICAL: use the same image as `pg_url`. PG17 introduced the
    # `MAINTAIN` grant privilege; capturing from PG17 then restoring
    # to PG16 fails with `unrecognized privilege type "maintain"`.
    # `PGRLS_TEST_PG_IMAGE` is the same env var the conftest's
    # `pg_url` fixture reads, so the source and target images match.
    import os

    from testcontainers.postgres import PostgresContainer

    image = os.environ.get("PGRLS_TEST_PG_IMAGE", "postgres:16-alpine")

    with PostgresContainer(
        image,
        username="postgres",
        password="postgres",
        dbname="postgres",
    ) as pg:
        url = pg.get_connection_url(driver=None)
        with psycopg.connect(url, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DO $$ BEGIN "
                    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgrls_to_sql_role') THEN "
                    "CREATE ROLE pgrls_to_sql_role NOLOGIN; END IF; END $$;"
                )
                cur.execute(original.to_sql())
        # Re-introspect.
        with psycopg.connect(url) as conn:
            restored = introspect(conn, schemas=["public"])

    # The diff against the original should be empty — to_sql
    # preserved every diff-relevant field.
    changes = diff_schemas(original, restored)
    assert changes == [], (
        "to_sql round-trip introduced a diff: " + repr(changes)
    )


# ---------------------------------------------------------------------------
# Snapshot v5 plumbing
# ---------------------------------------------------------------------------


def test_snapshot_version_is_eighteen():
    # Bumped 17 → 18 to add top-level default_privileges (from pg_default_acl)
    # for SEC044's default-privilege-exposes-future-tables check. Pin so a
    # future bump is deliberate.
    assert SNAPSHOT_VERSION == 18


def test_to_snapshot_emits_column_details_array():
    schema = Schema(
        tables=(
            _t(
                column_details=(
                    Column(name="id", data_type="integer", is_nullable=False),
                ),
            ),
        )
    )
    snap = schema.to_snapshot()
    assert snap["tables"][0]["column_details"] == [
        {
            "name": "id",
            "data_type": "integer",
            "is_nullable": False,
        }
    ]


def test_from_snapshot_round_trips_v5_with_column_details():
    schema = Schema(
        tables=(
            _t(
                column_details=(
                    Column(name="id", data_type="integer", is_nullable=False),
                    Column(name="email", data_type="text"),  # default nullable
                ),
            ),
        )
    )
    restored = Schema.from_snapshot(schema.to_snapshot())
    assert restored.tables[0].column_details == schema.tables[0].column_details


def test_from_snapshot_accepts_v3_v4_with_empty_column_details():
    # Backward compat: a v3 / v4 snapshot has no `column_details` key.
    # `from_snapshot` should accept it and leave column_details=().
    v4_payload = {
        "version": 4,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": False,
                "force_rls": False,
                "columns": ["id", "email"],
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
    }
    schema = Schema.from_snapshot(v4_payload)
    assert schema.tables[0].columns == ("id", "email")
    assert schema.tables[0].column_details == ()


def test_from_snapshot_v3_v4_roundtrip_then_to_sql_raises():
    # A v3/v4 snapshot loaded via from_snapshot has empty
    # column_details. Trying to use Schema.to_sql() on it raises
    # the clear "re-capture against v0.5+" error.
    v4_payload = {
        "version": 4,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": False,
                "force_rls": False,
                "columns": ["id"],
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
    }
    schema = Schema.from_snapshot(v4_payload)
    with pytest.raises(ValueError, match="column_details"):
        schema.to_sql()


def test_to_sql_rejects_multi_statement_policy_predicate() -> None:
    # A policy predicate that smuggles a second statement
    # (`true); DROP TABLE secrets; --`) must not be emitted into the
    # DDL that `pgrls diff --apply` executes — policy_to_sql requires
    # the predicate to be a single SQL expression. (#5: to_sql is a
    # trust-boundary sink for snapshot-sourced values.)
    schema = Schema(
        tables=(_t(policies=(_p(using_sql="true); DROP TABLE secrets; --"),)),)
    )
    with pytest.raises(ValueError, match="single SQL expression"):
        schema.to_sql()
