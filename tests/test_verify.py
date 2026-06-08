"""Tests for `pgrls verify` — the Z3 anonymous-isolation proof."""
from __future__ import annotations

import json

import psycopg
import pytest
from click.testing import CliRunner
from pglast import parse_sql

from pgrls.cli import main
from pgrls.diff._z3_compare import Z3_AVAILABLE
from pgrls.introspect import introspect
from pgrls.model import Policy, Schema, Table
from pgrls.verify import (
    Verification,
    build_verification,
    render_json,
    render_text,
)

requires_z3 = pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")


def _docker_available() -> bool:
    try:
        import docker  # noqa: PLC0415

        docker.from_env().ping()
        return True
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available for live introspection"
)

# Postgres validates a policy's USING expression at CREATE POLICY, so the
# auth.* helpers must exist before the policy references them. Minimal stub
# (mirrors the Supabase prelude the ephemeral engine installs).
_AUTH_STUB = (
    "CREATE SCHEMA IF NOT EXISTS auth;"
    "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS "
    "$$ SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid $$;"
)


def _using_ast(sql: str):
    return parse_sql(f"SELECT 1 WHERE {sql}")[0].stmt.whereClause


def _policy(
    using: str, *, name: str = "p", permissive: bool = True, command: str = "ALL"
) -> Policy:
    return Policy(
        name=name,
        command=command,
        permissive=permissive,
        roles=("authenticated",),
        using_sql=using,
        with_check_sql=None,
        using_ast=_using_ast(using) if using is not None else None,
        with_check_ast=None,
    )


def _table(name: str, *, rls: bool = True, policies: tuple[Policy, ...] = ()) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=True,
        policies=policies,
    )


def _verdict(v: Verification, table: str) -> str:
    return next(t.verdict for t in v.tables if t.qualified_name == table)


# --- verdict logic (Z3) ----------------------------------------------------


@requires_z3
def test_scoped_policy_is_proven_isolated() -> None:
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid()"),)),))
    assert _verdict(build_verification(schema), "public.t") == "isolated"


@requires_z3
def test_inverted_auth_is_proven_leak() -> None:
    # The signature Supabase bug — SEC004 shape — now PROVEN as a leak.
    schema = Schema(
        tables=(
            _table("t", policies=(_policy("auth.uid() IS NULL OR tenant_id = auth.uid()"),)),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "leak"
    assert v.has_leak


@requires_z3
def test_using_true_is_leak_all_rows() -> None:
    schema = Schema(tables=(_table("t", policies=(_policy("true"),)),))
    v = build_verification(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness == {}  # unconditional → "all rows"


@requires_z3
def test_characterizing_counterexample_row() -> None:
    # A row-specific leak yields a concrete characterizing assignment.
    schema = Schema(
        tables=(
            _table("t", policies=(_policy("is_public OR tenant_id = (select auth.uid())"),)),
        )
    )
    v = build_verification(schema)
    [t] = v.tables
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert leak.witness == {"is_public": True}


@requires_z3
def test_undecidable_predicate_is_unverified() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = ANY(string_to_array(current_setting('x'), ','))"),
                ),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "unverified"


@requires_z3
def test_restrictive_floor_downgrades_leak_to_unverified() -> None:
    # A permissive leak + a restrictive read floor: v1 cannot soundly combine,
    # so it makes no claim rather than a possibly-wrong leak.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("true", name="perm"),
                    _policy("tenant_id IS NOT NULL", name="floor", permissive=False),
                ),
            ),
        )
    )
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "unverified"
    assert not v.has_leak  # the floor downgrade must not count as a leak


@requires_z3
def test_isolated_permissive_with_restrictive_floor_stays_proven() -> None:
    # A restrictive floor only narrows access, so an already-isolated permissive
    # policy stays isolated (the floor downgrade is leak-only). A note flags the
    # floor's presence.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = auth.uid()", name="perm"),
                    _policy("tenant_id IS NOT NULL", name="floor", permissive=False),
                ),
            ),
        )
    )
    v = build_verification(schema)
    [t] = v.tables
    assert t.verdict == "isolated"
    assert t.note and "restrictive read floor" in t.note


@requires_z3
def test_satisfiable_but_uncharacterized_leak_is_all_rows() -> None:
    # A tautology that no real-column assignment characterizes (the witness
    # sufficiency check fails) is a sound leak with the "all rows" ({}) artifact.
    schema = Schema(tables=(_table("t", policies=(_policy("flag OR NOT flag"),)),))
    v = build_verification(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness == {}


def test_rls_on_no_permissive_policy_is_isolated() -> None:
    # Default-deny: RLS on, no permissive read policy → trivially isolated.
    schema = Schema(tables=(_table("t", policies=()),))
    v = build_verification(schema)
    assert _verdict(v, "public.t") == "isolated"
    assert v.tables[0].proofs == ()


def test_rls_off_table_is_out_of_scope() -> None:
    schema = Schema(tables=(_table("t", rls=False, policies=(_policy("true"),)),))
    assert build_verification(schema).tables == ()


def test_missing_using_ast_is_unverified() -> None:
    pol = Policy(
        name="p", command="ALL", permissive=True, roles=("authenticated",),
        using_sql="?", with_check_sql=None, using_ast=None, with_check_ast=None,
    )
    schema = Schema(tables=(_table("t", policies=(pol,)),))
    assert _verdict(build_verification(schema), "public.t") == "unverified"


def test_insert_only_policy_is_not_a_read_policy() -> None:
    # A FOR INSERT policy is not a read policy → no permissive read → isolated.
    schema = Schema(
        tables=(_table("t", policies=(_policy("true", command="INSERT"),)),)
    )
    assert _verdict(build_verification(schema), "public.t") == "isolated"


# --- renderers -------------------------------------------------------------


def _sample() -> Verification:
    return build_verification(
        Schema(
            tables=(
                _table("safe", policies=(_policy("tenant_id = auth.uid()"),)),
                _table("leaky", policies=(_policy("true"),)),
            )
        )
    )


@requires_z3
def test_render_text_has_verdicts_and_summary() -> None:
    out = render_text(_sample())
    assert "PROVEN" in out and "LEAK" in out
    assert "public.safe" in out and "public.leaky" in out
    assert "every row is anonymously readable" in out
    assert "proven isolated" in out and "leaking" in out


def test_render_text_empty() -> None:
    assert "No RLS-enabled tables" in render_text(build_verification(Schema(tables=())))


@requires_z3
def test_render_json_shape() -> None:
    payload = json.loads(render_json(_sample()))
    assert set(payload["summary"]) == {"tables", "isolated", "leak", "unverified"}
    leaky = next(t for t in payload["tables"] if t["table"] == "public.leaky")
    assert leaky["verdict"] == "leak"
    p = leaky["policies"][0]
    assert p["witness_scope"] == "all_rows"
    assert p["witness"] == {}


@requires_z3
def test_render_json_unicode_preserved() -> None:
    schema = Schema(tables=(_table("café", policies=(_policy("true"),)),))
    out = render_json(build_verification(schema))
    assert "café" in out and "\\u" not in out


# --- CLI -------------------------------------------------------------------


def test_verify_cli_help() -> None:
    result = CliRunner().invoke(main, ["verify", "--help"])
    assert result.exit_code == 0
    assert "Prove tenant isolation" in result.output


def test_verify_cli_errors_without_database_url() -> None:
    result = CliRunner().invoke(main, ["verify"], env={"DATABASE_URL": ""})
    assert result.exit_code == 2
    assert "No database connection" in result.output


def test_verify_cli_is_registered_format_list() -> None:
    from pgrls.verify import VERIFY_FORMATS

    assert VERIFY_FORMATS == ("text", "json")


# --- live introspection (Docker) ------------------------------------------


@requires_docker
@requires_z3
def test_verify_cli_live_leak_exits_one(pg_conn: psycopg.Connection) -> None:
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            # The inverted-auth leak: anon (auth.uid() NULL) sees every row.
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    schema = introspect(pg_conn, schemas=["public"])
    v = build_verification(schema)
    assert _verdict(v, "public.docs") == "leak"


@requires_docker
@requires_z3
def test_verify_cli_live_exit_code_and_output(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # End-to-end CLI: a leaking policy makes `pgrls verify` exit 1 (the CI
    # tenant-isolation gate) and print the LEAK verdict.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    result = CliRunner().invoke(
        main, ["verify", "--database-url", pg_url, "--schemas", "public"]
    )
    assert result.exit_code == 1, result.output
    assert "LEAK" in result.output and "public.docs" in result.output


@requires_docker
@requires_z3
def test_verify_cli_live_scoped_is_isolated(pg_conn: psycopg.Connection) -> None:
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.acct (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.acct ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.acct FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.acct FOR SELECT TO public "
            "  USING (tenant_id = (select auth.uid()));"
        )
    schema = introspect(pg_conn, schemas=["public"])
    assert _verdict(build_verification(schema), "public.acct") == "isolated"
