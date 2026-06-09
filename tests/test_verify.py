"""Tests for `pgrls verify` — the Z3 anonymous-isolation proof."""
from __future__ import annotations

import json
from pathlib import Path

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
def test_conditional_leak_has_none_witness() -> None:
    # A conditional leak the prover can't pin to a single real-column row
    # (the discriminator is a synthetic null-flag) → witness None, NOT {} —
    # so callers don't claim "every row".
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid() OR public_level IS NOT NULL"),),
            ),
        )
    )
    v = build_verification(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None  # conditional, uncharacterized (not {} = all-rows)
    assert "conditional" in render_text(v)


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
def test_satisfiable_nullable_tautology_is_conditional() -> None:
    # `flag OR NOT flag` is NOT a 3VL tautology — a NULL `flag` row evaluates to
    # NULL (hidden) — so it's a conditional leak (witness None), not "all rows".
    schema = Schema(tables=(_table("t", policies=(_policy("flag OR NOT flag"),)),))
    v = build_verification(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None


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
def test_verify_cli_emit_repro_force_guard(
    pg_url: str, pg_conn: psycopg.Connection, tmp_path: Path
) -> None:
    # `--emit-repro` must not silently clobber a hand-edited reproduction: a
    # second run without --force errors (exit 2) and preserves the edit; --force
    # rewrites. Mirrors the generate/fix/init --output guard convention.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    out = tmp_path / "repro"
    runner = CliRunner()
    args = [
        "verify", "--database-url", pg_url, "--schemas", "public",
        "--emit-repro", str(out),
    ]
    r1 = runner.invoke(main, args)
    assert r1.exit_code == 1, r1.output  # leak → exit 1 (files written first)
    sqlf = out / "public_docs_p.sql"
    assert sqlf.exists()
    sqlf.write_text("-- HAND-EDITED\n" + sqlf.read_text(), encoding="utf-8")

    # second run, no --force → refuses (ToolError exit 2), edit preserved
    r2 = runner.invoke(main, args)
    assert r2.exit_code == 2, r2.output
    assert "already exists" in r2.output and "--force" in r2.output
    assert "HAND-EDITED" in sqlf.read_text()

    # --force → overwrites, back to the leak exit
    r3 = runner.invoke(main, [*args, "--force"])
    assert r3.exit_code == 1, r3.output
    assert "HAND-EDITED" not in sqlf.read_text()


@requires_docker
@requires_z3
def test_verify_cli_emit_repro_unwritable_dir_clean_error(
    pg_url: str, pg_conn: psycopg.Connection, tmp_path: Path
) -> None:
    # An unwritable --emit-repro dir must surface a clean ToolError (exit 2),
    # not a raw OSError traceback — matching init/fix/generate's write guard.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (auth.uid() IS NULL OR tenant_id = auth.uid());"
        )
    # A regular file in the path → mkdir(parents=True) raises NotADirectoryError
    # (an OSError), independent of uid/permissions.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    result = CliRunner().invoke(
        main,
        ["verify", "--database-url", pg_url, "--schemas", "public",
         "--emit-repro", str(blocker / "sub")],
    )
    assert result.exit_code == 2, result.output
    assert "Cannot write reproduction files" in result.output


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


# --- cross-tenant mode (Z3) ------------------------------------------------


def _xt(schema: Schema) -> Verification:
    return build_verification(schema, mode="cross-tenant")


def test_build_verification_default_mode_is_anon() -> None:
    v = build_verification(Schema(tables=(_table("t", policies=()),)))
    assert v.mode == "anon"


@requires_z3
def test_cross_tenant_scoped_policy_is_proven() -> None:
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid()"),)),))
    assert _verdict(_xt(schema), "public.t") == "isolated"


@requires_z3
def test_cross_tenant_cast_scoping_is_proven() -> None:
    # The exact predicate `pgrls generate` emits — the cast is a no-op (uuid →
    # String) so the auth value stays a session symbol and the proof holds.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy("tenant_id = current_setting('app.tenant_id', true)::uuid"),
                ),
            ),
        )
    )
    assert _verdict(_xt(schema), "public.t") == "isolated"


@requires_z3
def test_cross_tenant_or_public_is_leak_with_row_witness() -> None:
    # An `OR is_public` bypass exposes another tenant's public rows.
    schema = Schema(
        tables=(_table("t", policies=(_policy("tenant_id = auth.uid() OR is_public"),)),)
    )
    v = _xt(schema)
    [t] = v.tables
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert t.verdict == "leak"
    assert leak.witness == {"is_public": True}


@requires_z3
def test_cross_tenant_admin_bypass_is_conditional_leak() -> None:
    # An admin disjunct lets an admin session read every tenant, but the leak
    # is conditional on the SESSION's role (not any row column) — so the row
    # witness is not self-sufficient → conditional leak (witness None), not an
    # over-claiming row.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid() OR auth.role() = 'admin'"),),
            ),
        )
    )
    v = _xt(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None


@requires_z3
def test_cross_tenant_witness_not_over_claimed_on_opaque_conjunct() -> None:
    # A bypass disjunct gated by an opaque runtime value
    # (`is_public AND current_setting(...) = 'x'`) is a real leak, but pinning
    # `is_public=True` alone does NOT force it — the row witness must NOT
    # over-claim. The sufficiency gate downgrades it to a conditional leak.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = auth.uid() "
                        "OR (is_public AND current_setting('app.x') = 'y')"
                    ),
                ),
            ),
        )
    )
    v = _xt(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness is None  # NOT {"is_public": True} — that would over-claim


@requires_z3
def test_cross_tenant_unconditional_bypass_is_any_other_tenant() -> None:
    # A disjunct that is unconditionally true alongside the scoping equality
    # exposes every other-tenant row with no row condition → empty witness,
    # rendered as the `any_other_tenant` scope.
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid() OR true"),)),))
    v = _xt(schema)
    [t] = v.tables
    [p] = t.proofs
    assert t.verdict == "leak"
    assert p.witness == {}


@requires_z3
def test_cross_tenant_hardcoded_tenant_pins_witness() -> None:
    # A hardcoded other-tenant disjunct pins the leak to that one tenant value
    # (the discriminator IS characterizing here, unlike the don't-care cases).
    tid = "00000000-0000-0000-0000-000000000000"
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy(f"tenant_id = auth.uid() OR tenant_id = '{tid}'"),),
            ),
        )
    )
    v = _xt(schema)
    [t] = v.tables
    leak = next(p for p in t.proofs if p.verdict == "leak")
    assert t.verdict == "leak"
    assert leak.witness == {"tenant_id": tid}


@requires_z3
def test_cross_tenant_inverted_auth_is_proven_complementary() -> None:
    # THE headline: the inverted-auth policy is an anon LEAK but cross-tenant
    # ISOLATED — an authenticated tenant only sees its own rows (the IS NULL
    # branch is false when authenticated). The two modes are complementary.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("auth.uid() IS NULL OR tenant_id = auth.uid()"),),
            ),
        )
    )
    assert _verdict(build_verification(schema), "public.t") == "leak"  # anon
    assert _verdict(_xt(schema), "public.t") == "isolated"  # cross-tenant


@requires_z3
def test_cross_tenant_using_true_is_unverified_not_leak() -> None:
    # USING(true) has no scoping equality → cross-tenant makes no claim (it is
    # already caught as an anon leak). Soundness: never a false isolated.
    schema = Schema(tables=(_table("t", policies=(_policy("true"),)),))
    v = _xt(schema)
    assert _verdict(v, "public.t") == "unverified"
    assert not v.has_leak


@requires_z3
def test_cross_tenant_multi_axis_is_unverified() -> None:
    # Two distinct scoping equalities (different columns) → no single tenant
    # axis → unverified. Conservative: soundness over recall.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(_policy("tenant_id = auth.uid() OR org_id = auth.uid()"),),
            ),
        )
    )
    assert _verdict(_xt(schema), "public.t") == "unverified"


@requires_z3
def test_cross_tenant_undecidable_predicate_is_unverified() -> None:
    # An untranslatable predicate → no claim (the verifier degrades to the
    # linter), same as anon mode.
    schema = Schema(
        tables=(
            _table(
                "t",
                policies=(
                    _policy(
                        "tenant_id = ANY(string_to_array(current_setting('x'), ','))"
                    ),
                ),
            ),
        )
    )
    assert _verdict(_xt(schema), "public.t") == "unverified"


@requires_z3
def test_cross_tenant_scoped_is_anon_unverified_or_proven() -> None:
    # The plain scoped policy `tenant_id = auth.uid()` is cross-tenant PROVEN;
    # under anon it is also isolated (auth.uid() NULL → tenant_id = NULL is U,
    # no row visible). Pin both so the modes don't accidentally converge wrong.
    schema = Schema(tables=(_table("t", policies=(_policy("tenant_id = auth.uid()"),)),))
    assert _verdict(build_verification(schema), "public.t") == "isolated"
    assert _verdict(_xt(schema), "public.t") == "isolated"


# --- cross-tenant renderers ------------------------------------------------


@requires_z3
def test_cross_tenant_render_text_phrasing() -> None:
    schema = Schema(
        tables=(
            _table("safe", policies=(_policy("tenant_id = auth.uid()"),)),
            _table("leaky", policies=(_policy("tenant_id = auth.uid() OR is_public"),)),
        )
    )
    out = render_text(_xt(schema))
    assert "no cross-tenant read" in out
    assert "a row of another tenant with is_public=True is readable" in out
    # the anon-only phrasings must NOT appear in cross-tenant output
    assert "anonymously readable" not in out


@requires_z3
def test_cross_tenant_render_json_mode_and_scope() -> None:
    schema = Schema(
        tables=(
            _table("u", policies=(_policy("tenant_id = auth.uid() OR true"),)),
        )
    )
    payload = json.loads(render_json(_xt(schema)))
    assert payload["mode"] == "cross-tenant"
    p = payload["tables"][0]["policies"][0]
    assert p["witness_scope"] == "any_other_tenant"
    assert p["witness"] == {}


def test_anon_render_json_records_mode() -> None:
    # Regression: the default mode is recorded in JSON (no Z3 needed — a
    # policy-free table is trivially isolated).
    payload = json.loads(
        render_json(build_verification(Schema(tables=(_table("t", policies=()),))))
    )
    assert payload["mode"] == "anon"


# --- cross-tenant CLI ------------------------------------------------------


def test_verify_cli_mode_option_in_help() -> None:
    result = CliRunner().invoke(main, ["verify", "--help"])
    assert result.exit_code == 0
    assert "--mode" in result.output and "cross-tenant" in result.output


@requires_docker
@requires_z3
def test_verify_cli_emit_repro_cross_tenant(
    pg_url: str, pg_conn: psycopg.Connection, tmp_path: Path
) -> None:
    # `--mode cross-tenant --emit-repro` writes a cross-tenant reproduction for
    # each leak (exit 1) — it is no longer rejected.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigint PRIMARY KEY, tenant_id uuid, is_public boolean);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid() OR is_public);"
        )
    out = tmp_path / "xt"
    result = CliRunner().invoke(
        main,
        [
            "verify", "--mode", "cross-tenant", "--database-url", pg_url,
            "--schemas", "public", "--emit-repro", str(out),
        ],
    )
    assert result.exit_code == 1, result.output  # leak → exit 1
    sqlf = out / "public_docs_p.sql"
    assert sqlf.exists()
    body = sqlf.read_text()
    assert "cross-tenant leak reproduction" in body
    assert "set_config('request.jwt.claim.sub'" in body


@requires_docker
@requires_z3
def test_verify_cli_live_cross_tenant_leak_exits_one(
    pg_url: str, pg_conn: psycopg.Connection
) -> None:
    # End-to-end: an `OR is_public` bypass is a cross-tenant LEAK → exit 1, and
    # the report frames the row as another tenant's.
    with pg_conn.cursor() as cur:
        cur.execute(_AUTH_STUB)
        cur.execute(
            "CREATE TABLE public.docs "
            "  (id bigint PRIMARY KEY, tenant_id uuid, is_public boolean);"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p ON public.docs FOR SELECT TO public "
            "  USING (tenant_id = auth.uid() OR is_public);"
        )
    result = CliRunner().invoke(
        main,
        [
            "verify",
            "--mode",
            "cross-tenant",
            "--database-url",
            pg_url,
            "--schemas",
            "public",
        ],
    )
    assert result.exit_code == 1, result.output
    assert "LEAK" in result.output and "another tenant" in result.output


@requires_docker
@requires_z3
def test_verify_live_cross_tenant_scoped_is_isolated(
    pg_conn: psycopg.Connection,
) -> None:
    # The gold-standard `pgrls generate` shape is cross-tenant PROVEN end-to-end.
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
    assert _verdict(_xt(schema), "public.acct") == "isolated"
