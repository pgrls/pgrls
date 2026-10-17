"""Unit tests for `pgrls matrix` — the effective access matrix."""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import replace
from datetime import datetime, timezone

import psycopg
import pytest
from click.testing import CliRunner

from pgrls.cli import main
from pgrls.introspect import introspect
from pgrls.matrix import (
    CellProof,
    COMMANDS,
    Matrix,
    build_matrix,
    render_html,
    render_json,
    render_markdown,
    render_text,
)
from pgrls.model import BypassRlsRole, ColumnGrant, Grant, Policy, Schema, Table


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

_ALL_PRIVS = ("SELECT", "INSERT", "UPDATE", "DELETE")
_FIXED_AT = datetime(2026, 6, 8, 12, 0, 0, tzinfo=timezone.utc)


def _grant(role: str = "authenticated", privs: tuple[str, ...] = _ALL_PRIVS) -> Grant:
    return Grant(role=role, privileges=privs)


def _policy(
    *,
    permissive: bool = True,
    command: str = "ALL",
    roles: tuple[str, ...] = ("authenticated",),
    using: str | None = "true",
    check: str | None = None,
    name: str = "p",
) -> Policy:
    return Policy(
        name=name,
        command=command,
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=check,
    )


def _table(
    name: str,
    *,
    rls: bool,
    force: bool = True,
    policies: tuple[Policy, ...] = (),
    grants: tuple[Grant, ...] = (),
) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
        grants=grants,
    )


def _cell(matrix: Matrix, table: str, command: str, role: str):
    row = next(
        r for r in matrix.rows if r.qualified_name == table and r.command == command
    )
    return dict(zip(matrix.roles, row.cells, strict=True))[role]


# --- verdict logic ---------------------------------------------------------


def test_no_grant_is_denied() -> None:
    schema = Schema(
        tables=(_table("t", rls=True, policies=(_policy(),)),), role_memberships=()
    )
    assert _cell(build_matrix(schema), "public.t", "SELECT", "authenticated").verdict == "denied"


def test_grant_with_rls_off_is_open() -> None:
    schema = Schema(tables=(_table("t", rls=False, grants=(_grant(),)),))
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "open"
    assert cell.note == "RLS off"


def test_permissive_literal_true_is_open() -> None:
    schema = Schema(
        tables=(_table("t", rls=True, grants=(_grant(),), policies=(_policy(using="true"),)),)
    )
    assert _cell(build_matrix(schema), "public.t", "SELECT", "authenticated").verdict == "open"


def test_permissive_predicate_is_conditional() -> None:
    pred = "tenant_id = current_setting('app.t', true)::uuid"
    schema = Schema(
        tables=(_table("t", rls=True, grants=(_grant(),), policies=(_policy(using=pred),)),)
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "conditional"
    assert cell.predicate == pred


def test_unparseable_predicate_is_conditional_with_raw_sql(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # When parse_expr cannot parse a clause it returns None; _clause_is_open
    # then conservatively treats it as NOT open (the safe direction), so the
    # cell is CONDITIONAL with the raw predicate surfaced verbatim — never a
    # false OPEN. Pins the node-is-None fallback in _clause_is_open.
    schema = Schema(
        tables=(
            _table("t", rls=True, grants=(_grant(),), policies=(_policy(using="tenant_id = ((("),)),
        )
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    capsys.readouterr()  # swallow the pglast parse warning on stderr
    assert cell.verdict == "conditional"
    assert cell.predicate == "tenant_id = ((("


def test_grant_rls_on_no_permissive_is_denied() -> None:
    # RLS on, granted, but no applicable permissive policy → Postgres default-deny.
    schema = Schema(tables=(_table("t", rls=True, grants=(_grant(),)),))
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "denied"
    assert cell.note == "no permissive policy"


def test_restrictive_floor_with_open_permissive_is_conditional() -> None:
    # Permissive admits all rows, but a restrictive floor still gates → COND
    # showing the restrictive predicate only.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(
                    _policy(using="true", name="perm"),
                    _policy(permissive=False, using="deleted_at IS NULL", name="floor"),
                ),
            ),
        )
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "conditional"
    assert cell.predicate == "deleted_at IS NULL"


def test_unconditional_restrictive_floor_is_a_noop_open() -> None:
    # A literal-true restrictive floor (SEC031) narrows nothing — with an open
    # permissive it must be OPEN, not COND with a "true" predicate.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(
                    _policy(using="true", name="perm"),
                    _policy(permissive=False, using="true", name="floor"),
                ),
            ),
        )
    )
    assert _cell(build_matrix(schema), "public.t", "SELECT", "authenticated").verdict == "open"


def test_mixed_restrictive_floor_drops_noop_true() -> None:
    # true AND a real predicate → show only the predicate that matters.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(
                    _policy(using="true", name="perm"),
                    _policy(permissive=False, using="true", name="noop"),
                    _policy(permissive=False, using="deleted_at IS NULL", name="real"),
                ),
            ),
        )
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "conditional"
    assert cell.predicate == "deleted_at IS NULL"


def test_conditional_permissive_drops_noop_true_restrictive() -> None:
    # A no-op restrictive true must not pollute a real permissive predicate.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(
                    _policy(using="tenant_id = 1", name="perm"),
                    _policy(permissive=False, using="true", name="noop"),
                ),
            ),
        )
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "conditional"
    assert cell.predicate == "tenant_id = 1"  # no trailing " AND true"


def test_multiple_permissive_predicates_are_ored() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(
                    _policy(using="a = 1", name="p1"),
                    _policy(using="b = 2", name="p2"),
                ),
            ),
        )
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "conditional"
    assert cell.predicate == "(a = 1 OR b = 2)"


def test_bypassrls_role_is_open_when_granted() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant("admin", ("SELECT",)),),
                policies=(_policy(using="tenant_id = 1", roles=("admin",)),),
            ),
        ),
        bypassrls_roles=(BypassRlsRole(name="admin", superuser=False, can_login=True),),
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "admin")
    assert cell.verdict == "open"
    assert cell.note == "bypasses RLS"


def test_bypassrls_role_still_needs_grant() -> None:
    # BYPASSRLS skips the policies, not the table privilege — a bypass role
    # with no grant is still DENIED (grant gate precedes the bypass).
    schema = Schema(
        tables=(_table("t", rls=True, policies=(_policy(using="true"),)),),
        bypassrls_roles=(BypassRlsRole(name="admin", superuser=False, can_login=True),),
        role_memberships=(),
    )
    m = build_matrix(schema, roles=("admin",))
    assert _cell(m, "public.t", "SELECT", "admin").verdict == "denied"
    # …and by default it gets no column at all: it reaches nothing.
    assert "admin" not in build_matrix(schema).roles


# --- command → clause mapping ---------------------------------------------


def test_insert_uses_with_check_not_using() -> None:
    # USING is false (no read), WITH CHECK is true (any insert): SELECT denied,
    # INSERT open — proving INSERT is gated by WITH CHECK.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(_policy(using="false", check="true"),),
            ),
        )
    )
    m = build_matrix(schema)
    assert _cell(m, "public.t", "SELECT", "authenticated").verdict == "conditional"
    assert _cell(m, "public.t", "INSERT", "authenticated").verdict == "open"


def test_for_all_policy_insert_falls_back_to_using_when_no_with_check() -> None:
    # A FOR ALL policy with USING but no WITH CHECK: Postgres reuses USING as
    # the implicit WITH CHECK, so INSERT is gated (conditional), not OPEN.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(_policy(command="ALL", using="tenant_id = 1", check=None),),
            ),
        )
    )
    m = build_matrix(schema)
    ins = _cell(m, "public.t", "INSERT", "authenticated")
    assert ins.verdict == "conditional"
    assert ins.predicate == "tenant_id = 1"
    assert _cell(m, "public.t", "SELECT", "authenticated").verdict == "conditional"


def test_select_policy_without_using_is_denied() -> None:
    # A FOR SELECT permissive policy with no USING denies all rows (Postgres
    # default-deny) — a missing required clause must not read as OPEN.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(_policy(command="SELECT", using=None),),
            ),
        )
    )
    cell = _cell(build_matrix(schema), "public.t", "SELECT", "authenticated")
    assert cell.verdict == "denied"
    assert cell.note == "no applicable permissive clause"


def test_insert_only_policy_without_with_check_is_denied() -> None:
    # A FOR INSERT permissive policy with no WITH CHECK denies every insert
    # (and, being non-ALL, does not fall back to USING).
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(_policy(command="INSERT", using=None, check=None),),
            ),
        )
    )
    cell = _cell(build_matrix(schema), "public.t", "INSERT", "authenticated")
    assert cell.verdict == "denied"
    assert cell.note == "no applicable permissive clause"


def test_command_specific_policy_does_not_apply_to_other_commands() -> None:
    # A SELECT-only permissive policy leaves INSERT/UPDATE/DELETE with no
    # applicable permissive policy → denied.
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(_policy(command="SELECT", using="true"),),
            ),
        )
    )
    m = build_matrix(schema)
    assert _cell(m, "public.t", "SELECT", "authenticated").verdict == "open"
    assert _cell(m, "public.t", "INSERT", "authenticated").verdict == "denied"
    assert _cell(m, "public.t", "DELETE", "authenticated").verdict == "denied"


# --- grant / policy applicability -----------------------------------------


def test_public_grant_reaches_any_role() -> None:
    schema = Schema(
        tables=(_table("t", rls=False, grants=(_grant("PUBLIC", ("SELECT",)),)),)
    )
    # anon has no own grant, but PUBLIC does → open.
    assert _cell(build_matrix(schema), "public.t", "SELECT", "anon").verdict == "open"


def test_empty_policy_roles_applies_to_all() -> None:
    # A policy with no TO clause defaults to PUBLIC (applies to every role).
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant("anon", ("SELECT",)),),
                policies=(_policy(roles=(), using="true"),),
            ),
        )
    )
    assert _cell(build_matrix(schema), "public.t", "SELECT", "anon").verdict == "open"


def test_column_grant_confers_select_but_not_delete() -> None:
    # A column-level SELECT grant lets the role read rows → SELECT not denied.
    # DELETE has no column-level form, so a DELETE column grant is impossible
    # and a table without a DELETE table-grant stays denied.
    t = Table(
        schema="public",
        name="t",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        grants=(),
        column_grants=(
            ColumnGrant(role="reader", column="body", privileges=("SELECT",)),
        ),
    )
    m = build_matrix(Schema(tables=(t,), role_memberships=()), roles=("reader",))
    assert _cell(m, "public.t", "SELECT", "reader").verdict == "open"
    assert _cell(m, "public.t", "DELETE", "reader").verdict == "denied"


def test_policy_targeting_other_role_does_not_apply() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant("anon", ("SELECT",)),),
                policies=(_policy(roles=("authenticated",), using="true"),),
            ),
        ),
        role_memberships=(),
    )
    # anon is granted but the only policy targets authenticated → denied.
    assert _cell(build_matrix(schema), "public.t", "SELECT", "anon").verdict == "denied"


# --- role collection -------------------------------------------------------


def test_default_roles_always_present() -> None:
    m = build_matrix(Schema(tables=(_table("t", rls=False),)))
    assert set(m.roles) == {"PUBLIC", "anon", "authenticated"}


def test_grant_and_policy_roles_are_collected() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant("billing", ("SELECT",)),),
                policies=(_policy(roles=("auditor",)),),
            ),
        )
    )
    assert {"billing", "auditor"} <= set(build_matrix(schema).roles)


def test_system_roles_hidden_by_default_shown_on_flag() -> None:
    schema = Schema(
        tables=(_table("t", rls=False, grants=(_grant("pg_read_all_data", ("SELECT",)),)),)
    )
    assert "pg_read_all_data" not in build_matrix(schema).roles
    assert "pg_read_all_data" in build_matrix(schema, include_system=True).roles


def test_roles_override_is_exact() -> None:
    schema = Schema(
        tables=(_table("t", rls=False, grants=(_grant("billing", ("SELECT",)),)),)
    )
    m = build_matrix(schema, roles=("anon", "billing"))
    assert m.roles == ("anon", "billing")  # billing kept, authenticated dropped


def test_role_ordering_is_stable() -> None:
    schema = Schema(
        tables=(_table("t", rls=False, grants=(_grant("zeta", ("SELECT",)), _grant("alpha", ("SELECT",))),),)
    )
    roles = build_matrix(schema).roles
    # PUBLIC, anon, authenticated first; then the rest alphabetical.
    assert roles == ("PUBLIC", "anon", "authenticated", "alpha", "zeta")


# --- summary ---------------------------------------------------------------


def test_summary_counts_reconcile() -> None:
    schema = Schema(
        tables=(
            _table("a", rls=False, grants=(_grant(),)),  # open for every command
            _table("b", rls=True),  # denied (no grant) x 3 roles
        )
    )
    s = build_matrix(schema).summary
    assert s["open"] + s["denied"] + s["conditional"] + s["undecided"] == s["cells"]
    assert s["cells"] == s["tables"] * len(COMMANDS) * s["roles"]


# --- renderers -------------------------------------------------------------


def _sample_matrix() -> Matrix:
    return build_matrix(
        Schema(
            tables=(
                _table("open_t", rls=False, grants=(_grant(),)),
                _table(
                    "cond_t",
                    rls=True,
                    grants=(_grant(),),
                    policies=(_policy(using="tenant_id = 1"),),
                ),
                _table("denied_t", rls=True),
            ),
            role_memberships=(),
        )
    )


def test_render_text_has_headers_and_summary() -> None:
    out = render_text(_sample_matrix())
    assert "TABLE" in out and "CMD" in out and "authenticated" in out
    assert "OPEN" in out and "DENIED" in out and "COND" in out
    assert re.search(r"\d+ tables? x \d+ roles?:", out)


def test_render_text_empty() -> None:
    assert "No tables found" in render_text(build_matrix(Schema(tables=())))


def test_render_json_shape_and_predicate() -> None:
    payload = json.loads(render_json(_sample_matrix()))
    assert payload["roles"] == ["PUBLIC", "anon", "authenticated"]
    assert set(payload["summary"]) == {
        "tables", "roles", "cells", "open", "denied", "conditional", "undecided"
    }
    cond = next(
        r for r in payload["rows"] if r["table"] == "public.cond_t" and r["command"] == "SELECT"
    )
    acc = cond["access"]["authenticated"]
    assert acc["verdict"] == "conditional"
    assert acc["predicate"] == "tenant_id = 1"
    # every cell carries the three keys
    assert acc.keys() == {"verdict", "predicate", "note"}


def test_render_json_unicode_preserved() -> None:
    schema = Schema(tables=(_table("café", rls=False, grants=(_grant("naïve", ("SELECT",)),)),))
    out = render_json(build_matrix(schema, roles=("naïve",)))
    assert "café" in out and "naïve" in out  # ensure_ascii=False
    assert "\\u" not in out


def test_render_markdown_table_and_pipe_escape() -> None:
    schema = Schema(tables=(_table("we|ird", rls=False, grants=(_grant(),)),))
    out = render_markdown(build_matrix(schema))
    assert out.startswith("# Access matrix")
    assert "| Table | Command |" in out
    assert "we\\|ird" in out  # pipe escaped so the row isn't split


def test_render_markdown_empty() -> None:
    assert "No tables found" in render_markdown(build_matrix(Schema(tables=())))


def test_render_markdown_newline_in_role_name_does_not_split_header() -> None:
    # A role name with an embedded newline (legal via a quoted pg_roles
    # identifier) must not split the GFM header into two physical lines —
    # safe_location neutralizes it, mirroring the body cells.
    schema = Schema(tables=(_table("t", rls=False, grants=(_grant("ok", ("SELECT",)),)),))
    out = render_markdown(build_matrix(schema, roles=("ok", "ev\nil")))
    pipe_rows = [ln for ln in out.splitlines() if ln.startswith("|")]
    # header + separator + (1 table x 5 commands) = 7 rows, all the same width.
    assert len(pipe_rows) == 7
    assert len({ln.count("|") for ln in pipe_rows}) == 1, pipe_rows  # aligned
    assert not any(ln.startswith("il") for ln in out.splitlines())  # no orphan


def test_render_html_is_self_contained() -> None:
    out = render_html(_sample_matrix(), generated_at=_FIXED_AT)
    assert out.startswith("<!DOCTYPE html>")
    assert "<style>" in out and "</style>" in out
    assert "<link" not in out and "<script" not in out


def test_render_html_predicate_in_title_attr_and_escaped() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                grants=(_grant(),),
                policies=(_policy(using="x < 1 AND y > 2"),),
            ),
        )
    )
    out = render_html(build_matrix(schema), generated_at=_FIXED_AT)
    # predicate surfaces as a tooltip, HTML-escaped
    assert 'title="x &lt; 1 AND y &gt; 2"' in out
    assert "x < 1 AND y > 2" not in out


def test_render_html_escapes_table_name() -> None:
    schema = Schema(tables=(_table('a<b>&"', rls=False, grants=(_grant(),)),))
    out = render_html(build_matrix(schema), generated_at=_FIXED_AT)
    assert "a&lt;b&gt;&amp;&quot;" in out
    assert "<b>" not in out


def test_render_html_empty_placeholder_spans_columns() -> None:
    out = render_html(build_matrix(Schema(tables=())), generated_at=_FIXED_AT)
    assert "<!DOCTYPE html>" in out
    assert 'colspan="5"' in out  # 2 fixed cols + 3 default roles
    assert "No tables found" in out


def test_render_html_rejects_naive_generated_at() -> None:
    with pytest.raises(ValueError, match="aware"):
        render_html(_sample_matrix(), generated_at=datetime(2026, 6, 8, 12, 0, 0))


# --- cross-format agreement ------------------------------------------------


def test_all_formats_agree_on_verdict_counts() -> None:
    m = _sample_matrix()
    s = m.summary
    # JSON is the structured source of truth.
    payload = json.loads(render_json(m))
    verdicts = [c["verdict"] for r in payload["rows"] for c in r["access"].values()]
    assert verdicts.count("open") == s["open"]
    assert verdicts.count("denied") == s["denied"]
    assert verdicts.count("conditional") == s["conditional"]
    # text + markdown label tallies match the same counts.
    for render in (render_text, render_markdown):
        body = render(m)
        assert body.count("OPEN") == s["open"]
        assert body.count("DENIED") == s["denied"]
        assert body.count("COND") == s["conditional"]


# --- CLI -------------------------------------------------------------------


def test_matrix_cli_help() -> None:
    result = CliRunner().invoke(main, ["matrix", "--help"])
    assert result.exit_code == 0
    assert "access matrix" in result.output


def test_matrix_cli_errors_without_database_url() -> None:
    result = CliRunner().invoke(main, ["matrix"], env={"DATABASE_URL": ""})
    assert result.exit_code == 2
    assert "No database connection" in result.output


def test_matrix_cli_rejects_empty_roles() -> None:
    result = CliRunner().invoke(
        main,
        ["matrix", "--database-url", "postgresql://u@/db", "--roles", " , "],
    )
    assert result.exit_code == 2
    assert "no role names" in result.output


def test_matrix_cli_checks_the_sec045_config_before_connecting(tmp_path) -> None:
    """A bad `[lint.rules.SEC045].patterns` is a config error whether or not
    the database is reachable — reported first, like a bad --roles."""
    config = tmp_path / "pgrls.toml"
    config.write_text('[lint.rules.SEC045]\npatterns = "ssn"\n')
    result = CliRunner().invoke(main, [
        "matrix", "--config", str(config),
        "--database-url", "postgresql://nobody@127.0.0.1:1/nothing",
    ])
    assert result.exit_code == 2
    assert "patterns must be a list" in result.output
    assert "Database error" not in result.output


def test_matrix_cli_is_registered_format_list() -> None:
    from pgrls.matrix import MATRIX_FORMATS

    assert MATRIX_FORMATS == ("text", "json", "markdown", "html")


# --- live introspection (Docker) ------------------------------------------
# These pin the matrix against *real* introspect() output — the only place
# that confirms PUBLIC comes back as role "PUBLIC", privileges are uppercase,
# and BYPASSRLS roles land in schema.bypassrls_roles. The unit tests above
# construct the model by hand and would not catch an introspection-shape drift.

_LIVE_DDL = """
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mtx_auth')
    THEN CREATE ROLE mtx_auth NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mtx_admin')
    THEN CREATE ROLE mtx_admin NOLOGIN BYPASSRLS; END IF;
END $$;
CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid NOT NULL);
GRANT SELECT, INSERT ON public.docs TO mtx_auth;
GRANT SELECT ON public.docs TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.docs TO mtx_admin;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p_sel ON public.docs FOR SELECT TO mtx_auth
  USING (tenant_id = current_setting('app.t', true)::uuid);
"""


@requires_docker
def test_matrix_live_against_real_introspection(pg_conn: psycopg.Connection) -> None:
    try:
        with pg_conn.cursor() as cur:
            cur.execute(_LIVE_DDL)
        schema = introspect(pg_conn, schemas=["public"])

        m = build_matrix(schema, roles=("PUBLIC", "mtx_auth", "mtx_admin"))

        # PUBLIC: holds a real SELECT grant (proving introspect emits role
        # "PUBLIC"), but RLS is on and no policy targets it → default-deny.
        pub = _cell(m, "public.docs", "SELECT", "PUBLIC")
        assert pub.verdict == "denied", pub
        assert pub.note == "no permissive policy"

        # mtx_auth: granted SELECT, RLS on, a tenant-scoped SELECT policy → COND
        # (the predicate round-trips through pg_get_expr, so just assert it's set).
        auth_sel = _cell(m, "public.docs", "SELECT", "mtx_auth")
        assert auth_sel.verdict == "conditional"
        assert auth_sel.predicate and "tenant_id" in auth_sel.predicate

        # mtx_auth INSERT: granted, RLS on, but the only policy is SELECT-only →
        # no permissive policy applies to INSERT → denied.
        assert _cell(m, "public.docs", "INSERT", "mtx_auth").verdict == "denied"

        # mtx_admin: BYPASSRLS role + full grants → open (proves bypassrls_roles
        # introspection feeds the bypass note).
        admin = _cell(m, "public.docs", "SELECT", "mtx_admin")
        assert admin.verdict == "open"
        assert admin.note == "bypasses RLS"
    finally:
        # `mtx_admin` holds BYPASSRLS and roles are CLUSTER-wide: left behind,
        # SEC016 fires on every later test that asserts an exact SEC016 set in
        # the shared session database (order-dependent). Anything this test
        # creates, it removes.
        with pg_conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public")
            cur.execute("DROP OWNED BY mtx_auth, mtx_admin")
            cur.execute("DROP ROLE IF EXISTS mtx_auth, mtx_admin")


@requires_docker
def test_matrix_live_for_all_insert_uses_using_when_no_with_check(
    pg_conn: psycopg.Connection,
) -> None:
    # Pins the introspection assumption behind the INSERT fallback: a FOR ALL
    # policy with USING and no WITH CHECK leaves pg_policy.polwithcheck NULL
    # (with_check_sql=None), and Postgres reuses USING as the INSERT check — so
    # the INSERT cell must be CONDITIONAL, not a false OPEN.
    with pg_conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE public.docs (id bigint PRIMARY KEY, tenant_id uuid NOT NULL);"
            "GRANT SELECT, INSERT, UPDATE, DELETE ON public.docs TO PUBLIC;"
            "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;"
            "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;"
            "CREATE POLICY p_all ON public.docs FOR ALL TO PUBLIC "
            "  USING (tenant_id = current_setting('app.t', true)::uuid);"
        )
    schema = introspect(pg_conn, schemas=["public"])
    m = build_matrix(schema, roles=("PUBLIC",))
    ins = _cell(m, "public.docs", "INSERT", "PUBLIC")
    assert ins.verdict == "conditional", ins
    assert ins.predicate and "tenant_id" in ins.predicate


@requires_docker
def test_matrix_live_rls_off_table_is_open(pg_conn: psycopg.Connection) -> None:
    with pg_conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE public.flat (id bigint);"
            "GRANT SELECT ON public.flat TO PUBLIC;"
        )
    schema = introspect(pg_conn, schemas=["public"])
    # Named explicitly: by default `anon` gets a column only when the role
    # exists, and this test does not create it.
    cell = _cell(build_matrix(schema, roles=("anon",)), "public.flat", "SELECT", "anon")
    # anon inherits the PUBLIC grant; RLS off → open with the RLS-off note.
    assert cell.verdict == "open"
    assert cell.note == "RLS off"


# --- the shared engine: membership, ownership, superuser ---------------------
#
# Before the fold, `matrix` matched role names literally. Measured on PG16, that
# reported DENIED for a role that read every row in three ways; each is pinned
# below, alongside its negative control.

from pgrls.model import Role, RoleMembership  # noqa: E402


def _owned(owner: str, *, force: bool, policies=(), grants=()) -> Table:
    return Table(
        schema="public", name="t", rls_enabled=True, force_rls=force,
        policies=policies, grants=grants, owner=owner,
    )


def test_grant_held_through_an_inherit_membership_is_reachable() -> None:
    schema = Schema(
        tables=(_table("t", rls=False, grants=(_grant("readers", ("SELECT",)),)),),
        role_memberships=(RoleMembership(member="app", role="readers", inherit=True),),
    )
    assert _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app").verdict == "open"


def test_noinherit_member_does_not_hold_the_groups_grant() -> None:
    """Measured: a NOINHERIT member's view got `permission denied`."""
    schema = Schema(
        tables=(_table("t", rls=False, grants=(_grant("readers", ("SELECT",)),)),),
        role_memberships=(RoleMembership(member="app", role="readers", inherit=False),),
    )
    assert _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app").verdict == "denied"


def test_owner_without_force_is_open() -> None:
    schema = Schema(
        tables=(_owned("app", force=False,
                       policies=(_policy(roles=("someone",), using="tenant_id = 1"),)),),
        role_memberships=(),
    )
    c = _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app")
    assert c.verdict == "open" and "FORCE" in (c.note or "")


def test_owner_with_force_is_bound_by_the_policies() -> None:
    schema = Schema(
        tables=(_owned("app", force=True,
                       policies=(_policy(roles=("app",), using="tenant_id = 1"),)),),
        role_memberships=(),
    )
    c = _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app")
    assert c.verdict == "conditional" and c.predicate == "tenant_id = 1"


def test_policy_to_a_group_applies_to_its_members() -> None:
    schema = Schema(
        tables=(_table("t", rls=True, grants=(_grant("app", ("SELECT",)),),
                       policies=(_policy(roles=("grp",), using="true"),)),),
        role_memberships=(RoleMembership(member="app", role="grp", inherit=True),),
    )
    assert _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app").verdict == "open"


def test_policy_to_a_group_does_not_bind_a_noinherit_member() -> None:
    """Policies follow INHERIT edges, like grants (`has_privs_of_role`).
    Measured on PG15-17: a NOINHERIT member holding its own grant read 0 rows
    under `TO grp USING (true)`. The grant is the member's own here."""
    schema = Schema(
        tables=(_table("t", rls=True, grants=(_grant("app", ("SELECT",)),),
                       policies=(_policy(roles=("grp",), using="true"),)),),
        role_memberships=(RoleMembership(member="app", role="grp", inherit=False),),
    )
    assert _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app").verdict == "denied"


@pytest.mark.parametrize(("inherit", "expected"), [(True, "conditional"), (False, "open")])
def test_restrictive_floor_to_a_group_binds_only_inherit_members(
    inherit: bool, expected: str
) -> None:
    """The unsafe direction. Measured on PG15-17: a restrictive `TO grp` floor
    cut an INHERIT member to the matching rows while a NOINHERIT member read
    every row past it. Applying the floor to every member reported COND for a
    role that read the whole table."""
    schema = Schema(
        tables=(_table("t", rls=True, grants=(_grant("app", ("SELECT",)),),
                       policies=(_policy(roles=("PUBLIC",), using="true"),
                                 _policy(name="floor", permissive=False, roles=("grp",),
                                         using="tenant_id = 1"))),),
        role_memberships=(RoleMembership(member="app", role="grp", inherit=inherit),),
    )
    assert _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app").verdict == expected


def test_superuser_needs_no_grant() -> None:
    schema = Schema(
        tables=(_table("t", rls=True, policies=(_policy(using="tenant_id = 1"),)),),
        roles=(Role("root", True, True, False),),
        role_memberships=(),
    )
    c = _cell(build_matrix(schema, roles=("root",)), "public.t", "DELETE", "root")
    assert c.verdict == "open" and c.note == "superuser"


def test_pg_read_all_data_confers_select_but_not_writes() -> None:
    schema = Schema(
        tables=(_table("t", rls=False),),
        role_memberships=(RoleMembership("analyst", "pg_read_all_data", True),),
    )
    m = build_matrix(schema, roles=("analyst",))
    assert _cell(m, "public.t", "SELECT", "analyst").verdict == "open"
    for cmd in ("INSERT", "UPDATE", "DELETE"):
        assert _cell(m, "public.t", cmd, "analyst").verdict == "denied", cmd


def test_pg_write_all_data_confers_writes_but_not_select() -> None:
    schema = Schema(
        tables=(_table("t", rls=False),),
        role_memberships=(RoleMembership("etl", "pg_write_all_data", True),),
    )
    m = build_matrix(schema, roles=("etl",))
    assert _cell(m, "public.t", "SELECT", "etl").verdict == "denied"
    for cmd in ("INSERT", "UPDATE", "DELETE"):
        assert _cell(m, "public.t", cmd, "etl").verdict == "open", cmd


def test_without_a_graph_a_named_role_is_undecided_but_public_is_not() -> None:
    """A named role might inherit a grant (or `pg_read_all_data`) we cannot
    see, so `denied` would be a guess in the unsafe direction. PUBLIC has no
    memberships of its own, so it stays decided even without a graph."""
    schema = Schema(tables=(_table("t", rls=False),), role_memberships=None)
    m = build_matrix(schema, roles=("PUBLIC", "app"))
    assert _cell(m, "public.t", "SELECT", "app").verdict == "undecided"
    assert _cell(m, "public.t", "SELECT", "PUBLIC").verdict == "denied"


def test_summary_line_mentions_undecided_only_when_present() -> None:
    from pgrls.matrix import _summary_line
    decided = build_matrix(Schema(tables=(_table("t", rls=False),), role_memberships=()),
                           roles=("app",))
    assert "undecided" not in _summary_line(decided)
    undecided = build_matrix(Schema(tables=(_table("t", rls=False),), role_memberships=None),
                             roles=("app",))
    assert "5 undecided" in _summary_line(undecided)  # one per command


def test_granted_role_with_an_undecidable_policy_is_undecided_not_denied() -> None:
    """The role holds its own grant, so privilege is decided — but the only
    permissive policy targets a group it may belong to through a membership we
    cannot see. `denied` would under-report; it is `undecided`.

    (A separate case from the no-grant one above, whose `undecided` comes from
    the privilege check: an earlier test assignment let this branch go
    completely untested.)"""
    schema = Schema(
        tables=(_table("t", rls=True, grants=(_grant("app", ("SELECT",)),),
                       policies=(_policy(roles=("grp",), using="true"),)),),
        role_memberships=None,
    )
    c = _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app")
    assert c.verdict == "undecided" and "grp" not in (c.predicate or "")
    assert "cannot tell whether" in (c.note or "")


def test_known_conditional_plus_an_undecidable_policy_is_undecided() -> None:
    """A known conditional read, plus a policy that MIGHT also apply and widen
    it. Reporting the known predicate alone would under-report."""
    schema = Schema(
        tables=(_table("t", rls=True, grants=(_grant("app", ("SELECT",)),),
                       policies=(
                           _policy(name="own", roles=("app",), using="tenant_id = 1"),
                           _policy(name="maybe", roles=("grp",), using="true"),
                       )),),
        role_memberships=None,
    )
    c = _cell(build_matrix(schema, roles=("app",)), "public.t", "SELECT", "app")
    assert c.verdict == "undecided" and "maybe" in (c.note or "")


# --- doors: definer views and SECURITY DEFINER functions widen SELECT ---------

from pgrls.model import SecdefFunction, View  # noqa: E402

_T = (("public", "t"),)


def _definer_view(owner_super: bool = True) -> View:
    return View(
        schema="public", name="v", is_materialized=False, security_invoker=False,
        security_barrier=False, definition="", references=_T,
        security_definer_calls=(), grants=(_grant("anon", ("SELECT",)),),
        owner="root", owner_bypasses_rls=owner_super, direct_references=_T,
        owner_is_superuser=owner_super,
    )


def _door_schema(**extra) -> Schema:
    return Schema(
        tables=(_table("t", rls=True, policies=(_policy(roles=("app",), using="tenant_id = 1"),)),),
        roles=(Role("anon", True, False, False), Role("root", False, True, False)),
        role_memberships=(),
        **extra,
    )


def test_a_definer_view_opens_select_for_a_role_with_no_grant() -> None:
    """Before the fold `matrix` had no notion of doors: anon held no grant on
    `t`, so it showed DENIED while anon read every row through `v`."""
    m = build_matrix(_door_schema(views=(_definer_view(),)), roles=("anon",))
    c = _cell(m, "public.t", "SELECT", "anon")
    assert c.verdict == "open" and "public.v" in (c.note or "")


def test_a_secdef_function_opens_select_for_a_role_with_no_grant() -> None:
    fn = SecdefFunction(
        qualified_name="public.f", body="SELECT * FROM t", language="sql",
        owner="root", execute_roles=("PUBLIC",), owner_bypasses_rls=True,
    )
    m = build_matrix(_door_schema(security_definer_functions=(fn,)), roles=("anon",))
    c = _cell(m, "public.t", "SELECT", "anon")
    assert c.verdict == "open" and "public.f" in (c.note or "")


def test_a_read_only_grant_on_a_view_opens_no_write() -> None:
    """A view is a write door only for the writes the role holds on it: a
    SELECT grant opens reads alone (write doors are pinned elsewhere)."""
    m = build_matrix(_door_schema(views=(_definer_view(),)), roles=("anon",))
    for cmd in ("INSERT", "UPDATE", "DELETE"):
        assert _cell(m, "public.t", cmd, "anon").verdict == "denied", cmd


def test_a_door_never_narrows_a_cell() -> None:
    """anon reads every row directly; a door that is merely conditional must
    not downgrade that.

    The door has to genuinely exist and be NARROWER for this to test anything:
    `svc` holds its own grant and its own row filter, so reading through `v`
    (as `svc`) is conditional while anon's direct read is open. An earlier
    version gave `svc` no grant, so the door was a dead path, no door existed,
    and the rule went unexercised."""
    t = _table(
        "t", rls=True,
        grants=(_grant("anon", ("SELECT",)), _grant("svc", ("SELECT",))),
        policies=(
            _policy(name="anon_all", roles=("anon",), using="true"),
            _policy(name="svc_some", roles=("svc",), using="tenant_id = 1"),
        ),
    )
    ordinary = View(
        schema="public", name="v", is_materialized=False, security_invoker=False,
        security_barrier=False, definition="", references=_T,
        security_definer_calls=(), grants=(_grant("anon", ("SELECT",)),),
        owner="svc", owner_bypasses_rls=False, direct_references=_T,
    )
    s = Schema(tables=(t,), views=(ordinary,),
               roles=(Role("anon", True, False, False), Role("svc", False, False, False)),
               role_memberships=())
    assert _cell(build_matrix(s, roles=("anon",)), "public.t", "SELECT", "anon").verdict == "open"


# --- sensitive exposures ------------------------------------------------------

from pgrls.model import ColumnGrant as _CG  # noqa: E402


def _pii_schema(*, view: bool) -> Schema:
    # A permissive policy for anon, so its own column grant yields rows. With
    # RLS on and NO policy, the grant reads zero rows (default-deny) and is
    # rightly not an exposure — an earlier version of this fixture missed that.
    users = Table(
        schema="public", name="users", rls_enabled=True, force_rls=True,
        policies=(_policy(roles=("anon",), using="true"),),
        owner="own", grants=(), columns=("id", "email", "ssn"),
        column_grants=(_CG(role="anon", column="email", privileges=("SELECT",)),),
    )
    ut = (("public", "users"),)
    views = (View(
        schema="public", name="dir", is_materialized=False, security_invoker=False,
        security_barrier=False, definition="", references=ut, security_definer_calls=(),
        grants=(_grant("anon", ("SELECT",)),), owner="root", owner_bypasses_rls=True,
        direct_references=ut, owner_is_superuser=True,
    ),) if view else ()
    return Schema(
        tables=(users,), views=views, role_memberships=(),
        roles=(Role("anon", True, False, False), Role("root", False, True, False)),
    )


def _exp(m, column):
    return {e.column: e for e in m.exposures}.get(column)


def test_a_column_grant_is_credited_only_for_its_own_columns() -> None:
    """Measured in the rendered output: `ssn`, reachable ONLY through the
    definer view, was listed as reached via the column grant on `email`."""
    m = build_matrix(_pii_schema(view=True), roles=("anon",))
    assert "column grant" in _exp(m, "email").via
    assert _exp(m, "ssn").via == "view public.dir"


def test_a_column_grant_alone_exposes_only_its_column() -> None:
    m = build_matrix(_pii_schema(view=False), roles=("anon",))
    assert _exp(m, "email") is not None
    assert _exp(m, "ssn") is None  # never granted, and no door


def test_a_grant_held_by_the_role_itself_is_not_labelled_via_itself() -> None:
    m = build_matrix(_pii_schema(view=False), roles=("anon",))
    assert _exp(m, "email").via == "column grant"


def test_json_always_carries_the_exposures_key() -> None:
    empty = build_matrix(Schema(tables=(_table("t", rls=False),), role_memberships=()),
                         roles=("anon",))
    assert json.loads(render_json(empty))["sensitive_exposures"] == []
    full = json.loads(render_json(build_matrix(_pii_schema(view=True), roles=("anon",))))
    assert {e["column"] for e in full["sensitive_exposures"]} == {"email", "ssn"}


def test_no_exposures_leaves_the_text_output_unchanged() -> None:
    m = build_matrix(Schema(tables=(_table("t", rls=False),), role_memberships=()),
                     roles=("anon",))
    assert not render_text(m).startswith("Sensitive columns reachable")


def test_a_grant_that_yields_no_rows_is_not_an_exposure() -> None:
    """RLS on with no applicable permissive policy is default-deny: holding the
    column grant reads zero rows, so it is not an exposure."""
    users = Table(
        schema="public", name="users", rls_enabled=True, force_rls=True, policies=(),
        owner="own", grants=(), columns=("id", "email"),
        column_grants=(_CG(role="anon", column="email", privileges=("SELECT",)),),
    )
    s = Schema(tables=(users,), role_memberships=(), roles=(Role("anon", True, False, False),))
    assert build_matrix(s, roles=("anon",)).exposures == ()


# --- doors for every command, traced bodies, parents -------------------------
#
# Review iteration 1 found each of these reporting less access than Postgres
# allows; every expectation below was measured live (see the docstrings).

from pgrls.matrix import Untraced  # noqa: E402

_ALL5 = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")


def _t(
    name: str = "t",
    *,
    schema: str = "public",
    owner: str = "own",
    rls: bool = True,
    force: bool = False,
    policies: tuple[Policy, ...] = (),
    grants: tuple[Grant, ...] = (),
    column_grants: tuple[ColumnGrant, ...] = (),
    partition_of: tuple[str, str] | None = None,
    inherits: tuple[tuple[str, str], ...] = (),
) -> Table:
    return Table(
        schema=schema, name=name, rls_enabled=rls, force_rls=force, policies=policies,
        grants=grants, column_grants=column_grants, owner=owner,
        columns=("id", "tenant_id", "email"), partition_of=partition_of, inherits=inherits,
    )


def _v(
    name: str,
    refs: tuple[tuple[str, str], ...],
    *,
    owner: str,
    invoker: bool = False,
    grants: tuple[Grant, ...] = (),
    updatable: tuple[str, ...] | None = ("INSERT", "UPDATE", "DELETE"),
    mat: bool = False,
    direct: tuple[tuple[str, str], ...] | None = None,
) -> View:
    return View(
        schema="public", name=name, is_materialized=mat, security_invoker=invoker,
        security_barrier=False, definition="", references=refs, security_definer_calls=(),
        grants=grants, owner=owner, direct_references=refs if direct is None else direct,
        updatable=() if mat else updatable,
    )


def _f(
    body: str,
    *,
    owner: str,
    execute: tuple[str, ...] = ("PUBLIC",),
    lang: str = "sql",
    definition: str | None = None,
    search_path: str | None = None,
) -> SecdefFunction:
    return SecdefFunction(
        qualified_name="public.f", body=body, language=lang, owner=owner,
        execute_roles=execute, definition=definition, search_path=search_path,
    )


def _s(tables=(), views=(), fns=(), roles=(), memberships=()) -> Schema:
    return Schema(
        tables=tuple(tables), views=tuple(views), security_definer_functions=tuple(fns),
        roles=tuple(roles), role_memberships=tuple(memberships),
    )


def _r(name: str, *, su: bool = False, brls: bool = False) -> Role:
    return Role(name, True, su, brls)


_OWN_T = (("public", "t"),)
_TENANT_A = _policy(roles=("PUBLIC",), using="tenant_id = 'a'", name="tenant_a")


def test_write_through_an_updatable_definer_view_runs_as_its_owner() -> None:
    """Measured: UPDATE / DELETE on the table touched 0 rows, and through a
    definer view owned by the (non-FORCE'd) table owner every row."""
    t = _t(policies=(_policy(roles=("PUBLIC",), using="owner_name = current_user"),),
           grants=(_grant("app", ("SELECT", "UPDATE", "DELETE")),))
    v = _v("v", _OWN_T, owner="own", grants=(_grant("app", ("UPDATE", "DELETE")),))
    m = build_matrix(_s([t], [v], roles=[_r("app"), _r("own")]), roles=("app",))
    for cmd in ("UPDATE", "DELETE"):
        c = _cell(m, "public.t", cmd, "app")
        assert c.verdict == "open" and "definer view public.v" in (c.note or ""), cmd
    # No INSERT on the view, and none on the table: nothing opens it.
    assert _cell(m, "public.t", "INSERT", "app").verdict == "denied"


def test_a_view_that_accepts_no_writes_is_no_write_door() -> None:
    t = _t()
    v = _v("v", _OWN_T, owner="own", grants=(_grant("app", ("SELECT", "UPDATE")),),
           updatable=())
    m = build_matrix(_s([t], [v], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "UPDATE", "app").verdict == "denied"
    assert _cell(m, "public.t", "SELECT", "app").verdict == "open"  # reads still pass


def test_uncaptured_updatability_is_undecided_not_denied() -> None:
    t = _t()
    v = _v("v", _OWN_T, owner="own", grants=(_grant("app", ("UPDATE",)),), updatable=None)
    m = build_matrix(_s([t], [v], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "UPDATE", "app").verdict == "undecided"


def test_an_invoker_view_inside_a_definer_view_resets_writes_to_the_caller() -> None:
    """Measured: UPDATE through outer(definer, owned by the table owner) over
    inner(invoker) updated 0 rows — the inner view ran as the caller."""
    t = _t(policies=(_policy(roles=("PUBLIC",), using="owner_name = current_user"),),
           grants=(_grant("app", ("UPDATE",)),))
    inner = _v("inner", _OWN_T, owner="own", invoker=True)
    outer = _v("outer", _OWN_T, owner="own", grants=(_grant("app", ("UPDATE",)),),
               direct=(("public", "inner"),))
    m = build_matrix(_s([t], [inner, outer], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "UPDATE", "app").verdict == "conditional"


@pytest.mark.parametrize(("body", "opens"), [
    ("DELETE FROM public.t", {"DELETE"}),
    ("DELETE FROM public.t RETURNING *", {"DELETE", "SELECT"}),
    ("INSERT INTO public.t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = excluded.id",
     {"INSERT", "UPDATE"}),
    ("TRUNCATE public.t", {"TRUNCATE"}),
    ("WITH d AS (DELETE FROM public.t RETURNING *) SELECT count(*) FROM d", {"DELETE", "SELECT"}),
    ("SELECT * FROM public.t", {"SELECT"}),
])
def test_a_function_opens_exactly_the_commands_its_body_runs(body: str, opens: set[str]) -> None:
    """A SECURITY DEFINER body runs each statement as its owner. Measured: a
    body `DELETE FROM t` deleted every row for a caller with no privilege — and
    it reads nothing back, so it is no SELECT door."""
    m = build_matrix(_s([_t()], fns=[_f(body, owner="own")], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    got = {cmd for cmd in _ALL5 if _cell(m, "public.t", cmd, "app").verdict == "open"}
    assert got == opens


_PLPGSQL = """CREATE FUNCTION public.f(p integer) RETURNS SETOF public.t
 LANGUAGE plpgsql SECURITY DEFINER AS $x$
DECLARE n int;
BEGIN
  n := (SELECT count(*) FROM public.a);
  IF EXISTS (SELECT 1 FROM public.b) THEN
    UPDATE public.c SET id = p;
  END IF;
  RETURN QUERY SELECT * FROM public.t;
END $x$"""


def test_a_plpgsql_body_is_traced_statement_by_statement() -> None:
    """Measured: a PL/pgSQL SECURITY DEFINER function returned every row to a
    caller whose direct read was `permission denied`. Assignments and IF
    conditions hold subqueries too."""
    tables = [_t(n) for n in ("a", "b", "c", "t")]
    f = _f("<body>", owner="own", lang="plpgsql", definition=_PLPGSQL)
    m = build_matrix(_s(tables, fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    for name in ("a", "b", "t"):
        assert _cell(m, f"public.{name}", "SELECT", "app").verdict == "open", name
    assert _cell(m, "public.c", "UPDATE", "app").verdict == "open"
    assert _cell(m, "public.c", "SELECT", "app").verdict == "denied"
    assert m.untraced == ()


def test_dynamic_sql_is_listed_but_the_static_part_still_counts() -> None:
    body = """CREATE FUNCTION public.f() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $x$
BEGIN
  PERFORM 1 FROM public.t;
  EXECUTE format('DELETE FROM %I', 'other');
END $x$"""
    f = _f("<body>", owner="own", lang="plpgsql", definition=body)
    m = build_matrix(_s([_t()], fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "SELECT", "app").verdict == "open"
    [u] = m.untraced
    assert u.door == "public.f" and "dynamic SQL" in u.reason
    assert u.reached_by == "EXECUTE: PUBLIC, owner own"


def test_a_role_inheriting_the_function_owner_can_execute_it() -> None:
    """Measured: EXECUTE revoked from PUBLIC, `GRANT svc TO app`, svc BYPASSRLS:
    app read 2 of 4 rows directly and 4 of 4 through the function. The owner's
    own EXECUTE is implicit, so it is not in the function's ACL."""
    t = _t(policies=(_TENANT_A,), grants=(_grant("svc", ("SELECT",)),))
    f = _f("SELECT * FROM public.t", owner="svc", execute=())
    m = build_matrix(
        _s([t], fns=[f], roles=[_r("app"), _r("svc", brls=True), _r("own")],
           memberships=[RoleMembership("app", "svc", True)]),
        roles=("app",),
    )
    assert _cell(m, "public.t", "SELECT", "app").verdict == "open"


def test_a_function_reading_through_an_invoker_view_reads_as_its_owner() -> None:
    """Inside a SECURITY DEFINER body `current_user` is the owner, so an
    invoker view read there runs as the owner — a door, not the caller's own
    access."""
    v = _v("v", _OWN_T, owner="own", invoker=True)
    f = _f("SELECT * FROM public.v", owner="own")
    m = build_matrix(_s([_t()], [v], [f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "SELECT", "app").verdict == "open"


@pytest.mark.parametrize(("search_path", "reached"), [
    ("b, pg_temp", {"b.t"}),
    (None, {"a.t", "b.t"}),  # the caller's search_path decides: either could win
])
def test_a_bare_name_resolves_through_the_functions_search_path(
    search_path: str | None, reached: set[str]
) -> None:
    tables = [_t(schema="a"), _t(schema="b")]
    f = _f("SELECT * FROM t", owner="own", search_path=search_path)
    m = build_matrix(_s(tables, fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    got = {q for q in ("a.t", "b.t") if _cell(m, q, "SELECT", "app").verdict == "open"}
    assert got == reached


def test_a_partition_is_reached_through_its_parent() -> None:
    """Measured: a partition with RLS FORCE'd, no policy and no grant was read,
    updated, deleted and truncated through its parent, and an INSERT into the
    parent was routed into it."""
    parent = _t("p", rls=False, grants=(_grant("app", _ALL5),))
    child = _t("p_a", force=True, partition_of=("public", "p"))
    m = build_matrix(_s([parent, child], roles=[_r("app"), _r("own")]), roles=("app",))
    for cmd in _ALL5:
        c = _cell(m, "public.p_a", cmd, "app")
        assert c.verdict == "open" and "through parent public.p" in (c.note or ""), cmd


def test_an_inheritance_child_is_reached_through_its_parent_except_insert() -> None:
    """An INSERT into a classic-inheritance parent stays in the parent."""
    parent = _t("ip", rls=False, grants=(_grant("app", _ALL5),))
    child = _t("ic", force=True, inherits=(("public", "ip"),))
    m = build_matrix(_s([parent, child], roles=[_r("app"), _r("own")]), roles=("app",))
    assert {c for c in _ALL5 if _cell(m, "public.ic", c, "app").verdict == "open"} == \
        {"SELECT", "UPDATE", "DELETE", "TRUNCATE"}


def test_a_parents_policies_filter_the_childs_rows() -> None:
    """Measured: through the parent, the child's rows were filtered by the
    PARENT's policy; the child's own deny-all did not apply."""
    parent = _t("ip", policies=(_TENANT_A,), grants=(_grant("app", ("SELECT",)),))
    child = _t("ic", force=True, inherits=(("public", "ip"),))
    m = build_matrix(_s([parent, child], roles=[_r("app"), _r("own")]), roles=("app",))
    c = _cell(m, "public.ic", "SELECT", "app")
    assert c.verdict == "conditional" and c.predicate == "tenant_id = 'a'"


def test_two_different_filtered_paths_are_undecided() -> None:
    """Measured: anon read id 1 directly and id 2 through a definer view. The
    cell said COND `(id = 1)`; the union of two filters can be every row."""
    t = _t(grants=(_grant("anon", ("SELECT",)), _grant("svc", ("SELECT",))),
           policies=(_policy(roles=("anon",), using="id = 1", name="p_anon"),
                     _policy(roles=("svc",), using="id = 2", name="p_svc")))
    v = _v("v", _OWN_T, owner="svc", grants=(_grant("anon", ("SELECT",)),))
    m = build_matrix(_s([t], [v], roles=[_r("anon"), _r("svc"), _r("own")]), roles=("anon",))
    c = _cell(m, "public.t", "SELECT", "anon")
    assert c.verdict == "undecided" and "definer view public.v" in (c.note or "")


def test_the_same_filter_on_two_paths_stays_conditional() -> None:
    parent = _t("p", policies=(_TENANT_A,), grants=(_grant("app", ("SELECT",)),))
    child = _t("p_a", policies=(_TENANT_A,), grants=(_grant("app", ("SELECT",)),),
               partition_of=("public", "p"))
    m = build_matrix(_s([parent, child], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.p_a", "SELECT", "app").verdict == "conditional"


@pytest.mark.parametrize("policies", [
    (_policy(roles=("svc",), using="id = 1 OR true"),),
    (_policy(roles=("svc",), using="true", name="perm"),
     _policy(roles=("svc",), using="true", name="floor", permissive=False)),
])
def test_a_door_is_judged_by_the_same_rules_as_a_cell(policies: tuple[Policy, ...]) -> None:
    """Measured: a view owner under `USING (id = 1 OR true)`, or a permissive
    `true` with a no-op `true` floor, read every row; the door said COND."""
    t = _t(policies=policies, grants=(_grant("svc", ("SELECT",)),))
    v = _v("v", _OWN_T, owner="svc", grants=(_grant("anon", ("SELECT",)),))
    m = build_matrix(_s([t], [v], roles=[_r("anon"), _r("svc"), _r("own")]), roles=("anon",))
    assert _cell(m, "public.t", "SELECT", "anon").verdict == "open"


def test_truncate_ignores_rls() -> None:
    """Measured: TRUNCATE emptied a FORCE'd table whose DELETE admitted no row."""
    t = _t(force=True, grants=(_grant("app", ("DELETE", "TRUNCATE")),))
    m = build_matrix(_s([t], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "DELETE", "app").verdict == "denied"
    c = _cell(m, "public.t", "TRUNCATE", "app")
    assert c.verdict == "open" and c.note == "TRUNCATE is not subject to RLS"


def test_pg_write_all_data_does_not_confer_truncate() -> None:
    m = build_matrix(
        _s([_t(rls=False)], roles=[_r("etl"), _r("own")],
           memberships=[RoleMembership("etl", "pg_write_all_data", True)]),
        roles=("etl",),
    )
    assert _cell(m, "public.t", "DELETE", "etl").verdict == "open"
    assert _cell(m, "public.t", "TRUNCATE", "etl").verdict == "denied"


def test_the_data_role_itself_holds_its_privilege() -> None:
    m = build_matrix(_s([_t(rls=False)], roles=[_r("own")]), roles=("pg_read_all_data",))
    assert _cell(m, "public.t", "SELECT", "pg_read_all_data").verdict == "open"


def test_default_columns_are_the_roles_that_reach_something() -> None:
    """With the role catalogue, a role that reaches data only through a group
    still gets a column, one that reaches nothing does not, and anon /
    authenticated appear only when they exist."""
    t = _t(rls=False, grants=(_grant("grp", ("SELECT",)),))
    m = build_matrix(_s(
        [t], roles=[_r("app"), Role("grp", False, False, False), _r("stranger"), _r("own")],
        memberships=[RoleMembership("app", "grp", True)],
    ))
    assert m.roles == ("PUBLIC", "app", "grp", "own")


def test_an_unbounded_door_outranks_a_known_filter() -> None:
    """A materialized view's rows cannot be bounded; a known COND must not mask it."""
    t = _t(grants=(_grant("anon", ("SELECT",)),),
           policies=(_policy(roles=("anon",), using="id = 1"),))
    mv = _v("mv", _OWN_T, owner="own", mat=True, grants=(_grant("anon", ("SELECT",)),))
    m = build_matrix(_s([t], [mv], roles=[_r("anon"), _r("own")]), roles=("anon",))
    c = _cell(m, "public.t", "SELECT", "anon")
    assert c.verdict == "undecided" and "materialized view" in (c.note or "")


def test_a_hop_the_owner_cannot_use_is_a_dead_path() -> None:
    """Measured: `permission denied for view inner` — no rows."""
    inner = _v("inner", _OWN_T, owner="root")
    outer = _v("outer", _OWN_T, owner="app_owner", grants=(_grant("anon", ("SELECT",)),),
               direct=(("public", "inner"),))
    m = build_matrix(_s([_t()], [inner, outer],
                        roles=[_r("anon"), _r("app_owner"), _r("root", su=True), _r("own")]),
                     roles=("anon",))
    assert _cell(m, "public.t", "SELECT", "anon").verdict == "denied"


def test_a_materialized_view_hop_is_undecided() -> None:
    mv = _v("mv", _OWN_T, owner="own", mat=True)
    outer = _v("outer", _OWN_T, owner="own", grants=(_grant("anon", ("SELECT",)),),
               direct=(("public", "mv"),))
    m = build_matrix(_s([_t()], [mv, outer], roles=[_r("anon"), _r("own")]), roles=("anon",))
    assert _cell(m, "public.t", "SELECT", "anon").verdict == "undecided"


def test_a_hop_undecidable_without_the_graph_is_undecided() -> None:
    inner = _v("inner", _OWN_T, owner="root", grants=(_grant("grp", ("SELECT",)),))
    outer = _v("outer", _OWN_T, owner="x", grants=(_grant("PUBLIC", ("SELECT",)),),
               direct=(("public", "inner"),))
    s = Schema(tables=(_t(),), views=(inner, outer), roles=(_r("root", su=True), _r("x")),
               role_memberships=None)
    m = build_matrix(s, roles=("PUBLIC",))
    assert _cell(m, "public.t", "SELECT", "PUBLIC").verdict == "undecided"


def test_column_grants_confer_update_but_never_delete() -> None:
    """Postgres has no column-level DELETE, so a column grant listing it can
    only come from a hand-edited snapshot — and must still not confer it."""
    t = _t(rls=False, column_grants=(ColumnGrant(role="app", column="id",
                                                 privileges=("UPDATE", "INSERT", "DELETE")),))
    m = build_matrix(_s([t], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "UPDATE", "app").verdict == "open"
    assert _cell(m, "public.t", "INSERT", "app").verdict == "open"
    assert _cell(m, "public.t", "DELETE", "app").verdict == "denied"


def test_untraced_doors_are_listed_in_every_format() -> None:
    f = _f("BEGIN RETURN; END", owner="svc", lang="plpgsql")  # no definition captured
    m = build_matrix(_s([_t()], fns=[f], roles=[_r("svc"), _r("own")]), roles=("PUBLIC",))
    why = "the PL/pgSQL definition was not captured"
    assert m.untraced == (Untraced("public.f", "svc", why, "EXECUTE: PUBLIC, owner svc"),)
    assert "not traced" in render_text(m)
    assert json.loads(render_json(m))["untraced_doors"] == [{
        "door": "public.f", "owner": "svc", "reached_by": "EXECUTE: PUBLIC, owner svc",
        "reason": why,
    }]
    assert "## Doors not traced" in render_markdown(m)
    assert "public.f" in render_html(m, generated_at=_FIXED_AT)
    quiet = build_matrix(_s([_t()], roles=[_r("own")]), roles=("PUBLIC",))
    assert json.loads(render_json(quiet))["untraced_doors"] == []
    assert "not traced" not in render_text(quiet)


def test_text_output_puts_the_grid_first() -> None:
    t = _t(rls=False, grants=(_grant("app", ("SELECT",)),))
    out = render_text(build_matrix(_s([t], roles=[_r("app"), _r("own")]), roles=("app",)))
    assert out.startswith("TABLE")
    assert out.index("Sensitive columns reachable") > out.index("public.t")


def test_a_data_role_is_named_plainly_in_exposures() -> None:
    m = build_matrix(
        _s([_t(rls=False)], roles=[_r("analyst"), _r("own")],
           memberships=[RoleMembership("analyst", "pg_read_all_data", True)]),
        roles=("analyst",),
    )
    assert {e.via for e in m.exposures} == {"pg_read_all_data"}


# --- review iteration 2: triggers, rules, foreign keys, tracing limits --------

from pgrls.model import ForeignKey, RewriteRule, Trigger  # noqa: E402


def _trg(fn: str, event: str = "INSERT", *, row: bool | None = True, name: str = "tr") -> Trigger:
    schema, _, fname = fn.partition(".")
    return Trigger(name=name, function_schema=schema, function_name=fname, event=event,
                   timing="AFTER", enabled=True, row=row)


def _tf(body: str, *, owner: str = "own", name: str = "public.trgfn",
        execute: tuple[str, ...] = ("PUBLIC",)) -> SecdefFunction:
    return SecdefFunction(qualified_name=name, body=body, language="sql", owner=owner,
                          execute_roles=execute, trigger=True)


def _with(table: Table, **changes: object) -> Table:
    from dataclasses import replace  # noqa: PLC0415

    return replace(table, **changes)


def test_a_security_definer_trigger_fires_for_whoever_writes_its_table() -> None:
    """Measured: a role holding only INSERT on `inbox` emptied a FORCE'd
    `secrets` through an AFTER INSERT trigger whose function it could not
    EXECUTE."""
    secrets = _t("secrets", force=False)
    inbox = _t("inbox", rls=False, grants=(_grant("app", ("INSERT",)),),
               )
    inbox = _with(inbox, triggers=(_trg("public.trgfn"),))
    fn = _tf("DELETE FROM public.secrets", execute=())
    m = build_matrix(_s([secrets, inbox], fns=[fn], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    c = _cell(m, "public.secrets", "DELETE", "app")
    assert c.verdict == "open" and "trigger tr on public.inbox" in (c.note or "")


def test_a_trigger_function_is_not_a_door_through_execute() -> None:
    """Measured: `trigger functions can only be called as triggers` — PUBLIC
    EXECUTE on one opens nothing to a role that cannot write its table."""
    secrets = _t("secrets")
    inbox = _with(_t("inbox", rls=False), triggers=(_trg("public.trgfn"),))
    fn = _tf("DELETE FROM public.secrets", execute=("PUBLIC",))
    m = build_matrix(_s([secrets, inbox], fns=[fn], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "denied"


@pytest.mark.parametrize(("row", "fires"), [(False, True), (True, False)])
def test_a_statement_trigger_fires_even_when_rls_admits_no_row(row: bool, fires: bool) -> None:
    secrets = _t("secrets")
    inbox = _with(_t("inbox", force=True, grants=(_grant("app", ("DELETE",)),)),
                  triggers=(_trg("public.trgfn", "DELETE", row=row),))
    fn = _tf("DELETE FROM public.secrets")
    m = build_matrix(_s([secrets, inbox], fns=[fn], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert (_cell(m, "public.secrets", "DELETE", "app").verdict == "open") is fires


def test_a_partition_fires_its_parents_triggers() -> None:
    """A trigger on a partitioned table is cloned to every partition."""
    secrets = _t("secrets")
    parent = _with(_t("p", rls=False), triggers=(_trg("public.trgfn"),))
    child = _t("p_a", rls=False, partition_of=("public", "p"),
               grants=(_grant("app", ("INSERT",)),))
    fn = _tf("DELETE FROM public.secrets")
    m = build_matrix(_s([secrets, parent, child], fns=[fn], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "open"


def test_a_trigger_can_fire_another() -> None:
    """A trigger's write fires the next table's trigger: a fixed point."""
    secrets = _t("secrets")
    mid = _with(_t("mid"), triggers=(_trg("public.second"),))
    inbox = _with(_t("inbox", rls=False, grants=(_grant("app", ("INSERT",)),)),
                  triggers=(_trg("public.first"),))
    first = _tf("INSERT INTO public.mid (id) VALUES (1)", name="public.first")
    second = _tf("DELETE FROM public.secrets", name="public.second")
    m = build_matrix(_s([secrets, mid, inbox], fns=[first, second],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "open"


@pytest.mark.parametrize(("on_delete", "on_update", "undecided"), [
    ("CASCADE", "NO ACTION", {"DELETE"}),
    ("SET NULL", "NO ACTION", {"UPDATE"}),
    ("NO ACTION", "CASCADE", {"UPDATE"}),
    ("NO ACTION", "NO ACTION", set()),
])
def test_a_foreign_key_action_rewrites_the_referencing_rows(
    on_delete: str, on_update: str, undecided: set[str]
) -> None:
    """Measured: a DELETE on `accounts` emptied a FORCE'd `ledger` the role
    could not touch; an UPDATE re-pointed its rows. Which rows depends on the
    data, so it is UNDECIDED."""
    accounts = _t("accounts", rls=False, grants=(_grant("app", ("DELETE", "UPDATE")),))
    ledger = _t("ledger", force=True)
    ledger = _with(ledger, foreign_keys=(ForeignKey(
        "ledger_acct", ("acct",), "public", "accounts", ("id",), on_delete, on_update),))
    m = build_matrix(_s([accounts, ledger], roles=[_r("app"), _r("own")]), roles=("app",))
    got = {c for c in ("DELETE", "UPDATE")
           if _cell(m, "public.ledger", c, "app").verdict == "undecided"}
    assert got == undecided


def test_a_cascade_needs_a_role_that_can_touch_the_parent() -> None:
    accounts = _t("accounts", force=True)  # the role reaches no row of it
    ledger = _with(_t("ledger", force=True), foreign_keys=(ForeignKey(
        "fk", ("acct",), "public", "accounts", ("id",), "CASCADE", "NO ACTION"),))
    m = build_matrix(_s([accounts, ledger], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.ledger", "DELETE", "app").verdict == "denied"


def _rule(relation: str, command: str, action: str, *, instead: bool = False) -> RewriteRule:
    kind = "INSTEAD" if instead else "ALSO"
    return RewriteRule(
        "public", relation, f"r_{relation}", command, instead,
        f"CREATE RULE r_{relation} AS ON {command} TO public.{relation} DO {kind} {action};",
    )


def test_a_rule_runs_its_actions_as_the_relations_owner() -> None:
    """Measured: `ON INSERT TO requests DO ALSO DELETE FROM archive` emptied a
    FORCE'd `archive` the inserting role could not touch."""
    archive = _t("archive", force=False)
    requests = _t("requests", rls=False, grants=(_grant("app", ("INSERT",)),))
    s = Schema(tables=(archive, requests), roles=(_r("app"), _r("own")), role_memberships=(),
               rules=(_rule("requests", "INSERT", "DELETE FROM public.archive"),))
    c = _cell(build_matrix(s, roles=("app",)), "public.archive", "DELETE", "app")
    assert c.verdict == "open" and "rule r_requests on public.requests" in (c.note or "")


def test_an_instead_rule_replaces_a_views_own_write() -> None:
    """A view writable only through an INSTEAD rule does not auto-update its
    base: the rule's actions are what runs."""
    shown = _t("shown", force=False)
    hidden = _t("hidden", force=False)
    v = _v("v", (("public", "shown"),), owner="own", grants=(_grant("app", ("INSERT",)),))
    s = Schema(tables=(shown, hidden), views=(v,), roles=(_r("app"), _r("own")),
               role_memberships=(),
               rules=(_rule("v", "INSERT", "DELETE FROM public.hidden", instead=True),))
    m = build_matrix(s, roles=("app",))
    assert _cell(m, "public.shown", "INSERT", "app").verdict == "denied"
    assert _cell(m, "public.hidden", "DELETE", "app").verdict == "open"


@pytest.mark.parametrize(("body", "why"), [
    ("DO $x$ BEGIN DELETE FROM public.t; END $x$", "DoStmt"),
    ("SET search_path = b", "search_path"),
    ("CALL public.p()", "CallStmt"),
    ("SELECT pg_catalog.query_to_xml('SELECT * FROM public.t', true, false, '')",
     "does not see into"),
    ("SELECT pg_catalog.table_to_xml('public.t'::regclass, true, false, '')",
     "does not see into"),
    ("SELECT public.helper()", "does not see into"),
    ("WITH t AS (SELECT 1) SELECT * FROM t", "CTE shadows"),
])
def test_what_the_tracer_does_not_follow_is_listed(body: str, why: str) -> None:
    """Measured: a `DO` block and `pg_catalog.query_to_xml` / `table_to_xml` in
    a SECURITY DEFINER body each reached a FORCE'd table while the matrix said
    DENIED and listed nothing."""
    m = build_matrix(_s([_t()], fns=[_f(body, owner="own")], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert any(why in u.reason for u in m.untraced), m.untraced


@pytest.mark.parametrize("call", ["set_config", "pg_catalog.set_config"])
def test_setting_an_ordinary_guc_is_harmless(call: str) -> None:
    body = f"SELECT {call}('app.tenant', 'a', true); SELECT * FROM public.t"
    m = build_matrix(_s([_t()], fns=[_f(body, owner="own")], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert _cell(m, "public.t", "SELECT", "app").verdict == "open"
    assert m.untraced == ()


@pytest.mark.parametrize("statement", [
    "FOR r IN EXECUTE 'SELECT 1' LOOP END LOOP;",
    "RETURN QUERY EXECUTE 'SELECT 1';",
    "OPEN c FOR EXECUTE 'SELECT 1';",
])
def test_every_form_of_dynamic_sql_is_listed(statement: str) -> None:
    body = f"""CREATE FUNCTION public.f() RETURNS SETOF record LANGUAGE plpgsql
 SECURITY DEFINER AS $x$ DECLARE r record; c refcursor; BEGIN {statement} END $x$"""
    f = _f("<body>", owner="own", lang="plpgsql", definition=body)
    m = build_matrix(_s([_t()], fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert any("dynamic SQL" in u.reason for u in m.untraced), m.untraced


def test_an_unparseable_plpgsql_statement_is_listed() -> None:
    body = """CREATE FUNCTION public.f() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $x$
BEGIN PERFORM 1 FROM public.t; x := ((; END $x$"""
    f = _f("<body>", owner="own", lang="plpgsql", definition=body)
    m = build_matrix(_s([_t()], fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert any("does not parse" in u.reason for u in m.untraced), m.untraced


def test_another_language_is_listed() -> None:
    m = build_matrix(_s([_t()], fns=[_f("x", owner="own", lang="plpython3u")],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert [u.reason for u in m.untraced] == ["a plpython3u body cannot be read"]


def test_a_body_too_deep_to_walk_is_listed_not_a_crash() -> None:
    """Measured: a 1200-term expression crashed `pgrls matrix`."""
    body = "SELECT " + " || ".join(["note"] * 3000) + " FROM public.t"
    m = build_matrix(_s([_t()], fns=[_f(body, owner="own")], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert any("too deeply" in u.reason or "does not parse" in u.reason for u in m.untraced)


def test_merge_opens_every_write_it_can_run() -> None:
    body = ("MERGE INTO public.t USING (SELECT 1 AS id) s ON t.id = s.id "
            "WHEN MATCHED THEN DELETE WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)")
    m = build_matrix(_s([_t()], fns=[_f(body, owner="own")], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert {c for c in _ALL5 if _cell(m, "public.t", c, "app").verdict == "open"} == \
        {"SELECT", "INSERT", "UPDATE", "DELETE"}


def test_on_conflict_do_nothing_is_not_an_update() -> None:
    body = "INSERT INTO public.t (id) VALUES (1) ON CONFLICT DO NOTHING"
    m = build_matrix(_s([_t()], fns=[_f(body, owner="own")], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert _cell(m, "public.t", "UPDATE", "app").verdict == "denied"


def test_a_sql_standard_return_body_is_traced() -> None:
    """Measured: listed as unparseable while it returned every row."""
    body = "RETURN (SELECT count(*) AS count FROM public.t)"
    m = build_matrix(_s([_t()], fns=[_f(body, owner="own")], roles=[_r("app"), _r("own")]),
                     roles=("app",))
    assert _cell(m, "public.t", "SELECT", "app").verdict == "open" and m.untraced == ()


def test_every_schema_on_the_path_with_the_name_is_credited() -> None:
    """Postgres skips a schema the owner lacks USAGE on, so the first match is
    not necessarily the one that wins (measured: `b.t` was read)."""
    tables = [_t(schema="a"), _t(schema="b")]
    f = _f("SELECT * FROM t", owner="own", search_path="a, b")
    m = build_matrix(_s(tables, fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert {q for q in ("a.t", "b.t") if _cell(m, q, "SELECT", "app").verdict == "open"} == \
        {"a.t", "b.t"}


def test_user_on_the_search_path_is_the_function_owner() -> None:
    tables = [_t(schema="own"), _t(schema="app")]
    f = _f("SELECT * FROM t", owner="own", search_path='"$user", public')
    m = build_matrix(_s(tables, fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "own.t", "SELECT", "app").verdict == "open"
    assert _cell(m, "app.t", "SELECT", "app").verdict == "denied"


def test_truncate_of_a_referenced_table_needs_truncate_on_the_referencing_one() -> None:
    parent = _t("parent", rls=False, grants=(_grant("app", ("TRUNCATE",)),))
    child = _with(_t("child", rls=False), foreign_keys=(ForeignKey(
        "fk", ("pid",), "public", "parent", ("id",), "NO ACTION", "NO ACTION"),))
    m = build_matrix(_s([parent, child], roles=[_r("app"), _r("own")]), roles=("app",))
    c = _cell(m, "public.parent", "TRUNCATE", "app")
    assert c.verdict == "denied" and "public.child" in (c.note or "")
    both = _with(child, grants=(_grant("app", ("TRUNCATE",)),))
    m = build_matrix(_s([parent, both], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.parent", "TRUNCATE", "app").verdict == "open"


def test_a_filter_from_a_function_and_the_same_text_elsewhere_is_undecided() -> None:
    """Measured: `owner_name = current_user` through a SECURITY DEFINER function
    is the OWNER's rows, directly the caller's — not the same row set."""
    t = _t(grants=(_grant("app", ("SELECT",)), _grant("fowner", ("SELECT",))),
           policies=(_policy(roles=("PUBLIC",), using="owner_name = current_user"),))
    f = _f("SELECT * FROM public.t", owner="fowner")
    m = build_matrix(_s([t], fns=[f], roles=[_r("app"), _r("fowner"), _r("own")]),
                     roles=("app",))
    assert _cell(m, "public.t", "SELECT", "app").verdict == "undecided"


def test_the_same_filter_twice_keeps_both_notes() -> None:
    parent = _t("p", policies=(_TENANT_A,), grants=(_grant("app", ("SELECT",)),))
    child = _t("p_a", policies=(_TENANT_A,), grants=(_grant("app", ("SELECT",)),),
               partition_of=("public", "p"))
    m = build_matrix(_s([parent, child], roles=[_r("app"), _r("own")]), roles=("app",))
    c = _cell(m, "public.p_a", "SELECT", "app")
    assert c.verdict == "conditional" and "through parent public.p" in (c.note or "")


def test_a_nested_view_door_is_named_by_the_view_the_role_opened() -> None:
    """The note names the view the role holds a grant on, not only the inner
    definer view whose owner the rows are read as."""
    inner = _v("inner", _OWN_T, owner="own", grants=(_grant("x", ("SELECT",)),))
    outer = _v("outer", _OWN_T, owner="x", grants=(_grant("app", ("SELECT",)),),
               direct=(("public", "inner"),))
    m = build_matrix(_s([_t()], [inner, outer], roles=[_r("app"), _r("x"), _r("own")]),
                     roles=("app",))
    c = _cell(m, "public.t", "SELECT", "app")
    assert c.verdict == "open"
    assert "through view public.outer, then definer view public.inner" in (c.note or "")


def test_default_columns_are_the_roles_that_differ_from_public() -> None:
    """Measured: one PUBLIC-executable helper made every role in a Supabase
    cluster a column. A role that can do exactly what everyone can adds
    nothing; one with a door PUBLIC cannot open is shown."""
    t = _t(rls=False)
    helper = _f("SELECT * FROM public.t", owner="own")  # PUBLIC may EXECUTE
    private = SecdefFunction(qualified_name="public.p", body="SELECT x FROM y(", language="sql",
                             owner="own", execute_roles=("svc",))
    s = _s([t], fns=[helper, private], roles=[_r("bystander"), _r("svc"), _r("own")])
    m = build_matrix(s)
    assert "bystander" not in m.roles and "svc" in m.roles
    [u] = [u for u in m.untraced if u.door == "public.p"]
    assert u.reached_by == "EXECUTE: svc, owner own"


def test_a_parent_outside_the_grid_is_still_a_door() -> None:
    """Measured: a partitioned `api.events` handed its partition's rows to a
    role a `--schemas public` matrix said was DENIED."""
    parent = _t("events", schema="api", rls=False, grants=(_grant("app", ("SELECT",)),))
    child = _t("events_a", force=True, partition_of=("api", "events"))
    m = build_matrix(_s([parent, child], roles=[_r("app"), _r("own")]), roles=("app",),
                     grid=frozenset({"public.events_a"}))
    assert [r.qualified_name for r in m.rows] == ["public.events_a"] * 5
    assert _cell(m, "public.events_a", "SELECT", "app").verdict == "open"


def test_configured_sensitive_patterns_extend_the_defaults() -> None:
    t = Table(schema="public", name="patients", rls_enabled=False, force_rls=False,
              policies=(), owner="own", columns=("id", "mrn"),
              grants=(_grant("app", ("SELECT",)),))
    s = _s([t], roles=[_r("app"), _r("own")])
    assert build_matrix(s, roles=("app",)).exposures == ()
    got = build_matrix(s, roles=("app",), sensitive_patterns=frozenset({"mrn"}))
    assert [(e.table, e.column) for e in got.exposures] == [("public.patients", "mrn")]


def test_updatable_bits_decode_to_commands() -> None:
    from pgrls.introspect import _updatable_commands  # noqa: PLC0415

    assert _updatable_commands(8) == ("INSERT",)
    assert _updatable_commands(4) == ("UPDATE",)
    assert _updatable_commands(16) == ("DELETE",)
    assert _updatable_commands(28) == ("INSERT", "UPDATE", "DELETE")
    assert _updatable_commands(None) == ()


# --- review iteration 3: what fires a trigger or rule, run-time settings -------


def _btrg(fn: str, event: str, *, timing: str = "AFTER", row: bool | None = True,
          name: str = "tr", enabled: bool = True) -> Trigger:
    schema, _, fname = fn.partition(".")
    return Trigger(name=name, function_schema=schema, function_name=fname, event=event,
                   timing=timing, enabled=enabled, row=row)


@pytest.mark.parametrize(("timing", "fires"), [("BEFORE", True), ("AFTER", False)])
def test_a_before_row_insert_trigger_fires_even_when_rls_refuses_the_row(
    timing: str, fires: bool
) -> None:
    """Measured: a BEFORE INSERT row trigger ran — and, returning NULL, its
    writes stood — although RLS refused the INSERT itself. An AFTER trigger
    never sees a refused row."""
    secrets = _t("secrets")
    inbox = _with(_t("inbox", force=True, grants=(_grant("app", ("INSERT",)),),
                     policies=(_policy(command="SELECT", roles=("PUBLIC",), using="true"),)),
                  triggers=(_btrg("public.trgfn", "INSERT", timing=timing),))
    m = build_matrix(_s([secrets, inbox], fns=[_tf("DELETE FROM public.secrets")],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert (_cell(m, "public.secrets", "DELETE", "app").verdict == "open") is fires


def test_a_statement_trigger_fires_through_a_door_that_reaches_no_row() -> None:
    """A SECURITY DEFINER function's DELETE on a table whose RLS admits its
    owner no row still fires that table's statement trigger."""
    secrets = _t("secrets")
    queue = _with(_t("queue", owner="fo", force=True),
                  triggers=(_btrg("public.trgfn", "DELETE", row=False),))
    f = _f("DELETE FROM public.queue", owner="fo")
    m = build_matrix(_s([secrets, queue], fns=[f, _tf("DELETE FROM public.secrets")],
                        roles=[_r("app"), _r("fo"), _r("own")]), roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "open"


def test_a_row_moving_update_fires_the_destinations_insert_trigger() -> None:
    secrets = _t("secrets")
    parent = _t("p", rls=False, grants=(_grant("app", ("UPDATE",)),))
    dest = _with(_t("p_b", rls=False, partition_of=("public", "p")),
                 triggers=(_btrg("public.trgfn", "INSERT"),))
    m = build_matrix(_s([secrets, parent, dest], fns=[_tf("DELETE FROM public.secrets")],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "open"


@pytest.mark.parametrize("enabled", [True, False])
def test_a_disabled_trigger_is_no_door(enabled: bool) -> None:
    secrets = _t("secrets")
    inbox = _with(_t("inbox", rls=False, grants=(_grant("app", ("INSERT",)),)),
                  triggers=(_btrg("public.trgfn", "INSERT", enabled=enabled),))
    m = build_matrix(_s([secrets, inbox], fns=[_tf("DELETE FROM public.secrets")],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert (_cell(m, "public.secrets", "DELETE", "app").verdict == "open") is enabled


def test_a_trigger_of_unknown_level_fires_on_the_privilege() -> None:
    """Pre-v27 snapshots carry no level; the wider reading is the safe one."""
    secrets = _t("secrets")
    inbox = _with(_t("inbox", force=True, grants=(_grant("app", ("DELETE",)),)),
                  triggers=(_btrg("public.trgfn", "DELETE", row=None),))
    m = build_matrix(_s([secrets, inbox], fns=[_tf("DELETE FROM public.secrets")],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "open"


def test_a_rule_fires_for_a_door_that_writes_its_relation() -> None:
    """Measured: a SECURITY DEFINER function inserting into `requests` emptied
    `archive` through the rule, for a caller with no privilege on either. The
    rule's actions run as `requests`' owner, who owns `archive` too."""
    archive = _t("archive")
    requests = _t("requests", rls=False, grants=(_grant("fo", ("INSERT",)),))
    f = _f("INSERT INTO public.requests (id) VALUES (1)", owner="fo")
    s = Schema(tables=(archive, requests), security_definer_functions=(f,),
               roles=(_r("app"), _r("fo"), _r("own")), role_memberships=(),
               rules=(_rule("requests", "INSERT", "DELETE FROM public.archive"),))
    c = _cell(build_matrix(s, roles=("app",)), "public.archive", "DELETE", "app")
    assert c.verdict == "open" and "rule r_requests on public.requests" in (c.note or "")


def test_a_long_trigger_chain_reaches_its_end() -> None:
    """Measured: a chain one step longer than the table count stopped short.
    The loop runs until nothing changes."""
    a, b, secrets = _t("a", rls=False, grants=(_grant("app", ("INSERT",)),)), _t("b"), _t("secrets")
    a = _with(a, triggers=(_btrg("public.f1", "INSERT", name="t1"),
                           _btrg("public.f3", "UPDATE", name="t3"),
                           _btrg("public.f5", "DELETE", name="t5")))
    b = _with(b, triggers=(_btrg("public.f2", "INSERT", name="t2"),
                           _btrg("public.f4", "UPDATE", name="t4"),
                           _btrg("public.f6", "DELETE", name="t6")))
    fns = [
        _tf("INSERT INTO public.b (id) VALUES (1)", name="public.f1"),
        _tf("UPDATE public.a SET note = 'x'", name="public.f2"),
        _tf("UPDATE public.b SET note = 'x'", name="public.f3"),
        _tf("DELETE FROM public.a", name="public.f4"),
        _tf("DELETE FROM public.b", name="public.f5"),
        _tf("DELETE FROM public.secrets", name="public.f6"),
    ]
    m = build_matrix(_s([a, b, secrets], fns=fns, roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "open"


def test_truncate_cascade_in_a_body_empties_what_references_the_table() -> None:
    parent = _t("parent")
    child = _with(_t("child"), foreign_keys=(ForeignKey(
        "fk", ("pid",), "public", "parent", ("id",), "NO ACTION", "NO ACTION"),))
    f = _f("TRUNCATE public.parent CASCADE", owner="own")
    m = build_matrix(_s([parent, child], fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.child", "TRUNCATE", "app").verdict == "open"


def test_a_role_that_differs_only_in_a_sensitive_column_is_shown() -> None:
    """Measured: a column grant on `ssn` left every cell equal to PUBLIC's,
    and the role — and its exposure — were hidden."""
    t = Table(schema="public", name="people", rls_enabled=False, force_rls=False,
              policies=(), owner="own", columns=("id", "ssn"),
              grants=(_grant("PUBLIC", ("SELECT",)),),
              column_grants=(ColumnGrant(role="hr", column="ssn", privileges=("SELECT",)),))
    t = _with(t, grants=(), column_grants=(
        ColumnGrant(role="PUBLIC", column="id", privileges=("SELECT",)),
        ColumnGrant(role="hr", column="ssn", privileges=("SELECT",)),
    ))
    m = build_matrix(_s([t], roles=[_r("hr"), _r("own")]))
    assert "hr" in m.roles
    assert ("hr", "ssn") in {(e.role, e.column) for e in m.exposures}


@pytest.mark.parametrize("setter", [
    "SELECT set_config('app.tenant', 'b', true);",
    "SELECT pg_catalog.set_config('app.tenant', 'b', true);",
    "SET LOCAL app.tenant = 'b';",
])
def test_a_body_that_sets_a_parameter_has_unbounded_rows(setter: str) -> None:
    """Measured: setting the parameter a policy reads, then reading, returned
    another tenant's row. The owner's filter no longer bounds what it gets."""
    t = _t(policies=(_policy(roles=("PUBLIC",), using="tenant_id = current_setting('app.tenant', true)"),),
           grants=(_grant("fo", ("SELECT",)),), force=True)
    f = _f(f"{setter} SELECT * FROM public.t", owner="fo")
    m = build_matrix(_s([t], fns=[f], roles=[_r("app"), _r("fo"), _r("own")]), roles=("app",))
    c = _cell(m, "public.t", "SELECT", "app")
    assert c.verdict == "undecided" and "sets configuration parameters" in (c.note or "")
    assert m.untraced == ()


def test_a_function_set_clause_has_unbounded_rows() -> None:
    t = _t(policies=(_policy(roles=("PUBLIC",), using="tenant_id = current_setting('app.tenant', true)"),),
           grants=(_grant("fo", ("SELECT",)),), force=True)
    f = SecdefFunction(qualified_name="public.f", body="SELECT * FROM public.t", language="sql",
                       owner="fo", execute_roles=("PUBLIC",), config_gucs=("app.tenant",))
    m = build_matrix(_s([t], fns=[f], roles=[_r("app"), _r("fo"), _r("own")]), roles=("app",))
    assert _cell(m, "public.t", "SELECT", "app").verdict == "undecided"


@pytest.mark.parametrize("setter", [
    "SET search_path = b;", "SET ROLE other;", "SET SESSION AUTHORIZATION other;",
    "SELECT set_config('search_path', 'b', true);", "SELECT set_config('role', 'x', true);",
])
def test_changing_name_resolution_or_the_role_is_untraced(setter: str) -> None:
    f = _f(f"{setter} SELECT * FROM public.t", owner="own")
    m = build_matrix(_s([_t()], fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert any("search_path or the role" in u.reason for u in m.untraced), m.untraced


@pytest.mark.parametrize("call", [
    "pg_catalog.ts_rewrite('a'::tsquery, 'SELECT 1')",
    "pg_catalog.ts_stat('SELECT 1')",
])
def test_every_sql_running_builtin_is_untraced(call: str) -> None:
    f = _f(f"SELECT {call}", owner="own")
    m = build_matrix(_s([_t()], fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert any("does not see into" in u.reason for u in m.untraced), m.untraced


@pytest.mark.parametrize(("expr", "untraced"), [
    ("1 OPERATOR(public.===) 2", True),
    ("1 === 2", True),
    ("1 OPERATOR(pg_catalog.=) 1", False),
    ("'x' ->> 'y' = 'z'", False),
])
def test_a_user_operator_is_untraced(expr: str, untraced: bool) -> None:
    """Measured: an operator whose function deletes from a table emptied it
    from inside a SECURITY DEFINER body the tracer called clean."""
    f = _f(f"SELECT {expr}", owner="own")
    m = build_matrix(_s([_t()], fns=[f], roles=[_r("app"), _r("own")]), roles=("app",))
    assert bool(m.untraced) is untraced


def test_the_same_session_free_filter_through_a_function_stays_conditional() -> None:
    """A filter that does not read who is running it admits the same rows in
    the function's session as in the caller's."""
    pred = "tenant_id = current_setting('app.tenant', true)"
    t = _t(grants=(_grant("app", ("SELECT",)), _grant("fo", ("SELECT",))), force=True,
           policies=(_policy(roles=("PUBLIC",), using=pred),))
    f = _f("SELECT * FROM public.t", owner="fo")
    m = build_matrix(_s([t], fns=[f], roles=[_r("app"), _r("fo"), _r("own")]), roles=("app",))
    c = _cell(m, "public.t", "SELECT", "app")
    assert c.verdict == "conditional" and c.predicate == pred


@pytest.mark.parametrize(("predicate", "session", "relations"), [
    ("owner_name = current_user", True, False),
    ("owner_name = session_user", True, False),
    ("pg_has_role('admin', 'MEMBER')", True, False),
    ("has_table_privilege('t', 'SELECT')", True, False),
    ("public.is_admin()", True, True),
    ("1 OPERATOR(public.===) 2", True, True),
    ("tenant_id = current_setting('app.tenant', true)", False, False),
    ("tenant_id = auth.uid()", False, False),
    ("tenant_id = (SELECT auth.uid())", False, False),
    # Reading a relation implies session dependence: the relation's own RLS
    # may compare against current_user.
    ("tenant_id IN (SELECT tenant_id FROM memberships)", True, True),
    ("EXISTS (SELECT 1 FROM m WHERE m.member = current_user)", True, True),
    ("((((", True, True),
])
def test_what_a_filter_depends_on(predicate: str, session: bool, relations: bool) -> None:
    from pgrls.access import _dependence  # noqa: PLC0415

    assert _dependence(predicate) == (session, relations)


# --- filters that read another table; TRUNCATE and triggers through parents --

_SUBSELECT = "tenant_id IN (SELECT memberships.tenant_id FROM public.memberships)"


def _subselect_schema(door: str, predicate: str = _SUBSELECT, owner: str = "o") -> Schema:
    t = _t(grants=(_grant("r", ("SELECT",)), _grant("o", ("SELECT",))),
           policies=(_policy(roles=("PUBLIC",), using=predicate),))
    members = _t("memberships", owner="o",
                 grants=(_grant("r", ("SELECT",)),),
                 policies=(_policy(roles=("PUBLIC",), using="member = current_user"),))
    views = [_v("v", _OWN_T, owner=owner, grants=(_grant("r", ("SELECT",)),))] \
        if door == "view" else []
    fns = [_f("SELECT * FROM public.t", owner=owner, execute=("r",))] if door == "function" else []
    return _s([t, members], views, fns, roles=[_r("r"), _r("o"), _r("own")])


@pytest.mark.parametrize("door", ["view", "function"])
def test_a_filter_reading_another_table_differs_through_a_door(door: str) -> None:
    """Measured on PG15/16/17: `tenant_id IN (SELECT … FROM memberships)`
    read 1 row directly and 2 through a SECURITY DEFINER function or a definer
    view owned by `o` — the sub-select runs with the door owner's RLS, even
    where `current_user` stays the caller. One COND would hide the second."""
    m = build_matrix(_subselect_schema(door), roles=("r",))
    c = _cell(m, "public.t", "SELECT", "r")
    assert c.verdict == "undecided", c


@pytest.mark.parametrize("door", ["view", "function"])
def test_a_from_less_sub_select_is_the_same_filter_through_a_door(door: str) -> None:
    """`(SELECT auth.uid())` reads no table: the same rows for everyone."""
    m = build_matrix(_subselect_schema(door, "tenant_id = (SELECT auth.uid())"),
                     roles=("r",))
    assert _cell(m, "public.t", "SELECT", "r").verdict == "conditional"


def test_a_role_opening_its_own_door_reads_as_itself() -> None:
    """A function `r` owns runs as `r`: its `current_user` filter is the same
    row set as `r`'s own session, not a second one."""
    t = _t(grants=(_grant("r", ("SELECT",)),),
           policies=(_policy(roles=("PUBLIC",), using="owner_name = current_user"),))
    f = _f("SELECT * FROM public.t", owner="r", execute=("r",))
    m = build_matrix(_s([t], fns=[f], roles=[_r("r"), _r("own")]), roles=("r",))
    assert _cell(m, "public.t", "SELECT", "r").verdict == "conditional"


def test_a_view_and_a_function_of_one_owner_differ_on_current_user() -> None:
    """Through a definer view `current_user` is still the caller; inside a
    SECURITY DEFINER function it is the owner. Same owner, same text — two
    row sets."""
    t = _t(grants=(_grant("o", ("SELECT",)),),
           policies=(_policy(roles=("PUBLIC",), using="owner_name = current_user"),))
    v = _v("v", _OWN_T, owner="o", grants=(_grant("r", ("SELECT",)),))
    f = _f("SELECT * FROM public.t", owner="o", execute=("r",))
    m = build_matrix(_s([t], [v], [f], roles=[_r("r"), _r("o"), _r("own")]), roles=("r",))
    assert _cell(m, "public.t", "SELECT", "r").verdict == "undecided"


def _fk(to: str, name: str = "fk") -> ForeignKey:
    return ForeignKey(name, ("pid",), "public", to, ("id",), "NO ACTION", "NO ACTION")


def test_truncating_a_parent_covers_a_foreign_key_from_its_partition() -> None:
    """Measured: `TRUNCATE tree` emptied a self-referencing partitioned table
    granted on the parent alone — the partitions are emptied by the same
    statement, and their privilege is not checked."""
    tree = _with(_t("tree", rls=False, grants=(_grant("app", ("TRUNCATE",)),)),
                 foreign_keys=(_fk("tree"),))
    parts = [_with(_t(f"tree_{i}", rls=False, partition_of=("public", "tree")),
                   foreign_keys=(_fk("tree"),)) for i in (1, 2)]
    m = build_matrix(_s([tree, *parts], roles=[_r("app"), _r("own")]), roles=("app",))
    for table in ("public.tree", "public.tree_1", "public.tree_2"):
        assert _cell(m, table, "TRUNCATE", "app").verdict == "open", table


@pytest.mark.parametrize(("z_granted", "verdict"), [(True, "open"), (False, "denied")])
def test_truncating_a_parent_must_also_empty_what_references_its_partitions(
    z_granted: bool, verdict: str,
) -> None:
    """`TRUNCATE tree` empties partition `tree_1` too, so a table referencing
    `tree_1` must be emptied by the same statement."""
    tree = _t("tree", rls=False, grants=(_grant("app", ("TRUNCATE",)),))
    part = _t("tree_1", rls=False, partition_of=("public", "tree"))
    z = _with(_t("z", rls=False, grants=(_grant("app", ("TRUNCATE",)),) if z_granted else ()),
              foreign_keys=(_fk("tree_1"),))
    m = build_matrix(_s([tree, part, z], roles=[_r("app"), _r("own")]), roles=("app",))
    c = _cell(m, "public.tree", "TRUNCATE", "app")
    assert c.verdict == verdict, c
    if verdict == "denied":
        assert "public.z" in (c.note or "")


@pytest.mark.parametrize(("granted", "verdict"), [(("p", "q"), "open"), (("p",), "denied")])
def test_a_referencing_partition_is_covered_by_truncating_its_parent(
    granted: tuple[str, ...], verdict: str,
) -> None:
    """Measured: `TRUNCATE p, q` emptied `p` although the foreign key came
    from `q`'s partition `q1`, which had no grant of its own."""
    p = _t("p", rls=False, grants=tuple(_grant("app", ("TRUNCATE",)) for n in granted if n == "p"))
    q = _t("q", rls=False, grants=tuple(_grant("app", ("TRUNCATE",)) for n in granted if n == "q"))
    q1 = _with(_t("q1", rls=False, partition_of=("public", "q")), foreign_keys=(_fk("p"),))
    m = build_matrix(_s([p, q, q1], roles=[_r("app"), _r("own")]), roles=("app",))
    c = _cell(m, "public.p", "TRUNCATE", "app")
    assert c.verdict == verdict, c
    if verdict == "denied":
        assert "public.q1" in (c.note or "")


@pytest.mark.parametrize("declarative", [True, False])
def test_truncating_a_parent_fires_its_childs_truncate_trigger(declarative: bool) -> None:
    """Measured: `TRUNCATE pp` fired the TRUNCATE trigger of partition `pp1`,
    and the same for a classic inheritance child."""
    secrets = _t("secrets")
    parent = _t("pp", rls=False, grants=(_grant("app", ("TRUNCATE",)),))
    link = {"partition_of": ("public", "pp")} if declarative else {"inherits": (("public", "pp"),)}
    child = _with(_t("pp1", rls=False, **link),
                  triggers=(_btrg("public.trgfn", "TRUNCATE", row=False),))
    m = build_matrix(_s([secrets, parent, child], fns=[_tf("DELETE FROM public.secrets")],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert _cell(m, "public.secrets", "DELETE", "app").verdict == "open"


@pytest.mark.parametrize(("declarative", "fires"), [(True, True), (False, False)])
def test_an_insert_routed_from_a_parent_fires_the_partitions_before_trigger(
    declarative: bool, fires: bool,
) -> None:
    """Measured: `INSERT INTO ins` — RLS on, no policy — fired partition
    `ins1`'s BEFORE ROW INSERT trigger; returning NULL, the INSERT added no
    row and the trigger's DELETE stood. A classic inheritance parent keeps
    its rows, so its child's trigger does not fire."""
    secrets = _t("secrets")
    parent = _t("ins", force=True, grants=(_grant("app", ("INSERT",)),))
    link = {"partition_of": ("public", "ins")} if declarative \
        else {"inherits": (("public", "ins"),)}
    child = _with(_t("ins1", **link),
                  triggers=(_btrg("public.trgfn", "INSERT", timing="BEFORE"),))
    m = build_matrix(_s([secrets, parent, child], fns=[_tf("DELETE FROM public.secrets")],
                        roles=[_r("app"), _r("own")]), roles=("app",))
    assert (_cell(m, "public.secrets", "DELETE", "app").verdict == "open") is fires


# --- live differential: every cell against a real SET ROLE session ------------
#
# Each matrix claim is checked against Postgres itself: the command runs as the
# role (SET LOCAL ROLE) in a transaction that is rolled back, and its EFFECT on
# the table is measured as superuser before the rollback — rows returned, rows
# updated, rows left after DELETE / TRUNCATE, which of two INSERTs landed (one
# row a tenant predicate admits, one it rejects). Every door is measured the
# same way and the widest reach wins: definer and invoker views (reads and
# writes), SQL and PL/pgSQL SECURITY DEFINER functions (reads, a delete, one
# reached through the owner's membership), a view in another schema, and
# partition / inheritance parents. This is the test that caught policies
# applied through NOINHERIT edges and the doors review iteration 1 found
# missing. NOINHERIT comes from the role attribute so it runs on PG15 too.

_MXD_ROLES = (
    "mxd_pub", "mxd_grp", "mxd_mid", "mxd_inh", "mxd_noinh", "mxd_nested",
    "mxd_owner", "mxd_owner_m", "mxd_owner_m_noinh", "mxd_su", "mxd_byp",
    "mxd_byp_nogrant", "mxd_rad", "mxd_wad", "mxd_colr", "mxd_colw",
    "mxd_door_owner", "mxd_vowner", "mxd_vuser", "mxd_invuser", "mxd_fnuser",
    "mxd_svc", "mxd_svc_m", "mxd_or_owner", "mxd_vwuser", "mxd_partuser", "mxd_apiuser",
    "mxd_trguser", "mxd_fkuser", "mxd_ruleuser",
)

_MXD_DDL = """
CREATE ROLE mxd_pub NOLOGIN;
CREATE ROLE mxd_grp NOLOGIN;
CREATE ROLE mxd_mid NOLOGIN;
CREATE ROLE mxd_inh NOLOGIN;
CREATE ROLE mxd_noinh NOLOGIN NOINHERIT;
CREATE ROLE mxd_nested NOLOGIN;
CREATE ROLE mxd_owner NOLOGIN;
CREATE ROLE mxd_owner_m NOLOGIN;
CREATE ROLE mxd_owner_m_noinh NOLOGIN NOINHERIT;
CREATE ROLE mxd_su NOLOGIN SUPERUSER;
CREATE ROLE mxd_byp NOLOGIN BYPASSRLS;
CREATE ROLE mxd_byp_nogrant NOLOGIN BYPASSRLS;
CREATE ROLE mxd_rad NOLOGIN;
CREATE ROLE mxd_wad NOLOGIN;
CREATE ROLE mxd_colr NOLOGIN;
CREATE ROLE mxd_colw NOLOGIN;
CREATE ROLE mxd_door_owner NOLOGIN;
CREATE ROLE mxd_vowner NOLOGIN;
CREATE ROLE mxd_vuser NOLOGIN;
CREATE ROLE mxd_invuser NOLOGIN;
CREATE ROLE mxd_fnuser NOLOGIN;
CREATE ROLE mxd_svc NOLOGIN BYPASSRLS;
CREATE ROLE mxd_svc_m NOLOGIN;
CREATE ROLE mxd_or_owner NOLOGIN;
CREATE ROLE mxd_vwuser NOLOGIN;
CREATE ROLE mxd_partuser NOLOGIN;
CREATE ROLE mxd_apiuser NOLOGIN;
CREATE ROLE mxd_trguser NOLOGIN;
CREATE ROLE mxd_fkuser NOLOGIN;
CREATE ROLE mxd_ruleuser NOLOGIN;
GRANT mxd_grp TO mxd_inh, mxd_noinh, mxd_mid;
GRANT mxd_mid TO mxd_nested;
GRANT mxd_owner TO mxd_owner_m, mxd_owner_m_noinh;
GRANT mxd_svc TO mxd_svc_m;
GRANT pg_read_all_data TO mxd_rad;
GRANT pg_write_all_data TO mxd_wad;

CREATE FUNCTION pg_temp.mk(t text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE format('CREATE TABLE public.%I (id int, tenant_id text, owner_name text,'
                 ' note text, email text, ssn text)', t);
  EXECUTE format($q$INSERT INTO public.%I VALUES
    (1, 'a', 'x', 'n1', 'a1@x', '111'), (2, 'a', 'x', 'n2', 'a2@x', '222'),
    (3, 'b', 'x', 'n3', 'b1@x', '333'), (4, 'b', 'x', 'n4', 'b2@x', '444')$q$, t);
END $$;

SELECT pg_temp.mk('t_open');
GRANT SELECT, TRUNCATE ON t_open TO mxd_grp;

SELECT pg_temp.mk('t_grp_policy');
ALTER TABLE t_grp_policy ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON t_grp_policy TO mxd_grp, mxd_noinh;
CREATE POLICY p_grp ON t_grp_policy FOR ALL TO mxd_grp USING (true);

SELECT pg_temp.mk('t_grp_floor');
ALTER TABLE t_grp_floor ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON t_grp_floor TO mxd_grp, mxd_noinh;
CREATE POLICY p_all ON t_grp_floor FOR ALL TO PUBLIC USING (true);
CREATE POLICY r_grp ON t_grp_floor AS RESTRICTIVE FOR ALL TO mxd_grp
  USING (tenant_id = current_setting('app.tenant', true));

SELECT pg_temp.mk('t_owned');
ALTER TABLE t_owned OWNER TO mxd_owner;
ALTER TABLE t_owned ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON t_owned TO mxd_owner_m_noinh;

SELECT pg_temp.mk('t_forced');
ALTER TABLE t_forced OWNER TO mxd_owner;
ALTER TABLE t_forced ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_forced FORCE ROW LEVEL SECURITY;
CREATE POLICY p_t ON t_forced FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.tenant', true));

SELECT pg_temp.mk('t_cols');
GRANT SELECT (id, email) ON t_cols TO mxd_colr;
GRANT UPDATE (note) ON t_cols TO mxd_colw;
GRANT INSERT (id, tenant_id, owner_name) ON t_cols TO mxd_colw;

SELECT pg_temp.mk('t_all_data');
ALTER TABLE t_all_data ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_ad ON t_all_data FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.tenant', true));

SELECT pg_temp.mk('t_bypass');
ALTER TABLE t_bypass ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_bypass FORCE ROW LEVEL SECURITY;
GRANT SELECT, TRUNCATE ON t_bypass TO mxd_byp;

SELECT pg_temp.mk('t_door');
ALTER TABLE t_door OWNER TO mxd_door_owner;
ALTER TABLE t_door ENABLE ROW LEVEL SECURITY;
CREATE VIEW v_def AS SELECT * FROM public.t_door;
ALTER VIEW v_def OWNER TO mxd_door_owner;
GRANT SELECT ON v_def TO mxd_vuser;
CREATE VIEW v_inv WITH (security_invoker = true) AS SELECT * FROM public.t_door;
ALTER VIEW v_inv OWNER TO mxd_door_owner;
GRANT SELECT ON v_inv TO mxd_invuser;
CREATE FUNCTION f_door() RETURNS SETOF public.t_door LANGUAGE sql SECURITY DEFINER
  AS 'SELECT * FROM public.t_door';
ALTER FUNCTION f_door() OWNER TO mxd_door_owner;
REVOKE EXECUTE ON FUNCTION f_door() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION f_door() TO mxd_fnuser;

SELECT pg_temp.mk('t_door_filtered');
ALTER TABLE t_door_filtered ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_v ON t_door_filtered FOR SELECT TO mxd_vowner
  USING (tenant_id = current_setting('app.tenant', true));
GRANT SELECT ON t_door_filtered TO mxd_vowner;
CREATE VIEW v_def2 AS SELECT * FROM public.t_door_filtered;
ALTER VIEW v_def2 OWNER TO mxd_vowner;
GRANT SELECT ON v_def2 TO mxd_vuser;

SELECT pg_temp.mk('t_fn_pub');
ALTER TABLE t_fn_pub OWNER TO mxd_door_owner;
ALTER TABLE t_fn_pub ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION f_pub() RETURNS SETOF public.t_fn_pub LANGUAGE sql SECURITY DEFINER
  AS 'SELECT * FROM public.t_fn_pub';
ALTER FUNCTION f_pub() OWNER TO mxd_door_owner;

SELECT pg_temp.mk('t_plpg');
ALTER TABLE t_plpg OWNER TO mxd_door_owner;
ALTER TABLE t_plpg ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION f_plpg() RETURNS SETOF public.t_plpg LANGUAGE plpgsql SECURITY DEFINER
  AS 'BEGIN RETURN QUERY SELECT * FROM public.t_plpg; END';
ALTER FUNCTION f_plpg() OWNER TO mxd_door_owner;

SELECT pg_temp.mk('t_wipe');
ALTER TABLE t_wipe OWNER TO mxd_door_owner;
ALTER TABLE t_wipe ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION f_wipe() RETURNS void LANGUAGE sql SECURITY DEFINER
  AS 'DELETE FROM public.t_wipe';
ALTER FUNCTION f_wipe() OWNER TO mxd_door_owner;
REVOKE EXECUTE ON FUNCTION f_wipe() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION f_wipe() TO mxd_fnuser;

SELECT pg_temp.mk('t_svc');
ALTER TABLE t_svc ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_svc ON t_svc FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.tenant', true));
GRANT SELECT ON t_svc TO mxd_svc;
CREATE FUNCTION f_svc() RETURNS SETOF public.t_svc LANGUAGE sql SECURITY DEFINER
  AS 'SELECT * FROM public.t_svc';
ALTER FUNCTION f_svc() OWNER TO mxd_svc;
REVOKE EXECUTE ON FUNCTION f_svc() FROM PUBLIC;

SELECT pg_temp.mk('t_ortrue');
ALTER TABLE t_ortrue ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_or ON t_ortrue FOR SELECT TO mxd_or_owner USING (id = 1 OR true);
GRANT SELECT ON t_ortrue TO mxd_or_owner;
CREATE VIEW v_or AS SELECT * FROM public.t_ortrue;
ALTER VIEW v_or OWNER TO mxd_or_owner;
GRANT SELECT ON v_or TO mxd_vuser;

SELECT pg_temp.mk('t_vw');
ALTER TABLE t_vw OWNER TO mxd_door_owner;
ALTER TABLE t_vw ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_vw ON t_vw FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.tenant', true));
GRANT SELECT, UPDATE, DELETE ON t_vw TO mxd_vwuser;
CREATE VIEW v_w AS SELECT * FROM public.t_vw;
ALTER VIEW v_w OWNER TO mxd_door_owner;
GRANT INSERT, UPDATE, DELETE ON v_w TO mxd_vwuser;

SELECT pg_temp.mk('t_mv');
ALTER TABLE t_mv OWNER TO mxd_door_owner;
ALTER TABLE t_mv ENABLE ROW LEVEL SECURITY;
CREATE MATERIALIZED VIEW mv_all AS SELECT * FROM public.t_mv;
ALTER MATERIALIZED VIEW mv_all OWNER TO mxd_door_owner;
GRANT SELECT ON mv_all TO mxd_vuser;

SELECT pg_temp.mk('t_x');
ALTER TABLE t_x OWNER TO mxd_door_owner;
ALTER TABLE t_x ENABLE ROW LEVEL SECURITY;
CREATE SCHEMA mxd_api;
GRANT USAGE ON SCHEMA mxd_api TO mxd_apiuser;
CREATE VIEW mxd_api.v_x AS SELECT * FROM public.t_x;
ALTER VIEW mxd_api.v_x OWNER TO mxd_door_owner;
GRANT SELECT ON mxd_api.v_x TO mxd_apiuser;

CREATE TABLE t_part (id int, tenant_id text, owner_name text, note text, email text, ssn text)
  PARTITION BY LIST (tenant_id);
CREATE TABLE t_part_a PARTITION OF t_part FOR VALUES IN ('a');
CREATE TABLE t_part_b PARTITION OF t_part FOR VALUES IN ('b', 'zzz');
INSERT INTO t_part VALUES (1, 'a', 'x', 'n1', 'a1@x', '111'), (2, 'a', 'x', 'n2', 'a2@x', '222'),
  (3, 'b', 'x', 'n3', 'b1@x', '333'), (4, 'b', 'x', 'n4', 'b2@x', '444');
ALTER TABLE t_part_a ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_part_a FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON t_part TO mxd_partuser;

CREATE TABLE t_inh (id int, tenant_id text, owner_name text, note text, email text, ssn text);
CREATE TABLE t_inh_c () INHERITS (t_inh);
INSERT INTO t_inh_c VALUES (1, 'a', 'x', 'n1', 'a1@x', '111'), (2, 'a', 'x', 'n2', 'a2@x', '222'),
  (3, 'b', 'x', 'n3', 'b1@x', '333'), (4, 'b', 'x', 'n4', 'b2@x', '444');
ALTER TABLE t_inh ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_inh ON t_inh FOR ALL TO PUBLIC
  USING (tenant_id = current_setting('app.tenant', true));
ALTER TABLE t_inh_c ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_inh_c FORCE ROW LEVEL SECURITY;
GRANT SELECT, UPDATE, DELETE, TRUNCATE ON t_inh TO mxd_partuser;

SELECT pg_temp.mk('t_nested');
GRANT SELECT ON t_nested TO mxd_mid;

-- A SECURITY DEFINER trigger: INSERT on the source deletes the destination.
SELECT pg_temp.mk('t_trig_src');
ALTER TABLE t_trig_src OWNER TO mxd_door_owner;
GRANT INSERT ON t_trig_src TO mxd_trguser;
SELECT pg_temp.mk('t_trig_dst');
ALTER TABLE t_trig_dst OWNER TO mxd_door_owner;
ALTER TABLE t_trig_dst ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION trg_wipe() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
  AS 'BEGIN DELETE FROM public.t_trig_dst; RETURN NEW; END';
ALTER FUNCTION trg_wipe() OWNER TO mxd_door_owner;
REVOKE EXECUTE ON FUNCTION trg_wipe() FROM PUBLIC;
CREATE TRIGGER wipe_on_insert AFTER INSERT ON t_trig_src
  FOR EACH ROW EXECUTE FUNCTION trg_wipe();

-- A rule: INSERT on the source runs a DELETE as the source's owner.
SELECT pg_temp.mk('t_rule_src');
ALTER TABLE t_rule_src OWNER TO mxd_door_owner;
GRANT INSERT ON t_rule_src TO mxd_ruleuser;
SELECT pg_temp.mk('t_rule_dst');
ALTER TABLE t_rule_dst OWNER TO mxd_door_owner;
ALTER TABLE t_rule_dst ENABLE ROW LEVEL SECURITY;
CREATE RULE r_wipe AS ON INSERT TO t_rule_src DO ALSO DELETE FROM public.t_rule_dst;

-- A foreign key that cascades a DELETE into a FORCE'd child with no grant.
CREATE TABLE t_fk_parent (id int PRIMARY KEY, tenant_id text, owner_name text,
  note text, email text, ssn text);
INSERT INTO t_fk_parent VALUES (1, 'a', 'x', 'n1', 'a1@x', '111'),
  (2, 'a', 'x', 'n2', 'a2@x', '222'), (3, 'b', 'x', 'n3', 'b1@x', '333'),
  (4, 'b', 'x', 'n4', 'b2@x', '444');
GRANT DELETE, UPDATE ON t_fk_parent TO mxd_fkuser;
CREATE TABLE t_fk_child (id int, tenant_id text, owner_name text, note text, email text,
  ssn text, pid int REFERENCES t_fk_parent ON DELETE CASCADE);
INSERT INTO t_fk_child SELECT id, tenant_id, owner_name, note, email, ssn, id FROM t_fk_parent;
ALTER TABLE t_fk_child ENABLE ROW LEVEL SECURITY;
ALTER TABLE t_fk_child FORCE ROW LEVEL SECURITY;

-- A SQL-standard body with an empty search_path: deparsed schema-qualified.
SELECT pg_temp.mk('t_atomic');
ALTER TABLE t_atomic OWNER TO mxd_door_owner;
ALTER TABLE t_atomic ENABLE ROW LEVEL SECURITY;
CREATE FUNCTION f_atomic() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = ''
  BEGIN ATOMIC DELETE FROM public.t_atomic; END;
ALTER FUNCTION f_atomic() OWNER TO mxd_door_owner;
REVOKE EXECUTE ON FUNCTION f_atomic() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION f_atomic() TO mxd_fnuser;

-- A partition whose parent lives outside the grid's schema.
CREATE TABLE mxd_api.t_evt (id int, tenant_id text, owner_name text, note text,
  email text, ssn text) PARTITION BY LIST (tenant_id);
CREATE TABLE public.t_evt_a PARTITION OF mxd_api.t_evt FOR VALUES IN ('a', 'zzz');
CREATE TABLE mxd_api.t_evt_b PARTITION OF mxd_api.t_evt FOR VALUES IN ('b');
INSERT INTO mxd_api.t_evt VALUES (1, 'a', 'x', 'n1', 'a1@x', '111'),
  (2, 'a', 'x', 'n2', 'a2@x', '222'), (3, 'b', 'x', 'n3', 'b1@x', '333'),
  (4, 'b', 'x', 'n4', 'b2@x', '444');
ALTER TABLE public.t_evt_a ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.t_evt_a FORCE ROW LEVEL SECURITY;
GRANT USAGE ON SCHEMA mxd_api TO mxd_partuser;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON mxd_api.t_evt TO mxd_partuser;
"""

# Function calls that reach a table, keyed by (table, command) — their call
# forms vary, so they are listed; view and parent doors are derived from the
# schema (`_mxd_doors`). A SELECT door is a template over `{expr}`.
_MXD_MANUAL_DOORS: dict[tuple[str, str], tuple[str, ...]] = {
    ("public.t_door", "SELECT"): ("SELECT {expr} FROM f_door()",),
    ("public.t_fn_pub", "SELECT"): ("SELECT {expr} FROM f_pub()",),
    ("public.t_plpg", "SELECT"): ("SELECT {expr} FROM f_plpg()",),
    ("public.t_svc", "SELECT"): ("SELECT {expr} FROM f_svc()",),
    ("public.t_wipe", "DELETE"): ("SELECT f_wipe()",),
    ("public.t_atomic", "DELETE"): ("SELECT f_atomic()",),
    # A trigger and a rule both fire on an INSERT into their source table.
    ("public.t_trig_dst", "DELETE"): (
        "INSERT INTO t_trig_src (id, tenant_id, owner_name) VALUES (500, 'a', 'x')",
    ),
    ("public.t_rule_dst", "DELETE"): (
        "INSERT INTO t_rule_src (id, tenant_id, owner_name) VALUES (600, 'a', 'x')",
    ),
}
# A partition only accepts its own key: probe it with rows it can hold.
_MXD_PROBES = {
    "public.t_part_a": ("(100, 'a', current_user)", "(101, 'a', 'nobody')"),
    "public.t_part_b": ("(100, 'b', current_user)", "(101, 'zzz', 'nobody')"),
}
_MXD_DEFAULT_PROBES = ("(100, 'a', current_user)", "(101, 'zzz', 'nobody')")


_MXD_VIEWS_SQL = """
SELECT DISTINCT vn.nspname || '.' || v.relname AS view, v.relkind = 'm' AS mat,
       tn.nspname || '.' || t.relname AS base
FROM pg_class v
JOIN pg_namespace vn ON vn.oid = v.relnamespace
JOIN pg_rewrite r ON r.ev_class = v.oid
JOIN pg_depend d ON d.objid = r.oid AND d.classid = 'pg_rewrite'::regclass
                AND d.refclassid = 'pg_class'::regclass
JOIN pg_class t ON t.oid = d.refobjid AND t.relkind IN ('r', 'p')
JOIN pg_namespace tn ON tn.oid = t.relnamespace
WHERE v.relkind IN ('v', 'm') AND vn.nspname NOT IN ('pg_catalog', 'information_schema')
"""
_MXD_PARENTS_SQL = """
SELECT cn.nspname || '.' || c.relname AS child, pn.nspname || '.' || p.relname AS parent,
       p.relkind = 'p' AS declarative
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_namespace cn ON cn.oid = c.relnamespace
JOIN pg_class p ON p.oid = i.inhparent JOIN pg_namespace pn ON pn.oid = p.relnamespace
"""


def _mxd_doors(conn: psycopg.Connection) -> dict[tuple[str, str], tuple[str, ...]]:
    """Every statement that reaches a table other than by naming it, read from
    the Postgres catalog rather than from pgrls' introspection — a door the
    introspection missed must not be missed here too. Each view over the table
    (read, and write for a regular view), each ancestor (read, write, TRUNCATE,
    and INSERT for a partitioned one), and the function calls."""
    doors: dict[tuple[str, str], list[str]] = {k: list(v) for k, v in _MXD_MANUAL_DOORS.items()}

    def add(table: str, command: str, stmt: str) -> None:
        doors.setdefault((table, command), []).append(stmt)

    with conn.cursor() as cur:
        cur.execute(_MXD_VIEWS_SQL)
        views = cur.fetchall()
        cur.execute(_MXD_PARENTS_SQL)
        edges = cur.fetchall()
    for view, mat, table in views:
        add(table, "SELECT", f"SELECT {{expr}} FROM {view}")
        if not mat:
            add(table, "INSERT", f"INSERT INTO {view} (id, tenant_id, owner_name) VALUES {{row}}")
            add(table, "UPDATE", f"UPDATE {view} SET note = 'x'")
            add(table, "DELETE", f"DELETE FROM {view}")
    parents = {child: (parent, declarative) for child, parent, declarative in edges}
    for child in parents:
        ancestor = child
        while ancestor in parents:  # every ancestor, not only the parent
            ancestor, declarative = parents[ancestor]
            add(child, "SELECT", f"SELECT {{expr}} FROM {ancestor} "
                f"WHERE tableoid = '{child}'::regclass")
            add(child, "UPDATE", f"UPDATE {ancestor} SET note = 'x'")
            add(child, "DELETE", f"DELETE FROM {ancestor}")
            add(child, "TRUNCATE", f"TRUNCATE {ancestor} CASCADE")
            if declarative:
                add(child, "INSERT", f"INSERT INTO {ancestor} "
                    "(id, tenant_id, owner_name) VALUES {row}")
    return {k: tuple(v) for k, v in doors.items()}


_MXD_RANK = {"all": 3, "some": 1, "none": 0}
_MXD_VERDICT_RANK = {"open": 3, "undecided": 2, "conditional": 1, "denied": 0}


def _mxd_effect(conn: psycopg.Connection, role: str, stmt: str, measure: str | None) -> int | None:
    """Run `stmt` as `role` (app.tenant = 'a'), then — back as superuser, in
    the same transaction — run `measure`; roll back either way. The first
    column of the last result, or None when `stmt` was refused."""
    with conn.cursor() as cur:
        cur.execute("BEGIN")
        try:
            cur.execute("SET LOCAL app.tenant = 'a'")
            cur.execute(f'SET LOCAL ROLE "{role}"')
            cur.execute(stmt)
            got = cur.fetchone()[0] if cur.description else 0
            cur.execute("RESET ROLE")
            if measure is not None:
                cur.execute(measure)
                got = cur.fetchone()[0]
            return int(got or 0)
        except psycopg.Error:
            return None
        finally:
            cur.execute("ROLLBACK")


def _mxd_truth(conn: psycopg.Connection, role: str, table: str, command: str,
               stmts: tuple[str, ...], total: int) -> str:
    """The widest reach any of `stmts` gives `role` on `table` for `command`."""
    def reach(n: int | None) -> str:
        return "none" if not n else ("all" if n >= total else "some")

    best = "none"
    for stmt in stmts:
        if command == "SELECT":
            got = reach(_mxd_effect(conn, role, stmt.format(expr="count(*)"), None))
        elif command == "UPDATE":
            got = reach(_mxd_effect(conn, role, stmt,
                                    f"SELECT count(*) FROM {table} WHERE note = 'x'"))
        elif command in ("DELETE", "TRUNCATE"):
            left = _mxd_effect(conn, role, stmt, f"SELECT count(*) FROM {table}")
            got = reach(None if left is None else total - left)
        else:
            good, bad = _MXD_PROBES.get(table, _MXD_DEFAULT_PROBES)
            landed = [
                _mxd_effect(conn, role, stmt.format(row=row),
                            f"SELECT count(*) FROM {table} WHERE id = {rid}")
                for row, rid in ((good, 100), (bad, 101))
            ]
            hits = sum(1 for n in landed if n)
            got = "all" if hits == 2 else ("some" if hits else "none")
        best = max(best, got, key=_MXD_RANK.__getitem__)
    return best


@requires_docker
def test_every_cell_matches_a_live_set_role_session(pg_conn: psycopg.Connection) -> None:
    from pgrls.matrix import introspect_for_matrix  # noqa: PLC0415

    roles = ("PUBLIC",) + _MXD_ROLES[1:]
    as_db = {"PUBLIC": "mxd_pub"}  # a role with no memberships stands in for PUBLIC
    direct = {
        "SELECT": "SELECT {{expr}} FROM {t}",
        "INSERT": "INSERT INTO {t} (id, tenant_id, owner_name) VALUES {{row}}",
        "UPDATE": "UPDATE {t} SET note = 'x'",
        "DELETE": "DELETE FROM {t}",
        # CASCADE: a referenced table cannot be truncated otherwise, and the
        # matrix answers whether the role can empty it at all.
        "TRUNCATE": "TRUNCATE {t} CASCADE",
    }
    with pg_conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS " + ", ".join(_MXD_ROLES))
    try:
        with pg_conn.cursor() as cur:
            cur.execute(_MXD_DDL)
        schema, grid = introspect_for_matrix(pg_conn, ["public"])
        m = build_matrix(schema, roles=roles, grid=grid)
        doors = _mxd_doors(pg_conn)
        totals = {}
        with pg_conn.cursor() as cur:
            for t in {r.qualified_name for r in m.rows}:
                cur.execute(f"SELECT count(*) FROM {t}")
                totals[t] = cur.fetchone()[0]

        wrong = []
        for row in m.rows:
            t, cmd = row.qualified_name, row.command
            stmts = (direct[cmd].format(t=t),) + doors.get((t, cmd), ())
            for role, cell in zip(m.roles, row.cells):
                if cell.verdict == "undecided":
                    continue  # "possibly reachable" is consistent with any truth
                truth = _mxd_truth(pg_conn, as_db.get(role, role), t, cmd, stmts, totals[t])
                if _MXD_VERDICT_RANK[cell.verdict] != _MXD_RANK[truth]:
                    wrong.append((t, cmd, role, cell.verdict, truth, cell.note))
        assert wrong == [], wrong
        # Not vacuous: every verdict shows up, UNDECIDED from the matview.
        seen = {c.verdict for r in m.rows for c in r.cells}
        assert seen == {"open", "conditional", "denied", "undecided"}, seen
        assert m.untraced == ()  # every function body here is traceable
        # The foreign-key door is UNDECIDED (which rows depends on the data),
        # so the loop above skips it — check it is real here instead.
        fk = _cell(m, "public.t_fk_child", "DELETE", "mxd_fkuser")
        assert fk.verdict == "undecided" and "ON DELETE CASCADE" in (fk.note or "")
        assert _mxd_effect(pg_conn, "mxd_fkuser", "DELETE FROM t_fk_parent",
                           "SELECT count(*) FROM t_fk_child") == 0

        # The sensitive-columns section lists exactly what each role can read.
        readable = set()
        for role in roles:
            for t in totals:
                reads = (f"SELECT {{expr}} FROM {t}",) + doors.get((t, "SELECT"), ())
                for col in ("email", "ssn"):
                    if any(_mxd_effect(pg_conn, as_db.get(role, role),
                                       stmt.format(expr=f"count({col})"), None)
                           for stmt in reads):
                        readable.add((role, t, col))
        assert {(e.role, e.table, e.column) for e in m.exposures} == readable
    finally:
        # Roles are cluster-wide (two carry SUPERUSER / BYPASSRLS, which later
        # tests would see): drop every one that exists. DROP OWNED has no
        # IF EXISTS, and a failed DDL batch rolls back as one transaction.
        with pg_conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS mxd_api CASCADE")
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public")
            cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)",
                        (list(_MXD_ROLES),))
            existing = [r[0] for r in cur.fetchall()]
            if existing:
                cur.execute("DROP OWNED BY " + ", ".join(existing))
                cur.execute("DROP ROLE " + ", ".join(existing))


@requires_docker
def test_the_database_owner_is_a_member_of_pg_database_owner(pg_conn: psycopg.Connection) -> None:
    """Measured: the database owner read a table granted only to
    `pg_database_owner`, while `pg_auth_members` held no edge for it."""
    with pg_conn.cursor() as cur:
        cur.execute("SELECT pg_get_userbyid(datdba) FROM pg_database "
                    "WHERE datname = current_database()")
        dbo = cur.fetchone()[0]
    schema = introspect(pg_conn, schemas=["public"])
    assert RoleMembership(member=dbo, role="pg_database_owner", inherit=True) in (
        schema.role_memberships or ()
    )


@requires_docker
def test_introspection_captures_what_the_matrix_reads(pg_conn: psycopg.Connection) -> None:
    """A function's SET clauses, each trigger's level, and a view's reads from
    its SELECT rule alone — not the target of its INSERT rule."""
    with pg_conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE public.t (id int);
            CREATE TABLE public.log (id int);
            CREATE FUNCTION public.trg() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
              SET search_path = public SET app.tenant = 'a' SET statement_timeout = '5s'
              AS $$ BEGIN RETURN NULL; END $$;
            CREATE TRIGGER st AFTER DELETE ON public.t
              FOR EACH STATEMENT EXECUTE FUNCTION public.trg();
            CREATE TRIGGER rt BEFORE INSERT ON public.t
              FOR EACH ROW EXECUTE FUNCTION public.trg();
            CREATE VIEW public.v AS SELECT id FROM public.t;
            CREATE RULE log_ins AS ON INSERT TO public.v
              DO INSTEAD INSERT INTO public.log VALUES (NEW.id);
        """)
    schema = introspect(pg_conn, schemas=["public"])
    [fn] = [f for f in schema.security_definer_functions if f.qualified_name == "public.trg"]
    assert fn.trigger is True
    assert fn.config_gucs == ("app.tenant", "statement_timeout")
    [t] = [t for t in schema.tables if t.name == "t"]
    assert {tr.name: tr.row for tr in t.triggers} == {"st": False, "rt": True}
    [v] = [v for v in schema.views if v.name == "v"]
    assert ("public", "t") in v.references and ("public", "log") not in v.references
    assert [(r.relation, r.command, r.instead) for r in schema.rules or ()] == [
        ("v", "INSERT", True)
    ]


@requires_docker
def test_the_database_owner_edge_follows_the_owners_inherit_on_pg15(
    pg_url: str, pg_conn: psycopg.Connection,
) -> None:
    """The implicit membership inherits on PG16+ and follows the owner's own
    INHERIT attribute on PG15 (measured on both); CI runs this on each."""
    from psycopg.conninfo import make_conninfo  # noqa: PLC0415

    with pg_conn.cursor() as cur:
        cur.execute("SHOW server_version_num")
        version = int(cur.fetchone()[0])
        cur.execute("DROP DATABASE IF EXISTS pgrls_dbo_noinh")
        cur.execute("DROP ROLE IF EXISTS pgrls_dbo_noinh")
        cur.execute("CREATE ROLE pgrls_dbo_noinh NOINHERIT")
        cur.execute("CREATE DATABASE pgrls_dbo_noinh OWNER pgrls_dbo_noinh")
    try:
        with psycopg.connect(make_conninfo(pg_url, dbname="pgrls_dbo_noinh"),
                             autocommit=True) as conn:
            schema = introspect(conn, schemas=["public"])
        edges = [m for m in schema.role_memberships or () if m.role == "pg_database_owner"]
        assert edges == [RoleMembership(member="pgrls_dbo_noinh", role="pg_database_owner",
                                        inherit=version >= 160000)]
    finally:
        with pg_conn.cursor() as cur:
            cur.execute("DROP DATABASE IF EXISTS pgrls_dbo_noinh")
            cur.execute("DROP ROLE IF EXISTS pgrls_dbo_noinh")


# --- live: review iteration 4's three shapes, measured and matched -----------

_REV4_ROLES = ("pgrls_rev4_r", "pgrls_rev4_o")


def _rev4_measure(conn: psycopg.Connection, role: str, stmt: str, after: str) -> int:
    """Run `stmt` as `role` in a rolled-back transaction and return `after`'s
    count, read as the superuser before the rollback."""
    from psycopg import sql as _sql  # noqa: PLC0415

    with conn.transaction(force_rollback=True), conn.cursor() as cur:
        cur.execute(_sql.SQL("SET LOCAL ROLE {}").format(_sql.Identifier(role)))
        cur.execute(stmt)
        cur.execute("RESET ROLE")
        cur.execute(after)
        return int(cur.fetchone()[0])


def _rev4_matrix(conn: psycopg.Connection) -> Matrix:
    from pgrls.matrix import introspect_for_matrix  # noqa: PLC0415

    schema, grid = introspect_for_matrix(conn, ["public"])
    return build_matrix(schema, roles=("pgrls_rev4_r",), grid=grid)


def _rev4_drop_roles(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        for role in _REV4_ROLES:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
            if cur.fetchone() is not None:
                cur.execute(f"DROP OWNED BY {role} CASCADE")
                cur.execute(f"DROP ROLE {role}")


@pytest.fixture
def rev4_roles(pg_conn: psycopg.Connection) -> Iterator[None]:
    """The two roles, created fresh and dropped with what they own: roles are
    cluster-wide, so a test must not leave them behind."""
    _rev4_drop_roles(pg_conn)
    with pg_conn.cursor() as cur:
        for role in _REV4_ROLES:
            cur.execute(f"CREATE ROLE {role}")
    try:
        yield
    finally:
        _rev4_drop_roles(pg_conn)


@requires_docker
@pytest.mark.usefixtures("rev4_roles")
def test_live_a_filter_reading_another_table_differs_through_doors(
    pg_conn: psycopg.Connection,
) -> None:
    with pg_conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE public.memberships (tenant_id text, member text);
            ALTER TABLE public.memberships OWNER TO pgrls_rev4_o;
            ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
            CREATE POLICY m_self ON public.memberships FOR SELECT USING (member = current_user);
            GRANT SELECT ON public.memberships TO pgrls_rev4_r;
            INSERT INTO public.memberships VALUES ('a', 'pgrls_rev4_r'), ('b', 'someone_else');
            CREATE TABLE public.t (id int, tenant_id text);
            ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
            CREATE POLICY p ON public.t FOR SELECT
              USING (tenant_id IN (SELECT tenant_id FROM public.memberships));
            GRANT SELECT ON public.t TO pgrls_rev4_r, pgrls_rev4_o;
            INSERT INTO public.t VALUES (1, 'a'), (2, 'b');
            CREATE VIEW public.v AS SELECT * FROM public.t;
            ALTER VIEW public.v OWNER TO pgrls_rev4_o;
            GRANT SELECT ON public.v TO pgrls_rev4_r;
        """)
    direct = _rev4_measure(pg_conn, "pgrls_rev4_r", "CREATE TEMP TABLE n AS SELECT * FROM public.t",
                           "SELECT count(*) FROM n")
    through = _rev4_measure(pg_conn, "pgrls_rev4_r",
                            "CREATE TEMP TABLE n AS SELECT * FROM public.v",
                            "SELECT count(*) FROM n")
    assert (direct, through) == (1, 2)
    assert _cell(_rev4_matrix(pg_conn), "public.t", "SELECT", "pgrls_rev4_r").verdict == "undecided"


@requires_docker
@pytest.mark.usefixtures("rev4_roles")
def test_live_truncate_through_a_parent_covers_its_partitions(
    pg_conn: psycopg.Connection,
) -> None:
    with pg_conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE public.tree (id int, part int, parent_id int, parent_part int,
              PRIMARY KEY (id, part), FOREIGN KEY (parent_id, parent_part) REFERENCES public.tree)
              PARTITION BY LIST (part);
            CREATE TABLE public.tree_1 PARTITION OF public.tree FOR VALUES IN (1);
            CREATE TABLE public.tree_2 PARTITION OF public.tree FOR VALUES IN (2);
            INSERT INTO public.tree VALUES (1, 1, NULL, NULL), (2, 2, 1, 1);
            GRANT TRUNCATE ON public.tree TO pgrls_rev4_r;
        """)
    left = _rev4_measure(pg_conn, "pgrls_rev4_r", "TRUNCATE public.tree",
                         "SELECT count(*) FROM public.tree")
    assert left == 0
    m = _rev4_matrix(pg_conn)
    for table in ("public.tree", "public.tree_1", "public.tree_2"):
        assert _cell(m, table, "TRUNCATE", "pgrls_rev4_r").verdict == "open", table


@requires_docker
@pytest.mark.usefixtures("rev4_roles")
@pytest.mark.parametrize(("setup", "stmt"), [
    ("""CREATE TABLE public.pp (id int) PARTITION BY RANGE (id);
        CREATE TABLE public.pp1 PARTITION OF public.pp FOR VALUES FROM (0) TO (100);
        CREATE TRIGGER t AFTER TRUNCATE ON public.pp1
          FOR EACH STATEMENT EXECUTE FUNCTION public.wipe();
        GRANT TRUNCATE ON public.pp TO pgrls_rev4_r;""",
     "TRUNCATE public.pp"),
    ("""CREATE TABLE public.pp (id int) PARTITION BY RANGE (id);
        CREATE TABLE public.pp1 PARTITION OF public.pp FOR VALUES FROM (0) TO (100);
        ALTER TABLE public.pp ENABLE ROW LEVEL SECURITY;
        CREATE TRIGGER b BEFORE INSERT ON public.pp1
          FOR EACH ROW EXECUTE FUNCTION public.wipe();
        GRANT INSERT ON public.pp TO pgrls_rev4_r;""",
     "INSERT INTO public.pp VALUES (1)"),
], ids=["truncate-parent", "insert-routed"])
def test_live_a_childs_trigger_fires_through_its_parent(
    pg_conn: psycopg.Connection, setup: str, stmt: str,
) -> None:
    with pg_conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE public.secrets (id int);
            ALTER TABLE public.secrets OWNER TO pgrls_rev4_o;
            ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;
            INSERT INTO public.secrets VALUES (1), (2);
            CREATE FUNCTION public.wipe() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
              SET search_path = public
              AS $$ BEGIN DELETE FROM public.secrets; RETURN NULL; END $$;
            ALTER FUNCTION public.wipe() OWNER TO pgrls_rev4_o;
        """ + setup)
    assert _rev4_measure(pg_conn, "pgrls_rev4_r", stmt, "SELECT count(*) FROM public.secrets") == 0
    assert _cell(_rev4_matrix(pg_conn), "public.secrets", "DELETE",
                 "pgrls_rev4_r").verdict != "denied"


@requires_docker
@pytest.mark.usefixtures("rev4_roles")
def test_matrix_cli_rejects_a_role_the_database_does_not_have(
    pg_url: str, pg_conn: psycopg.Connection,
) -> None:
    """Measured: a typo in --roles showed a full column of DENIED and exit 0."""
    result = CliRunner().invoke(main, [
        "matrix", "--database-url", pg_url, "--roles", "PUBLIC,pgrls_rev4_x",
    ])
    assert result.exit_code == 2, result.output
    assert "Roles not found in the database: pgrls_rev4_x." in result.output
    assert "Did you mean 'pgrls_rev4_r'?" in result.output


# --- iteration 5: relation-reading filters, cascade from partitions, depth ---


def test_a_relation_reading_filter_differs_between_a_view_and_a_function_door() -> None:
    """r reaches t ONLY through the doors — a definer view (`current_user` is
    the caller) and a SECURITY DEFINER function (`current_user` is the owner).
    The `IN (SELECT … FROM memberships)` sub-select reads a different set for
    each, so their union is UNDECIDED, not one COND (measured in iteration 5's
    review: the view returned the caller's row, the function the owner's)."""
    memb = _t("memberships", owner="o",
              policies=(_policy(roles=("PUBLIC",), using="member = current_user"),),
              grants=(_grant("o", ("SELECT",)),))
    t = _t(policies=(_policy(roles=("PUBLIC",),
            using="tenant_id IN (SELECT tenant_id FROM public.memberships)"),),
           grants=(_grant("o", ("SELECT",)),))  # NOT granted to r
    v = _v("v", _OWN_T, owner="o", grants=(_grant("r", ("SELECT",)),))
    f = _f("SELECT * FROM public.t", owner="o", execute=("r",))
    m = build_matrix(_s([t, memb], [v], [f], roles=[_r("r"), _r("o"), _r("own")]),
                     roles=("r",))
    assert _cell(m, "public.t", "SELECT", "r").verdict == "undecided"


def test_a_cascade_in_a_body_reaches_a_referencer_of_a_partition() -> None:
    """`TRUNCATE p CASCADE` also empties tables referencing p's partitions
    (measured: a foreign key to a partition cascades). The door must credit
    that referencer, not only tables referencing p itself."""
    p = _t("p", rls=False, grants=(_grant("o", ("TRUNCATE",)),))
    p1 = _t("p1", rls=False, partition_of=("public", "p"))
    x = _with(_t("x", rls=False, grants=(_grant("o", ("TRUNCATE",)),)),
              foreign_keys=(_fk("p1"),))
    f = _f("TRUNCATE public.p CASCADE", owner="o", execute=("r",))
    m = build_matrix(_s([p, p1, x], fns=[f], roles=[_r("r"), _r("o"), _r("own")]),
                     roles=("r",))
    assert _cell(m, "public.x", "TRUNCATE", "r").verdict != "denied"


def test_a_deeply_nested_predicate_does_not_crash() -> None:
    """A pathologically deep policy predicate must not overflow the AST walks
    (`_clause_is_open`, `_dependence`); it is treated as a real predicate."""
    deep = "id = 0"
    for i in range(1, 1200):
        deep = f"id = {i} OR ({deep})"
    t = _t(policies=(_policy(roles=("PUBLIC",), using=deep),),
           grants=(_grant("r", ("SELECT",)),))
    v = _v("v", _OWN_T, owner="o", grants=(_grant("r", ("SELECT",)),))
    m = build_matrix(_s([t], [v], roles=[_r("r"), _r("o"), _r("own")]), roles=("r",))
    assert _cell(m, "public.t", "SELECT", "r").verdict in ("conditional", "undecided")


# --- matrix --prove: an isolation proof per SELECT cell -----------------------


def _proof(m: Matrix, table: str, role: str):
    row = next(r for r in m.rows if r.qualified_name == table and r.command == "SELECT")
    assert row.proofs is not None
    return dict(zip(m.roles, row.proofs, strict=True))[role]


def _api(name: str) -> Role:
    """A Supabase-style API role: NOLOGIN, reached by SET ROLE from a login
    role that carries the request's JWT."""
    return Role(name, False, False, False)


def _prove(tables, views=(), fns=(), *, roles=None, cols=("anon", "authenticated")) -> Matrix:
    roles = roles or [_api("anon"), _api("authenticated"), _r("svc"), _r("own")]
    return build_matrix(_s(tables, views, fns, roles=roles), roles=cols, prove=True)


def _sel(using: str, *, grants=("anon", "authenticated"), **kw) -> Table:
    return _t(policies=(_policy(command="SELECT", roles=("PUBLIC",), using=using),),
              grants=tuple(_grant(g, ("SELECT",)) for g in grants), **kw)


# Each key shape as written and as Postgres stores it (Supabase's InitPlan
# wrapper, deparsed with an alias and brackets).
_UID = ["auth.uid()", "( SELECT auth.uid() AS uid)"]


@pytest.mark.parametrize("uid", _UID)
def test_prove_the_inverted_auth_check_leaks_to_anon_but_isolates_tenants(uid: str) -> None:
    """The Lovable-CVE shape in one row: anon reads every row, a tenant only
    its own."""
    m = _prove([_sel(f"({uid} IS NULL) OR (tenant_id = {uid})")])
    anon, auth = _proof(m, "public.t", "anon"), _proof(m, "public.t", "authenticated")
    assert (anon.status, anon.model, anon.witness) == ("leak", "anon", {})
    assert (auth.status, auth.model) == ("proven", "cross-tenant")


@pytest.mark.parametrize("uid", _UID)
def test_prove_a_scoped_filter_is_proven_for_both_models(uid: str) -> None:
    m = _prove([_sel(f"(tenant_id = {uid})")])
    assert {_proof(m, "public.t", r).status for r in ("anon", "authenticated")} == {"proven"}


@pytest.mark.parametrize("uid", _UID)
def test_prove_a_public_flag_leaks_with_the_row_that_shows_it(uid: str) -> None:
    m = _prove([_sel(f"((tenant_id = {uid}) OR is_public)")])
    for role in ("anon", "authenticated"):
        p = _proof(m, "public.t", role)
        assert p.status == "leak" and p.witness and p.witness.get("is_public") is True, p


def test_prove_a_union_sub_select_is_called_a_table_read() -> None:
    m = _prove([_sel("tenant_id IN (SELECT tenant_id FROM public.a UNION "
                     "SELECT tenant_id FROM public.b)")], cols=("authenticated",))
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "sub-select" in (p.detail or ""), p


def test_prove_the_initplan_wrapper_is_not_called_a_table_read() -> None:
    """A FROM-less ( SELECT auth.uid() AS uid) reads no table: an unscoped
    column gets the identity_columns hint, not the sub-select reason."""
    m = _prove([_sel("(creator = ( SELECT auth.uid() AS uid))")], cols=("authenticated",))
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "sub-select" not in (p.detail or ""), p


def test_prove_a_qualified_auth_function_matches_its_stored_bare_call() -> None:
    """Postgres stores public.my_tenant() as my_tenant(): naming the qualified
    helper must make it the identity for the prover too."""
    m = build_matrix(_s([_sel("tenant_id = my_tenant()")],
                        roles=[_api("anon"), _api("authenticated"), _r("own")]),
                     roles=("anon", "authenticated"), prove=True,
                     auth_functions={"public.my_tenant"})
    for role in ("anon", "authenticated"):
        assert _proof(m, "public.t", role).status == "proven", role
    # The defaults (auth.uid) come along with --auth-function; a public.uid()
    # the policy calls bare is not auth.uid.
    s = replace(_s([_sel("tenant_id = uid()")],
                   roles=[_api("anon"), _api("authenticated"), _r("own")]),
                user_functions=(_fn("auth.uid"), _fn("public.uid")))
    m = build_matrix(s, roles=("authenticated",), prove=True,
                     auth_functions={"auth.uid", "app.my_tenant"})
    assert _proof(m, "public.t", "authenticated").status != "proven"
    # Another schema's uid() of the same name: the bare call is ambiguous.
    s = replace(_s([_sel("tenant_id = uid()")],
                   roles=[_api("anon"), _api("authenticated"), _r("own")]),
                user_functions=(_fn("app.uid"), _fn("public.uid")))
    m = build_matrix(s, roles=("anon", "authenticated"), prove=True,
                     auth_functions={"app.uid"})
    assert _proof(m, "public.t", "authenticated").status != "proven"


def test_prove_a_leak_resting_on_an_opaque_helper_is_unknown() -> None:
    """Without --auth-function the prover cannot see what app.uid() returns:
    no row characterizes a leak, so it is not claimed."""
    m = _prove([_sel("tenant_id = app.uid()")])
    for role in ("anon", "authenticated"):
        p = _proof(m, "public.t", role)
        assert p.status == "unknown" and "--auth-function" in (p.detail or ""), (role, p)


def test_prove_a_set_role_to_a_bypassing_role_says_so() -> None:
    t = _sel("tenant_id = auth.uid()", grants=("authenticated", "svc"))
    roles = [_api("authenticated"), Role("svc", False, False, True), _r("own")]
    edge = RoleMembership(member="authenticated", role="svc", inherit=False)
    m = build_matrix(_s([t], roles=roles, memberships=[edge]), roles=("authenticated",),
                     prove=True)
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "bypasses RLS" in (p.detail or ""), p


def test_prove_a_filter_outside_the_fragment_is_unknown() -> None:
    m = _prove([_sel("tenant_id IN (SELECT tenant_id FROM public.memberships)")])
    for role in ("anon", "authenticated"):
        p = _proof(m, "public.t", role)
        assert p.status == "unknown" and p.detail, p


def test_prove_no_privilege_is_proven() -> None:
    m = _prove([_sel("true", grants=())])
    p = _proof(m, "public.t", "anon")
    assert (p.status, p.detail) == ("proven", "no row reachable")


def test_prove_rls_off_reads_every_row() -> None:
    m = _prove([_t(rls=False, grants=(_grant("anon", ("SELECT",)),
                                       _grant("authenticated", ("SELECT",))))])
    anon = _proof(m, "public.t", "anon")
    assert (anon.status, anon.witness, anon.detail) == ("leak", {}, "RLS off")
    # tenant_id is a tenant column: every row includes other tenants' rows.
    assert _proof(m, "public.t", "authenticated").status == "leak"


def test_prove_reading_every_row_of_a_shared_table_is_unknown_cross_tenant() -> None:
    """No tenant column to isolate on: shared data like `countries`, not a
    cross-tenant leak — but still an anonymous read."""
    shared = _with(_t(rls=False, grants=(_grant("anon", ("SELECT",)),
                                         _grant("authenticated", ("SELECT",)))),
                   columns=("code", "name"))
    m = _prove([shared])
    assert _proof(m, "public.t", "anon").status == "leak"
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "no tenant column" in (p.detail or "")


def test_prove_an_undecided_cell_is_unknown() -> None:
    mv = _v("mv", _OWN_T, owner="own", mat=True, grants=(_grant("anon", ("SELECT",)),))
    m = _prove([_sel("tenant_id = auth.uid()", grants=())], [mv])
    assert _proof(m, "public.t", "anon").status == "unknown"


@pytest.mark.parametrize("using", ["true", "tenant_id = auth.uid() OR is_public"])
def test_prove_a_leak_only_through_a_door_is_possible(using: str) -> None:
    """anon holds no grant on t; a definer view owned by svc hands rows over.
    A door is credited with its owner's whole reach — the view's own WHERE is
    not traced — so the leak is POSSIBLE, never a claimed LEAK."""
    t = _sel(using, grants=("svc",))
    v = _v("v", _OWN_T, owner="svc", grants=(_grant("anon", ("SELECT",)),))
    p = _proof(_prove([t], [v]), "public.t", "anon")
    assert p.status == "possible" and "definer view public.v" in (p.detail or ""), p


def test_prove_a_session_dependent_filter_through_a_door_is_unknown() -> None:
    """A door evaluates the filter as its owner; one that reads current_user
    can admit different rows there, so PROVEN cannot be claimed."""
    t = _sel("owner_name = current_user", grants=("svc",))
    f = _f("SELECT * FROM public.t", owner="svc", execute=("anon",))
    p = _proof(_prove([t], fns=[f]), "public.t", "anon")
    assert p.status == "unknown" and "door" in (p.detail or ""), p


def test_prove_a_bypassrls_role_is_exempt_but_an_anonymous_one_leaks() -> None:
    t = _sel("tenant_id = auth.uid()", grants=("anon", "svc"))
    roles = [_r("anon", brls=True), _r("svc", brls=True), _r("own")]
    m = _prove([t], roles=roles, cols=("anon", "svc"))
    assert _proof(m, "public.t", "svc").status == "exempt"
    anon = _proof(m, "public.t", "anon")
    assert (anon.status, anon.witness) == ("leak", {}), anon


def test_prove_no_privilege_beats_exempt() -> None:
    roles = [_r("anon"), _r("svc", brls=True), _r("own")]
    m = _prove([_sel("true", grants=())], roles=roles, cols=("anon", "svc"))
    assert _proof(m, "public.t", "svc").status == "proven"


def test_without_prove_there_are_no_proofs() -> None:
    m = build_matrix(_s([_sel("true")], roles=[_r("anon"), _r("own")]), roles=("anon",))
    assert not m.proven and all(r.proofs is None for r in m.rows)
    payload = json.loads(render_json(m))
    assert "proof_summary" not in payload
    assert all("proof" not in c for r in payload["rows"] for c in r["access"].values())


def test_prove_only_select_rows_carry_proofs() -> None:
    m = _prove([_sel("tenant_id = auth.uid()")])
    assert {r.command for r in m.rows if r.proofs is not None} == {"SELECT"}


def test_prove_renders_in_every_format() -> None:
    m = _prove([_sel("auth.uid() IS NULL OR tenant_id = auth.uid()", name="a<b>")])
    text = render_text(m)
    assert "Isolation proof (SELECT)" in text and "Leaks and possible leaks:" in text
    assert "Anonymous: anon; Cross-tenant: authenticated." in text
    assert "every row is anonymously readable" in text
    assert "Isolation: 1 proven, 1 leak" in text
    md = render_markdown(m)
    assert "## Isolation proof (SELECT)" in md and "### Leaks and possible leaks" in md
    assert "| public.a<b> | LEAK | PROVEN |" in md
    assert "| public.a<b> | anon | LEAK | every row is anonymously readable |" in md
    assert "Isolation: 1 proven, 1 leak." in md
    payload = json.loads(render_json(m))
    access = payload["rows"][0]["access"]
    assert access["anon"]["proof"]["status"] == "leak"
    assert access["authenticated"]["proof"]["status"] == "proven"
    assert payload["proof_summary"]["leak"] == 1
    page = render_html(m, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert "Proven access map" in page and 'class="cell p-leak"' in page
    assert "public.a&lt;b&gt;" in page and "public.a<b>" not in page


def test_matrix_cli_auth_function_needs_prove() -> None:
    result = CliRunner().invoke(
        main, ["matrix", "--database-url", "postgresql://u@/db", "--auth-function", "auth.x"],
    )
    assert result.exit_code == 2
    assert "only applies with --prove" in result.output


def test_prove_an_untraced_door_whose_owner_reaches_the_table_is_unknown() -> None:
    """A function pgrls cannot read may select from the table as its owner."""
    f = _f("BEGIN RETURN; END", owner="svc", lang="plpgsql", execute=("anon",))
    m = _prove([_sel("tenant_id = auth.uid()", grants=("anon", "authenticated", "svc"))],
               fns=[f])
    anon = _proof(m, "public.t", "anon")
    assert anon.status == "unknown" and "public.f" in (anon.detail or ""), anon
    assert _proof(m, "public.t", "authenticated").status == "proven"  # cannot run f
    # Its owner reaches no row of t: nothing it could hand over.
    m = _prove([_sel("tenant_id = auth.uid()")], fns=[f])
    assert _proof(m, "public.t", "anon").status == "proven"


def test_prove_without_schema_usage_the_own_read_is_only_possible() -> None:
    """The role cannot query the table by name, but a view or a pre-parsed
    function body skips the schema check — so not LEAK, and never PROVEN."""
    s = replace(_s([_sel("true")], roles=[_r("anon"), _r("authenticated"), _r("own")]),
                schema_usage=(("public", "authenticated"), ("public", "own")))
    m = build_matrix(s, roles=("anon", "authenticated"), prove=True)
    anon = _proof(m, "public.t", "anon")
    assert anon.status == "possible" and "no USAGE on schema public" in (anon.detail or "")
    assert _proof(m, "public.t", "authenticated").status == "leak"
    # USAGE to PUBLIC, or not captured at all: the read goes through.
    for usage in ((("public", "PUBLIC"),), None):
        m = build_matrix(replace(s, schema_usage=usage), roles=("anon",), prove=True)
        assert _proof(m, "public.t", "anon").status == "leak", usage


def test_prove_pg_read_all_data_carries_usage_on_every_schema() -> None:
    edge = RoleMembership(member="app", role="pg_read_all_data", inherit=True)
    s = replace(_s([_sel("true", grants=("app",))], roles=[_r("app"), _r("own")],
                   memberships=[edge]),
                schema_usage=(("public", "own"),))
    m = build_matrix(s, roles=("app",), prove=True, anon_roles={"app"})
    assert _proof(m, "public.t", "app").status == "leak"


def test_prove_without_schema_usage_a_door_is_still_possible() -> None:
    t = _sel("true", grants=("anon", "svc"))
    v = _v("v", _OWN_T, owner="svc", grants=(_grant("anon", ("SELECT",)),))
    s = replace(_s([t], [v], roles=[_r("anon"), _r("svc"), _r("own")]),
                schema_usage=(("public", "svc"),))
    p = _proof(build_matrix(s, roles=("anon",), prove=True), "public.t", "anon")
    assert p.status == "possible", p


def test_prove_an_untraced_door_is_followed_through_its_owners_doors() -> None:
    """anon can run f (owned by mid, who reaches nothing); mid can run g
    (owned by svc, who reads t). Neither body is readable."""
    f = SecdefFunction(qualified_name="public.f", body="BEGIN RETURN; END", language="plpgsql",
                       owner="mid", execute_roles=("anon",))
    g = SecdefFunction(qualified_name="public.g", body="BEGIN RETURN; END", language="plpgsql",
                       owner="svc", execute_roles=("mid",))
    t = _sel("tenant_id = auth.uid()", grants=("anon", "svc"))
    roles = [_api("anon"), _api("mid"), _r("svc"), _r("own")]
    p = _proof(build_matrix(_s([t], fns=[f, g], roles=roles), roles=("anon",), prove=True),
               "public.t", "anon")
    assert p.status == "unknown" and "public.f" in (p.detail or ""), p
    # svc reaching nothing either: nothing to hand over.
    t = _sel("tenant_id = auth.uid()", grants=("anon",))
    p = _proof(build_matrix(_s([t], fns=[f, g], roles=roles), roles=("anon",), prove=True),
               "public.t", "anon")
    assert p.status == "proven", p


def test_prove_a_parent_reached_only_through_a_view_is_not_the_roles_own() -> None:
    parent = _t("p", rls=False)
    child = _t("c", rls=False, partition_of=("public", "p"))
    v = _v("v", (("public", "p"),), owner="own", grants=(_grant("app", ("SELECT",)),))
    m = build_matrix(_s([parent, child], [v], roles=[_r("app"), _r("own")]),
                     roles=("app",), prove=True, anon_roles={"app"})
    assert _proof(m, "public.p", "app").status == "possible"
    assert _proof(m, "public.c", "app").status == "possible"


def test_prove_a_parent_in_a_schema_without_usage_is_not_the_roles_own() -> None:
    parent = _t("p", schema="pp", rls=False, grants=(_grant("app", ("SELECT",)),))
    child = _t("c", rls=False, partition_of=("pp", "p"))
    s = replace(_s([parent, child], roles=[_r("app"), _r("own")]),
                schema_usage=(("public", "PUBLIC"), ("pp", "own")))
    m = build_matrix(s, roles=("app",), prove=True, anon_roles={"app"})
    assert _proof(m, "pp.p", "app").status == "possible"
    assert _proof(m, "public.c", "app").status == "possible"
    # With USAGE on pp the parent query is the role's own.
    m = build_matrix(replace(s, schema_usage=None), roles=("app",), prove=True,
                     anon_roles={"app"})
    assert _proof(m, "public.c", "app").status == "leak"


def test_prove_a_parent_leak_counts_when_the_child_schema_lacks_usage() -> None:
    """The role cannot name cs.c, but SELECT FROM public.p is its own query
    and returns c's rows."""
    parent = _t("p", rls=False, grants=(_grant("app", ("SELECT",)),))
    child = _t("c", schema="cs", rls=False, grants=(_grant("app", ("SELECT",)),),
               partition_of=("public", "p"))
    s = replace(_s([parent, child], roles=[_r("app"), _r("own")]),
                schema_usage=(("public", "PUBLIC"), ("cs", "own")))
    m = build_matrix(s, roles=("app",), prove=True, anon_roles={"app"})
    p = _proof(m, "cs.c", "app")
    assert (p.status, p.witness) == ("leak", {}) and "public.p" in (p.detail or ""), p


def test_prove_a_leaking_parent_the_role_queries_wins_over_another_door() -> None:
    """app reads p1 itself (RLS off) and p0 only through a view: c's rows
    reach it through p1, so LEAK — the view does not soften that."""
    p0 = _t("p0", rls=False)
    p1 = _t("p1", rls=False, grants=(_grant("app", ("SELECT",)),),
            partition_of=("public", "p0"))
    c = _t("c", rls=False, partition_of=("public", "p1"))
    v = _v("v", (("public", "p0"),), owner="own", grants=(_grant("app", ("SELECT",)),))
    m = build_matrix(_s([p0, p1, c], [v], roles=[_r("app"), _r("own")]),
                     roles=("app",), prove=True, anon_roles={"app"})
    p = _proof(m, "public.c", "app")
    assert (p.status, p.witness) == ("leak", {}) and "public.p1" in (p.detail or ""), p
    assert _proof(m, "public.p0", "app").status == "possible"


def test_prove_a_grandparent_the_role_cannot_query_is_not_its_own_leak() -> None:
    """p1 is reached only through p0 — via a view in one case, in a schema
    without USAGE in the other — so c's rows are not the role's own read."""
    p1 = _t("p1", rls=False, partition_of=("public", "p0"))
    c = _t("c", rls=False, partition_of=("public", "p1"))
    v = _v("v", (("public", "p0"),), owner="own", grants=(_grant("app", ("SELECT",)),))
    m = build_matrix(_s([_t("p0", rls=False), p1, c], [v], roles=[_r("app"), _r("own")]),
                     roles=("app",), prove=True, anon_roles={"app"})
    assert _proof(m, "public.c", "app").status == "possible"
    p0 = _t("p0", schema="s0", rls=False, grants=(_grant("app", ("SELECT",)),))
    p1 = _t("p1", rls=False, partition_of=("s0", "p0"))
    s = replace(_s([p0, p1, c], roles=[_r("app"), _r("own")]),
                schema_usage=(("public", "PUBLIC"), ("s0", "own")))
    m = build_matrix(s, roles=("app",), prove=True, anon_roles={"app"})
    assert _proof(m, "public.c", "app").status == "possible"


def test_prove_a_filtered_parent_leak_is_only_possible_on_a_partition() -> None:
    """The parent's filter is written for every partition: its leaking row
    (visibility = 'public') may not be one this partition can hold."""
    parent = _t("posts", policies=(_policy(command="SELECT", roles=("PUBLIC",),
                                           using="visibility = 'public'"),),
                grants=(_grant("anon", ("SELECT",)),))
    child = _t("posts_priv", partition_of=("public", "posts"))
    m = _prove([parent, child], cols=("anon",))
    assert _proof(m, "public.posts", "anon").status == "leak"
    assert _proof(m, "public.posts_priv", "anon").status == "possible"


def test_prove_a_parent_filter_admitting_every_row_leaks_the_child() -> None:
    """`auth.uid() IS NULL OR …` hands anon every row of the parent, so every
    row of each partition too — no partition bound can rule that out."""
    parent = _t("posts", policies=(_policy(command="SELECT", roles=("PUBLIC",),
                                           using="auth.uid() IS NULL OR tenant_id = auth.uid()"),),
                grants=(_grant("anon", ("SELECT",)),))
    child = _t("posts_a", partition_of=("public", "posts"))
    m = _prove([parent, child], cols=("anon",))
    p = _proof(m, "public.posts_a", "anon")
    assert (p.status, p.witness) == ("leak", {}) and "public.posts" in (p.detail or ""), p


@pytest.mark.parametrize("table", [
    _with(_t(rls=False, grants=(_grant("PUBLIC", ("SELECT",)),)), columns=("code", "name")),
    _sel("auth.uid() IS NULL OR tenant_id = auth.uid()", grants=("PUBLIC",)),
    _sel("auth.role() = 'anon' OR tenant_id = auth.uid()", grants=("PUBLIC",)),
])
def test_prove_a_role_doing_what_public_does_is_not_a_column(table: Table) -> None:
    """PUBLIC answers the anonymous question; each other role is compared
    with PUBLIC under its own (cross-tenant) one, so identical roles stay
    hidden even where the two questions disagree."""
    s = _s([table], roles=[_r("anon"), _r("authenticated"), _r("app_user0"), _r("own")])
    assert "app_user0" not in build_matrix(s, prove=True).roles


def test_prove_unknown_cells_are_listed_with_the_reason() -> None:
    m = _prove([_sel("tenant_id IN (SELECT tenant_id FROM public.memberships)")])
    text, md = render_text(m), render_markdown(m)
    assert "Undecided:" in text and "### Undecided" in md
    assert "reads another table (a sub-select)" in text
    assert "identity_columns" not in text.split("Undecided:")[1]
    page = render_html(m, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert "<h2>Undecided</h2>" in page


def test_prove_the_table_owner_is_never_proven() -> None:
    """FORCE binds the owner to the policies, but the owner can lift FORCE or
    rewrite the policy in one statement — and so can a role that inherits
    the owner, or can SET ROLE to it."""
    t = _with(_sel("tenant_id = auth.uid()", grants=()), owner="app_owner", force_rls=True)
    roles = [_api("app_owner"), _api("heir"), _api("deployer"), _api("other")]
    edges = [RoleMembership(member="heir", role="app_owner", inherit=True),
             RoleMembership(member="deployer", role="app_owner", inherit=False)]
    m = build_matrix(_s([t], roles=roles, memberships=edges),
                     roles=("app_owner", "heir", "deployer", "other"), prove=True)
    for role in ("app_owner", "heir", "deployer"):
        p = _proof(m, "public.t", role)
        assert p.status == "unknown", (role, p)
    assert "owns the table (app_owner)" in (_proof(m, "public.t", "app_owner").detail or "")
    assert "SET ROLE app_owner" in (_proof(m, "public.t", "deployer").detail or "")
    assert _proof(m, "public.t", "other").status == "proven"


def test_prove_a_login_role_can_set_the_identity_it_is_judged_by() -> None:
    """A role that logs in runs its own SQL: it can SET request.jwt.claim.sub
    (or any setting) to another tenant's value, or leave it unset. A NOLOGIN
    API role reached through a gateway that sets the JWT cannot."""
    t = _sel("tenant_id = auth.uid()", grants=("app_user", "authenticated"))
    m = build_matrix(_s([t], roles=[_r("app_user"), _api("authenticated"), _r("own")]),
                     roles=("app_user", "authenticated"), prove=True)
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "logs in" in (p.detail or ""), p
    assert _proof(m, "public.t", "authenticated").status == "proven"


def test_prove_public_is_a_gateway_session_while_a_login_role_is_not() -> None:
    t = _sel("tenant_id = auth.uid()", grants=("PUBLIC",))
    m = build_matrix(_s([t], roles=[_api("anon"), _r("app_user"), _r("own")]), prove=True)
    assert _proof(m, "public.t", "PUBLIC").status == "proven"
    assert _proof(m, "public.t", "app_user").status == "unknown"


def _fn(qname: str, *, owner: str = "own", body: str | None = "SELECT 1",
        language: str = "sql", search_path: str | None = None, atomic: bool = False):
    from pgrls.model import UserFunction  # noqa: PLC0415

    return UserFunction(qualified_name=qname, owner=owner, language=language,
                        search_path=search_path, atomic=atomic, body=body)


# A helper keyed on current_user, which a login session cannot forge — so the
# schema-changing gates are what stands between it and PROVEN.
_SAFE_BODY = "SELECT tenant FROM app.users WHERE name = current_user"
_BARE_BODY = "SELECT tenant FROM users WHERE name = current_user"


def _helper_matrix(*fns, creators=(), memberships=()):
    roles = ("app_user", "other")
    t = _sel("tenant_id = cur()", grants=roles)
    users = _t("users", schema="app", rls=False)  # what the helpers read; nobody writes it
    s = replace(_s([t, users], roles=[*(_r(r) for r in roles), _api("fnadm"), _r("own")],
                   memberships=memberships),
                user_functions=fns, schema_create=creators)
    return build_matrix(s, roles=roles, prove=True, auth_functions={"cur"},
                        grid=frozenset({"public.t"}))


def test_prove_a_login_role_with_an_unforgeable_helper_is_proven() -> None:
    m = _helper_matrix(_fn("app.cur", body=_SAFE_BODY, search_path="app, pg_temp"))
    assert _proof(m, "public.t", "app_user").status == "proven"


def test_prove_a_helper_that_reads_a_setting_is_forgeable() -> None:
    m = _helper_matrix(_fn("app.cur", body="SELECT current_setting('app.tenant', true)",
                           search_path="app, pg_temp"))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "cur()" in (p.detail or ""), p


def test_prove_the_owner_of_a_function_the_filter_calls_is_not_proven() -> None:
    """Measured: the owner of the helper redefined it and read another
    tenant's row."""
    m = _helper_matrix(_fn("app.cur", owner="app_user", body=_SAFE_BODY,
                           search_path="app, pg_temp"))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "owns the user-defined function app.cur()" in (
        p.detail or ""), p
    assert _proof(m, "public.t", "other").status == "proven"


def test_prove_a_member_of_a_function_owner_is_not_proven() -> None:
    """Measured: a member of the helper's owner (no grant on the table
    itself) redefined it and read another tenant's row."""
    m = _helper_matrix(_fn("app.cur", owner="fnadm", body=_SAFE_BODY, search_path="app, pg_temp"),
                       memberships=[RoleMembership(member="app_user", role="fnadm",
                                                   inherit=True)])
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "app.cur()" in (p.detail or ""), p


def test_prove_owning_any_function_rules_out_the_filter() -> None:
    """Measured: an operator backed by a function the session owns — the
    owned function need not be one the filter names."""
    m = _helper_matrix(_fn("app.cur", body=_SAFE_BODY, search_path="app, pg_temp"),
                       _fn("public.txt_eq", owner="app_user"))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "operator" in (p.detail or ""), p


def test_prove_create_on_a_schema_rules_out_a_filter_calling_a_user_function() -> None:
    """Measured: with CREATE on a schema the session put a shadowing function
    on its search_path, which the helper resolved."""
    fns = (_fn("app.cur", body=_SAFE_BODY),)
    m = _helper_matrix(*fns, creators=(("public", "PUBLIC"),))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "schema public" in (p.detail or ""), p
    assert "REVOKE CREATE ON SCHEMA public FROM PUBLIC" in (p.detail or "")
    m = _helper_matrix(*fns, creators=(("public", "own"),))
    assert _proof(m, "public.t", "app_user").status == "proven"


def test_prove_schema_changing_gates_skip_a_gateway_role() -> None:
    """A NOLOGIN role is reached through a gateway that runs only the API's
    queries; a login member's own column carries what the session can do."""
    t = _sel("tenant_id = cur()", grants=("authenticated",))
    users = _t("users", schema="app", rls=False)
    s = replace(_s([t, users], roles=[_api("authenticated"), _r("own")]),
                user_functions=(_fn("app.cur", owner="authenticated", body=_SAFE_BODY),),
                schema_create=(("public", "PUBLIC"),))
    m = build_matrix(s, roles=("authenticated",), prove=True, auth_functions={"cur"})
    assert _proof(m, "public.t", "authenticated").status == "proven"


@pytest.mark.parametrize(("fn", "shadowable"), [
    (_fn("app.cur", body=_BARE_BODY), True),
    (_fn("app.cur", body=_SAFE_BODY), False),
    (_fn("app.cur", body=_BARE_BODY, search_path="app, pg_temp"), False),
    (_fn("app.cur", body=_BARE_BODY, search_path="pg_temp, app"), True),
    (_fn("app.cur", body=_BARE_BODY, search_path=""), True),
    (_fn("app.cur", body="SELECT 1", atomic=True), False),
    (_fn("app.cur", body="BEGIN RETURN 1; END", language="plpgsql"), True),
    (_fn("app.cur", body="tenant_lookup", language="c"), False),
    (_fn("app.cur", body="WITH users AS (SELECT 1 AS tenant) SELECT tenant FROM users"), True),
])
def test_prove_a_helper_that_reads_a_table_by_bare_name_is_not_proven(fn, shadowable) -> None:
    """A login session can create a temp table; pg_temp is searched first
    for relations unless the search_path ends in it, so a helper naming a
    table without its schema can be made to read the session's own. A CTE
    name counts too (its scope is not modelled)."""
    p = _proof(_helper_matrix(fn), "public.t", "app_user")
    assert (p.status == "unknown") is shadowable, p


@pytest.mark.parametrize("outer", [
    _fn("app.cur", body="SELECT app.inner_uid()"),
    _fn("app.cur", body="SELECT app.inner_uid()", search_path="app, pg_temp"),
    _fn("app.cur", body="CREATE FUNCTION app.cur() RETURNS text BEGIN ATOMIC "
        "SELECT app.inner_uid(); END", atomic=True),
])
def test_prove_a_shadowable_helper_called_inside_another_is_found(outer) -> None:
    """A safe outer body still calls an inner one that resolves its own
    names — by its pinned path, or the one it inherits (measured)."""
    inner = _fn("app.inner_uid", body=_BARE_BODY, search_path="app")
    p = _proof(_helper_matrix(outer, inner), "public.t", "app_user")
    assert p.status == "unknown" and "app.inner_uid()" in (p.detail or ""), p


def test_prove_a_pre16_createrole_login_is_never_proven() -> None:
    """Measured on PG15: GRANT service_role TO cr; SET ROLE service_role read
    every row of a table cr had no grant on."""
    t = _sel("tenant_id = auth.uid()", grants=("svc",))
    roles = [_r("cr"), _api("svc"), _r("own")]
    s = replace(_s([t], roles=roles), self_granting_roles=("cr",))
    p = _proof(build_matrix(s, roles=("cr",), prove=True), "public.t", "cr")
    assert p.status == "unknown" and "CREATEROLE" in (p.detail or ""), p
    m = build_matrix(replace(s, self_granting_roles=()), roles=("cr",), prove=True)
    assert _proof(m, "public.t", "cr").status == "proven"


@pytest.mark.parametrize("role", [_r("app_user"), _api("app_user")])
def test_prove_an_identity_read_from_a_table_the_role_can_write_is_not_proven(role) -> None:
    """Measured: the session inserted a membership row for another tenant
    and its identity function then returned that tenant — through an ordinary
    API write too, so a gateway role is not spared."""
    body = ("SELECT tenant_id FROM public.memberships WHERE member = current_user "
            "ORDER BY tenant_id DESC LIMIT 1")
    fns = (_fn("app.tenant_of", body=body, search_path="public, pg_temp"),)
    t = _sel("tenant_id = app.tenant_of()", grants=("app_user",))

    def proof(write: bool) -> CellProof:
        memberships = _t("memberships", rls=False, grants=(
            _grant("app_user", ("SELECT", "INSERT") if write else ("SELECT",)),))
        s = replace(_s([t, memberships], roles=[role, _r("own")]), user_functions=fns)
        m = build_matrix(s, roles=("app_user",), prove=True,
                         auth_functions={"app.tenant_of"}, grid=frozenset({"public.t"}))
        return _proof(m, "public.t", "app_user")

    p = proof(write=True)
    assert p.status == "unknown" and "public.memberships" in (p.detail or ""), p
    assert proof(write=False).status == "proven"


def test_prove_a_writable_table_read_by_a_function_the_identity_calls_is_found() -> None:
    fns = (_fn("app.tenant_of", body="SELECT app.lookup()", search_path="public, pg_temp"),
           _fn("app.lookup", body="SELECT tenant_id FROM public.memberships LIMIT 1",
               search_path="public, pg_temp"))
    t = _sel("tenant_id = app.tenant_of()", grants=("app_user",))
    memberships = _t("memberships", rls=False, grants=(_grant("app_user", ("INSERT",)),))
    s = replace(_s([t, memberships], roles=[_api("app_user"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("app_user",), prove=True, auth_functions={"app.tenant_of"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "public.memberships" in (p.detail or ""), p


@pytest.mark.parametrize(("body", "language", "views"), [
    ("BEGIN RETURN (SELECT tenant_id FROM public.memberships LIMIT 1); END", "plpgsql", ()),
    ("SELECT tenant_id FROM public.my_memberships LIMIT 1", "sql", ("my_memberships",)),
    ("SELECT tenant_id FROM private.profiles LIMIT 1", "sql", ()),
    ("BEGIN RETURN 1; EXECUTE 'SELECT 1'; END", "plpgsql", ()),
    ("SELECT tenant_id FROM", "sql", ()),
])
def test_prove_an_identity_pgrls_cannot_fully_see_is_not_proven(body, language, views) -> None:
    """Measured for a view over the table and a plpgsql body: the session
    wrote memberships and became another tenant. A body pgrls cannot read or a
    relation it cannot resolve counts as any table the role can write."""
    fns = (_fn("app.tenant_of", body=body, language=language, search_path="public, pg_temp"),)
    t = _sel("tenant_id = app.tenant_of()", grants=("app_user",))
    memberships = _t("memberships", rls=False, grants=(_grant("app_user", ("INSERT",)),))
    vs = [_v(v, (("public", "memberships"),), owner="own", invoker=True) for v in views]
    s = replace(_s([t, memberships], vs, roles=[_api("app_user"), _r("own")]),
                user_functions=fns)
    m = build_matrix(s, roles=("app_user",), prove=True, auth_functions={"app.tenant_of"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "app.tenant_of()" in (p.detail or ""), p


def test_prove_an_identity_reading_a_relation_pgrls_cannot_resolve_is_not_proven() -> None:
    """Even when the role writes no table pgrls sees: the relation may be one
    it can write."""
    fns = (_fn("app.tenant_of", body="SELECT tenant_id FROM elsewhere.profiles LIMIT 1"),)
    t = _sel("tenant_id = app.tenant_of()", grants=("app_user",))
    s = replace(_s([t], roles=[_api("app_user"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("app_user",), prove=True, auth_functions={"app.tenant_of"})
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "elsewhere.profiles" in (p.detail or ""), p


def test_prove_a_cte_name_in_an_identity_body_is_not_a_table() -> None:
    body = ("WITH me AS (SELECT tenant_id FROM app.users WHERE name = current_user) "
            "SELECT tenant_id FROM me")
    m = _helper_matrix(_fn("app.cur", body=body, search_path="app, pg_temp"))
    assert _proof(m, "public.t", "other").status == "proven"


def test_prove_an_identity_table_a_set_role_target_can_write_is_found() -> None:
    """Measured: xr could not write memberships itself, but SET ROLE writer;
    INSERT …; RESET ROLE made it another tenant."""
    fns = (_fn("app.tenant_of", body="SELECT tenant_id FROM public.memberships LIMIT 1",
               search_path="public, pg_temp"),)
    t = _sel("tenant_id = app.tenant_of()", grants=("xr",))
    memberships = _t("memberships", rls=False, grants=(
        _grant("xr", ("SELECT",)), _grant("writer", ("INSERT",))))
    edges = [RoleMembership(member="xr", role="writer", inherit=False)]
    s = replace(_s([t, memberships], roles=[_api("xr"), _api("writer"), _r("own")],
                   memberships=edges), user_functions=fns)
    m = build_matrix(s, roles=("xr",), prove=True, auth_functions={"app.tenant_of"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "xr")
    assert p.status == "unknown" and "public.memberships" in (p.detail or ""), p


def test_prove_an_unreadable_identity_is_fine_when_the_role_writes_nothing() -> None:
    fns = (_fn("app.tenant_of", body="BEGIN RETURN 1; END", language="plpgsql"),)
    t = _sel("tenant_id = app.tenant_of()", grants=("app_user",))
    s = replace(_s([t], roles=[_api("app_user"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("app_user",), prove=True, auth_functions={"app.tenant_of"})
    assert _proof(m, "public.t", "app_user").status == "proven"


def test_prove_createrole_reached_by_set_role_is_named() -> None:
    t = _sel("tenant_id = auth.uid()", grants=())
    roles = [_r("ops"), _api("cr"), _api("gw"), _r("own")]
    edges = [RoleMembership(member="ops", role="cr", inherit=False)]
    s = replace(_s([t], roles=roles, memberships=edges), self_granting_roles=("cr", "gw"))
    m = build_matrix(s, roles=("ops", "gw"), prove=True)
    p = _proof(m, "public.t", "ops")
    assert p.status == "unknown" and "SET ROLE cr" in (p.detail or ""), p
    # A NOLOGIN CREATEROLE role is reached only through a login member's column.
    assert _proof(m, "public.t", "gw").status == "proven"


@pytest.mark.parametrize("setting", ["request.header.tenant", "request.cookie.tenant",
                                     "request.headers", "request.path", "request.method"])
def test_prove_a_client_controlled_setting_is_never_an_identity(setting: str) -> None:
    t = _sel(f"tenant_id = current_setting('{setting}', true)", grants=("authenticated",))
    m = _prove([t], cols=("authenticated",))
    p = _proof(m, "public.t", "authenticated")
    assert p.status != "proven", p


def test_prove_a_setting_name_in_its_stored_cast_form_is_read() -> None:
    """Postgres stores current_setting('x'::text, true): a tenant setting is
    still PROVEN, a request header still is not."""
    ok = _sel("tenant_id = current_setting('app.tenant_id'::text, true)", grants=("authenticated",))
    hdr = _with(_sel("tenant_id = current_setting('request.header.t'::text, true)",
                     grants=("authenticated",)), name="h")
    m = _prove([ok, hdr], cols=("authenticated",))
    assert _proof(m, "public.t", "authenticated").status == "proven"
    p = _proof(m, "public.h", "authenticated")
    assert p.status == "unknown" and "request.header.t" in (p.detail or ""), p


def test_prove_a_client_controlled_setting_in_a_helper_body_is_found() -> None:
    fns = (_fn("app.cur", body="SELECT current_setting('request.header.tenant', true)"),)
    t = _sel("tenant_id = cur()", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("authenticated",), prove=True, auth_functions={"cur"})
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "request.header.tenant" in (p.detail or ""), p


def test_prove_a_cte_name_excuses_a_bare_name_only_in_its_own_body() -> None:
    fns = (_fn("app.tenant_of", body="WITH x AS (SELECT 1 AS tenant_id) "
               "SELECT app.inner_of() FROM x", search_path="app, pg_temp"),
           _fn("app.inner_of", body="SELECT tenant_id FROM x LIMIT 1",
               search_path="app, pg_temp"))
    t = _sel("tenant_id = app.tenant_of()", grants=("app_user",))
    s = replace(_s([t], roles=[_api("app_user"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("app_user",), prove=True, auth_functions={"app.tenant_of"})
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "reads x" in (p.detail or ""), p


@pytest.mark.parametrize("fns", [
    (_fn("app.cur", body="SELECT app.hdr()"),
     _fn("app.hdr", body="SELECT current_setting('request.headers', true)")),
    (_fn("app.cur", language="plpgsql",
         body="DECLARE r text; BEGIN EXECUTE 'SELECT 1' INTO r; RETURN r; END"),),
    (_fn("app.cur", body="SELECT current_setting('request.' || 'headers', true)"),),
])
def test_prove_a_client_setting_pgrls_cannot_rule_out_is_found(fns) -> None:
    """Measured for a nested helper and dynamic SQL: the client chose the
    tenant through a request header."""
    t = _sel("tenant_id = cur()", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("authenticated",), prove=True, auth_functions={"cur"})
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "PostgREST" in (p.detail or ""), p


def test_prove_public_gets_the_writable_identity_check_too() -> None:
    """Measured: any session — an anonymous one included — inserted a row
    into the table its identity function reads and saw another user's rows."""
    fns = (_fn("auth.uid", body="SELECT uid FROM public.sessions WHERE pid = pg_backend_pid()",
               search_path="public, pg_temp"),)
    t = _sel("tenant_id = auth.uid()", grants=("PUBLIC",))
    sessions = _t("sessions", rls=False, grants=(_grant("PUBLIC", ("SELECT", "INSERT")),))
    s = replace(_s([t, sessions], roles=[_api("anon"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("PUBLIC",), prove=True, grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "PUBLIC")
    assert p.status == "unknown" and "public.sessions" in (p.detail or ""), p


def test_prove_create_on_the_database_lets_a_login_session_make_its_own_schema() -> None:
    """Measured: CREATE SCHEMA evil; a shadowing lower() on the search_path
    changed what the helper returned."""
    fns = (_fn("app.cur", body=_SAFE_BODY),)
    m = _helper_matrix(*fns)
    assert _proof(m, "public.t", "app_user").status == "proven"
    t = _sel("tenant_id = cur()", grants=("app_user",))
    users = _t("users", schema="app", rls=False)
    s = replace(_s([t, users], roles=[_r("app_user"), _r("own")]), user_functions=fns,
                schema_create=(), database_create=("app_user",))
    m = build_matrix(s, roles=("app_user",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "CREATE on the database" in (p.detail or ""), p


@pytest.mark.parametrize("body", [
    "SELECT application_name FROM pg_catalog.pg_stat_activity WHERE pid = pg_backend_pid()",
    "SELECT setting FROM pg_settings WHERE name = 'application_name'",
])
def test_prove_a_helper_reading_session_state_from_the_catalog_is_settable(body: str) -> None:
    """Measured: SET application_name = 't2' made the helper return another
    tenant."""
    m = _helper_matrix(_fn("app.cur", body=body, search_path="pg_catalog, pg_temp"))
    p = _proof(m, "public.t", "app_user")
    assert p.status == "unknown" and "cur()" in (p.detail or ""), p


def test_prove_a_conditional_leak_on_a_builtin_stays_a_leak() -> None:
    """now() is not a helper the prover cannot see: a row with a future
    timestamp leaks, even if no single row is shown."""
    m = _prove([_sel("(tenant_id = auth.uid()) OR (created > now())")], cols=("anon",))
    assert _proof(m, "public.t", "anon").status == "leak"


@pytest.mark.parametrize("kind", ["table", "view"])
def test_prove_a_login_session_owning_what_its_identity_reads_is_not_proven(kind: str) -> None:
    """Measured: the owner lifted FORCE on the identity table (or replaced the
    view's _RETURN rule) and read another tenant's row."""
    rt = _t("role_tenants", schema="app", owner="appf", force=True,
            policies=(_policy(command="SELECT", roles=("PUBLIC",), using="true"),),
            grants=(_grant("appf", ("SELECT",)),))
    views = []
    rel = "app.role_tenants"
    if kind == "view":
        rt = _with(rt, owner="own")
        views = [_v("my_tenant_v", (("app", "role_tenants"),), owner="appf")]
        rel = "public.my_tenant_v"
    fns = (_fn("app.cur", body=f"SELECT tenant_id FROM {rel} LIMIT 1",
               search_path="pg_catalog, pg_temp"),)
    t = _sel("tenant_id = cur()", grants=("appf",))
    for login, expect in ((True, "unknown"), (False, "proven")):
        role = _r("appf") if login else _api("appf")
        s = replace(_s([t, rt], views, roles=[role, _r("own")]), user_functions=fns)
        m = build_matrix(s, roles=("appf",), prove=True, auth_functions={"cur"},
                         grid=frozenset({"public.t"}))
        p = _proof(m, "public.t", "appf")
        assert p.status == expect, (login, p)
        if expect == "unknown":
            assert "owns" in (p.detail or ""), p


@pytest.mark.parametrize("role", [_r("appf"), _api("appf")])
def test_prove_current_schema_is_chosen_by_the_session(role) -> None:
    """Measured for a login role: SET search_path = t2 read the other tenant.
    PostgREST sets the search_path from the client's Accept-Profile header."""
    fns = (_fn("app.cur", body="SELECT pg_catalog.current_schema()::text",
               search_path=None),)
    t = _sel("tenant_id = cur()", grants=("appf",))
    s = replace(_s([t], roles=[role, _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("appf",), prove=True, auth_functions={"cur"})
    assert _proof(m, "public.t", "appf").status == "unknown"


@pytest.mark.parametrize("child_kind", ["inherits", "partition"])
@pytest.mark.parametrize("role", [_r("appf"), _api("appf")])
def test_prove_a_writable_child_of_the_identity_table_is_found(child_kind, role) -> None:
    """Measured (inheritance, through an API write too): inserting into a
    child changed what the identity function read from the parent."""
    parent = _t("role_tenants", rls=False, grants=(_grant("appf", ("SELECT",)),))
    child = _t("role_tenants_extra", rls=False, grants=(_grant("appf", ("INSERT",)),),
               **({"inherits": (("public", "role_tenants"),)} if child_kind == "inherits"
                  else {"partition_of": ("public", "role_tenants")}))
    fns = (_fn("app.cur", body="SELECT max(tenant_id) FROM public.role_tenants",
               search_path="pg_catalog, pg_temp"),)
    t = _sel("tenant_id = cur()", grants=("appf",))
    s = replace(_s([t, parent, child], roles=[role, _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("appf",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "appf")
    assert p.status == "unknown" and "role_tenants_extra" in (p.detail or ""), p


@pytest.mark.parametrize("extra", [
    "(published AND current_setting('app.preview', true) = 'on')",
    "auth.role() = 'anon'",
    "((tenant_id = 'demo') AND (current_setting('app.preview', true) = 'on'))",
])
def test_prove_a_cross_tenant_leak_on_another_session_value_is_unknown(extra: str) -> None:
    """The cross-tenant prover leaves a setting or a second claim free; a
    real authenticated session may never hold the value it needs."""
    m = _prove([_sel(f"(tenant_id = auth.uid()) OR {extra}")], cols=("authenticated",))
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "besides the tenant identity" in (p.detail or ""), p


@pytest.mark.parametrize("filt", [
    "(tenant_id = auth.uid()) OR (created > now())",
    "(tenant_id = current_setting('app.tenant', true)) OR (created > now())",
    "((tenant_id = auth.uid()) AND (auth.role() = 'authenticated')) OR (created > now())",
])
def test_prove_a_cross_tenant_leak_on_a_builtin_stays_a_leak(filt: str) -> None:
    """The tenant binding — even one that reads a setting — and a claim that
    only narrows the tenant branch are not what the leak rests on."""
    m = _prove([_sel(filt)], cols=("authenticated",))
    assert _proof(m, "public.t", "authenticated").status == "leak"


@pytest.mark.parametrize("role", [_r("appf"), _api("appf")])
def test_prove_an_untraced_door_that_writes_the_identity_table_is_found(role) -> None:
    """Measured: a SECURITY DEFINER function's dynamic UPDATE of the table the
    identity function reads switched the caller's tenant."""
    rt = _t("role_tenants", rls=False, grants=(_grant("appf", ("SELECT",)),
                                               _grant("tenant_admin", ("UPDATE",))))
    door = _f("BEGIN RETURN; END", owner="tenant_admin", lang="plpgsql", execute=("appf",))
    fns = (_fn("app.cur", body="SELECT max(tenant_id) FROM public.role_tenants",
               search_path="pg_catalog, pg_temp"),)
    t = _sel("tenant_id = cur()", grants=("appf",))
    s = replace(_s([t, rt], fns=[door], roles=[role, _r("tenant_admin"), _r("own")]),
                user_functions=fns)
    m = build_matrix(s, roles=("appf",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "appf")
    assert p.status == "unknown" and "public.role_tenants" in (p.detail or ""), p


def _door_case(*, owns: str):
    """A gateway role that can run an untraced SECURITY DEFINER function owned
    by tenant_admin; `owns` says what tenant_admin owns."""
    rt = _t("role_tenants", owner="tenant_admin" if owns == "identity_table" else "own",
            force=True, policies=(_policy(command="SELECT", roles=("PUBLIC",), using="true"),),
            grants=(_grant("appf", ("SELECT",)),))
    door = _f("BEGIN RETURN; END", owner="tenant_admin", lang="plpgsql", execute=("appf",))
    fns = (_fn("app.cur", owner="tenant_admin" if owns == "function" else "own",
               body="SELECT max(tenant_id) FROM public.role_tenants",
               search_path="pg_catalog, pg_temp"),)
    t = _with(_sel("tenant_id = cur()", grants=("appf",)),
              owner="tenant_admin" if owns == "table" else "own")
    s = replace(_s([t, rt], fns=[door], roles=[_api("appf"), _api("tenant_admin"), _r("own")]),
                user_functions=fns)
    m = build_matrix(s, roles=("appf",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    return _proof(m, "public.t", "appf")


@pytest.mark.parametrize("owns", ["identity_table", "function", "table"])
def test_prove_an_untraced_door_acts_with_its_owners_ddl(owns: str) -> None:
    """Measured: through a SECURITY DEFINER function's dynamic SQL, its owner
    lifted FORCE on the identity table, or redefined the identity function,
    and the caller read another tenant's row."""
    p = _door_case(owns=owns)
    assert p.status == "unknown", (owns, p)
    assert "untraced door" in (p.detail or ""), p  # the cause is the door, named


def test_prove_an_untraced_door_owning_nothing_relevant_is_fine() -> None:
    assert _door_case(owns="nothing").status == "proven"


@pytest.mark.parametrize(("using", "role", "expect"), [
    ("tenant_id = coalesce(current_setting('app.allowed', true), 't1')", _r("appf"), "unknown"),
    ("tenant_id = coalesce(current_setting('app.allowed', true), 't1')", _api("appf"), "proven"),
    ("tenant_id = current_setting('request.header.t', true)", _api("appf"), "unknown"),
])
def test_prove_the_identity_tables_own_row_security_is_followed(using, role, expect) -> None:
    """Measured for a login role: SET app.allowed = 't2' changed which rows
    the identity function saw, and the caller read another tenant's row. A
    gateway session cannot SET, but the HTTP client chooses its headers."""
    rt = _t("role_tenants", force=True,
            policies=(_policy(command="SELECT", roles=("PUBLIC",), using=using),),
            grants=(_grant("appf", ("SELECT",)),))
    fns = (_fn("app.cur", body="SELECT max(tenant_id) FROM public.role_tenants",
               search_path="pg_catalog, pg_temp"),)
    t = _sel("tenant_id = cur()", grants=("appf",))
    s = replace(_s([t, rt], roles=[role, _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("appf",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "appf")
    assert p.status == expect, p
    if expect == "unknown":
        assert "row security" in (p.detail or ""), p


@pytest.mark.parametrize("via", ["sub-select", "helper"])
@pytest.mark.parametrize("role", [_r("appf"), _api("appf")])
def test_prove_a_writable_table_behind_the_identity_tables_policy_is_found(via, role) -> None:
    """Measured (through an ordinary API write too): inserting into the table
    the identity table's policy reads changed which rows the identity saw."""
    using = ("tenant_id IN (SELECT tenant_id FROM public.unlocked)" if via == "sub-select"
             else "app.is_unlocked(tenant_id)")
    rt = _t("role_tenants", force=True,
            policies=(_policy(command="SELECT", roles=("PUBLIC",), using=using),),
            grants=(_grant("appf", ("SELECT",)),))
    unlocked = _t("unlocked", rls=False, grants=(_grant("appf", ("SELECT", "INSERT")),))
    fns = (_fn("app.cur", body="SELECT max(tenant_id) FROM public.role_tenants",
               search_path="pg_catalog, pg_temp"),
           _fn("app.is_unlocked", body="SELECT EXISTS (SELECT 1 FROM public.unlocked)",
               search_path="pg_catalog, pg_temp"))
    t = _sel("tenant_id = cur()", grants=("appf",))
    s = replace(_s([t, rt, unlocked], roles=[role, _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("appf",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "appf")
    assert p.status == "unknown" and "public.unlocked" in (p.detail or ""), p
    if via == "sub-select":
        assert "through the row security of public.role_tenants" in (p.detail or ""), p


@pytest.mark.parametrize(("hook_body", "expect"), [
    ("SELECT set_config('app.tenant', current_setting('request.headers', true)::json"
     " ->> 'x-tenant', true)", "unknown"),
    ("SELECT set_config('app.tenant', current_setting('request.jwt.claims', true)::json"
     " ->> 'tenant', true)", "proven"),
])
def test_prove_a_pre_request_hook_copying_a_header_taints_settings(hook_body, expect) -> None:
    """Replayed: PostgREST's per-request sequence with a hook that copies the
    X-Tenant header into app.tenant served another tenant's rows."""
    t = _sel("tenant_id = current_setting('app.tenant', true)", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(_fn("public.pre", body=hook_body),),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True)
    p = _proof(m, "public.t", "authenticated")
    assert p.status == expect, p
    if expect == "unknown":
        assert "pre-request hook" in (p.detail or ""), p


def test_prove_a_hook_taints_only_the_settings_it_writes() -> None:
    """A hook that copies a header into app.tenant leaves a filter on
    auth.uid() — which reads the JWT claim — PROVEN."""
    hook = _fn("public.pre", body="SELECT set_config('app.tenant', current_setting("
               "'request.header.x-tenant', true), true)")
    uid = _fn("auth.uid", body="SELECT nullif(current_setting('request.jwt.claim.sub', true), '')")
    t = _sel("tenant_id = auth.uid()", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(hook, uid),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True)
    assert _proof(m, "public.t", "authenticated").status == "proven"
    # A hook writing a computed name taints every setting.
    s = replace(s, user_functions=(_fn("public.pre", body=(
        "SELECT set_config('app.' || current_setting('request.header.k', true), 'x', true)")),
        uid))
    m = build_matrix(s, roles=("authenticated",), prove=True)
    assert _proof(m, "public.t", "authenticated").status == "unknown"


@pytest.mark.parametrize(("privs", "expect"), [(("SELECT", "UPDATE"), "unknown"),
                                              (("SELECT",), "proven")])
def test_prove_a_hook_copying_from_a_writable_table_taints_settings(privs, expect) -> None:
    """Replayed: an ordinary UPDATE of the user's own profile row changed the
    "active org" the hook copied into app.tenant."""
    hook = _fn("public.pre", body="SELECT set_config('app.tenant', "
               "(SELECT active_org FROM public.profiles LIMIT 1), true)")
    profiles = _t("profiles", rls=False, grants=(_grant("authenticated", privs),))
    t = _sel("tenant_id = current_setting('app.tenant', true)", grants=("authenticated",))
    s = replace(_s([t, profiles], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(hook,),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True, grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "authenticated")
    assert p.status == expect, p
    if expect == "unknown":
        assert "public.profiles" in (p.detail or ""), p  # the real source, named


def test_prove_a_hook_that_writes_no_setting_taints_nothing() -> None:
    """A header-checking hook that only raises writes no setting, so it can
    steer none — even for a filter reaching an auth function pgrls cannot
    read."""
    hook = _fn("public.pre", body="SELECT CASE WHEN current_setting('request.header.k', true)"
               " IS NULL THEN 1/0 END")
    t = _sel("tenant_id = auth.uid()", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(hook,),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True)
    assert _proof(m, "public.t", "authenticated").status == "proven"


def test_prove_two_tainting_hooks_combine_what_they_write() -> None:
    """Measured: a database-level hook tainting app.x sorted first, and the
    role-level one that runs taints app.tenant."""
    a_pre = _fn("public.a_pre", body="SELECT set_config('app.x', current_setting("
                "'request.headers', true), true)")
    pre = _fn("public.pre", body="SELECT set_config('app.tenant', current_setting("
              "'request.header.x-tenant', true), true)")
    t = _sel("tenant_id = current_setting('app.tenant', true)", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(a_pre, pre),
                set_gucs=(("pgrst.db_pre_request", "public.a_pre"),),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True)
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "public.pre " in (p.detail or ""), p
    # Only the hook whose setting the filter reads is named.
    assert "public.a_pre" not in (p.detail or ""), p


def test_prove_every_configured_pre_request_hook_is_judged() -> None:
    """Measured: a database-level clean hook and a role-level tainting one —
    the role's overrides it, so it is the one that runs."""
    clean = _fn("public.aaa_clean", body="SELECT 1")
    pre = _fn("public.pre", body="SELECT set_config('app.tenant', current_setting("
              "'request.header.x-tenant', true), true)")
    t = _sel("tenant_id = current_setting('app.tenant', true)", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(clean, pre),
                set_gucs=(("pgrst.db_pre_request", "public.aaa_clean"),),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True)
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "public.pre" in (p.detail or ""), p


def test_prove_a_hook_tainted_setting_in_the_identity_tables_policy_is_found() -> None:
    """Replayed: the hook copied X-Tenant into app.tenant, which the identity
    table's own policy read."""
    hook = _fn("public.pre", body="SELECT set_config('app.tenant', current_setting("
               "'request.headers', true)::json ->> 'x-tenant', true)")
    cur = _fn("app.cur", body="SELECT max(tenant_id) FROM public.memberships",
              search_path="pg_catalog, pg_temp")
    mem = _t("memberships", force=True, policies=(_policy(
        command="SELECT", roles=("PUBLIC",),
        using="tenant_id = coalesce(current_setting('app.tenant', true), 't1')"),),
        grants=(_grant("authenticated", ("SELECT",)),))
    t = _sel("tenant_id = cur()", grants=("authenticated",))
    s = replace(_s([t, mem], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(hook, cur),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "row security" in (p.detail or ""), p


@pytest.mark.parametrize(("fn", "expect"), [
    (_fn("app.cur", body="SELECT tenant_id FROM tenant_info"), "unknown"),
    (_fn("app.cur", body="SELECT tenant_id FROM tenant_info", search_path="t1"), "proven"),
    (_fn("app.cur", body="SELECT tenant_id FROM t1.tenant_info"), "proven"),
    (_fn("app.cur", body="SELECT lookup()"), "unknown"),
])
def test_prove_accept_profile_can_steer_a_gateway_helpers_bare_names(fn, expect) -> None:
    """Measured: search_path = "t2", "public" — what PostgREST sets for
    Accept-Profile: t2 — made an unpinned helper read t2's table."""
    fns = (fn, _fn("app.lookup", body="SELECT 1", search_path="app"))
    t = _sel("tenant_id = cur()", grants=("authenticated",))
    tables = [_t("tenant_info", schema="t1", rls=False), _t("tenant_info", schema="t2", rls=False)]
    s = replace(_s([t, *tables], roles=[_api("authenticated"), _r("own")]), user_functions=fns)
    m = build_matrix(s, roles=("authenticated",), prove=True, auth_functions={"cur"},
                     grid=frozenset({"public.t"}))
    p = _proof(m, "public.t", "authenticated")
    assert p.status == expect, p
    if expect == "unknown":
        assert "Accept-Profile" in (p.detail or ""), p


@pytest.mark.parametrize("write", [
    "INSERT INTO public.request_log VALUES (current_setting('request.headers', true))",
    "MERGE INTO public.request_log l USING (SELECT current_setting('request.headers', true) "
    "AS h) s ON false WHEN NOT MATCHED THEN INSERT VALUES (s.h)",
    "TRUNCATE public.request_log",
])
def test_prove_a_hook_that_writes_a_table_taints_every_setting(write: str) -> None:
    """Measured (INSERT and MERGE): a trigger on the table the hook wrote set
    app.tenant from the request headers."""
    hook = _fn("public.pre", body=f"SELECT current_setting('request.headers', true); {write}")
    t = _sel("tenant_id = current_setting('app.tenant', true)", grants=("authenticated",))
    s = replace(_s([t], roles=[_api("authenticated"), _r("authenticator"), _r("own")]),
                user_functions=(hook,),
                role_set_gucs=(("authenticator", "pgrst.db_pre_request", "public.pre"),))
    m = build_matrix(s, roles=("authenticated",), prove=True)
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "any setting" in (p.detail or ""), p


def test_prove_a_column_never_reads_safer_than_the_role_is() -> None:
    """PUBLIC shows PROVEN (anonymous question); a login role's UNKNOWN
    under its own question must not hide behind that."""
    t = _with(_sel("auth.uid() IS NOT NULL", grants=("PUBLIC",)), columns=("id", "body"))
    s = _s([t], roles=[_api("anon"), _r("app_user"), _r("own")])
    m = build_matrix(s, prove=True)
    assert _proof(m, "public.t", "PUBLIC").status == "proven"
    assert "app_user" in m.roles and _proof(m, "public.t", "app_user").status == "unknown"


def test_prove_a_leak_every_login_role_shares_is_still_shown() -> None:
    """PUBLIC's column answers the anonymous question (PROVEN here); a leak
    to every signed-in role must not hide behind PUBLIC's unshown answer to
    the cross-tenant one."""
    t = _sel("auth.uid() IS NOT NULL AND (tenant_id = auth.uid() OR is_public)",
             grants=("PUBLIC",))
    s = _s([t], roles=[_api("anon"), _r("app_user"), _r("own")])
    m = build_matrix(s, prove=True)
    assert _proof(m, "public.t", "PUBLIC").status == "proven"
    assert "app_user" in m.roles and _proof(m, "public.t", "app_user").status == "leak"


def test_prove_a_role_that_reaches_nothing_is_not_a_column() -> None:
    s = _s([_sel("tenant_id = auth.uid()")],
           roles=[_r("anon"), _r("authenticated"), _r("y"), _r("own")])
    assert "y" not in build_matrix(s, prove=True).roles


def test_prove_a_superuser_column_is_exempt() -> None:
    t = _sel("tenant_id = auth.uid()", grants=())
    m = _prove([t], roles=[_r("anon"), _r("su", su=True), _r("own")], cols=("anon", "su"))
    p = _proof(m, "public.t", "su")
    assert p.status == "exempt" and (p.detail or "").startswith("superuser"), p


def test_prove_identity_columns_set_the_tenant_axis() -> None:
    t = _t(rls=False, grants=(_grant("authenticated", ("SELECT",)),))
    s = _s([t], roles=[_r("authenticated"), _r("own")])
    assert _proof(build_matrix(s, roles=("authenticated",), prove=True),
                  "public.t", "authenticated").status == "leak"
    p = _proof(build_matrix(s, roles=("authenticated",), prove=True,
                            identity_columns=frozenset({"org_id"})),
               "public.t", "authenticated")
    assert p.status == "unknown" and "no tenant column" in (p.detail or ""), p


def test_prove_html_with_no_tables_says_so() -> None:
    m = build_matrix(_s([], roles=[_r("anon")]), roles=("anon",), prove=True)
    page = render_html(m, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert page.count("No tables found in the scanned schemas.") == 2


def test_matrix_cli_rejects_bad_anon_roles_before_connecting(tmp_path) -> None:
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint.rules.SEC004]\nanon_roles = "anon"\n')
    result = CliRunner().invoke(main, [
        "matrix", "--database-url", "postgresql://u@127.0.0.1:1/db", "--prove",
        "--config", str(cfg),
    ])
    assert result.exit_code == 2, result.output
    assert "anon_roles" in result.output


def test_prove_a_role_that_can_set_role_to_a_bypassing_one_is_unknown() -> None:
    t = _sel("tenant_id = auth.uid()", grants=("anon", "authenticated", "svc"))
    roles = [_api("anon"), _api("authenticated"), _r("svc", brls=True), _r("own")]
    # NOINHERIT: no privileges carried over, but SET ROLE svc still works.
    edge = RoleMembership(member="authenticated", role="svc", inherit=False)
    m = build_matrix(_s([t], roles=roles, memberships=[edge]),
                     roles=("anon", "authenticated"), prove=True)
    p = _proof(m, "public.t", "authenticated")
    assert p.status == "unknown" and "SET ROLE svc" in (p.detail or ""), p
    assert _proof(m, "public.t", "anon").status == "proven"
    # Without the membership graph it cannot be ruled out.
    s = replace(_s([t], roles=roles), role_memberships=None)
    p = _proof(build_matrix(s, roles=("authenticated",), prove=True), "public.t",
               "authenticated")
    assert p.status == "unknown" and "role-membership" in (p.detail or ""), p
    # And with no membership at all it is proven.
    m = build_matrix(_s([t], roles=roles), roles=("authenticated",), prove=True)
    assert _proof(m, "public.t", "authenticated").status == "proven"


def test_prove_a_role_only_a_set_role_away_from_bypassing_is_shown() -> None:
    """Its cells are PUBLIC's, so the plain matrix hides it; its proof is not."""
    t = _sel("tenant_id = auth.uid()", grants=("svc",))
    roles = [_r("x"), _r("svc", brls=True), _r("own")]
    s = _s([t], roles=roles,
           memberships=[RoleMembership(member="x", role="svc", inherit=False)])
    assert "x" not in build_matrix(s).roles
    m = build_matrix(s, prove=True)
    assert "x" in m.roles and _proof(m, "public.t", "x").status == "unknown"


def test_prove_each_anonymous_column_gets_its_own_login_settings() -> None:
    """A role-level setting binds to that login role only (guest cannot log
    in, so its own settings never apply)."""
    t = _sel("current_setting('app.open', true) = 'on'", grants=("anon", "guest", "PUBLIC"))
    s = replace(_s([t], roles=[_r("anon"), _api("guest"), _r("own")]),
                role_set_gucs=(("anon", "app.open", "on"),))
    m = build_matrix(s, roles=("anon", "guest", "PUBLIC"), prove=True,
                     anon_roles={"anon", "guest"})
    assert _proof(m, "public.t", "anon").status == "leak"
    assert _proof(m, "public.t", "guest").status == "proven"
    # PUBLIC is any session, so anon's among them: it leaks under PUBLIC too.
    assert _proof(m, "public.t", "PUBLIC").status == "leak"


def test_prove_a_tenant_setting_left_unset_is_not_proven() -> None:
    """Isolated while the session names its tenant; not if it can leave the
    setting unset and fall into the other branch."""
    leaky = ("current_setting('app.tenant', true) IS NULL "
             "OR tenant_id = current_setting('app.tenant', true)")
    p = _proof(_prove([_sel(leaky)]), "public.t", "authenticated")
    assert p.status == "unknown" and "unset" in (p.detail or ""), p
    p = _proof(_prove([_sel("tenant_id = current_setting('app.tenant', true)")]),
               "public.t", "authenticated")
    assert p.status == "proven", p


def test_prove_the_roles_own_leak_wins_over_a_door() -> None:
    """The role reads the leaking row itself; a door adding rows does not make
    that merely POSSIBLE."""
    t = _sel("tenant_id = auth.uid() OR is_public", grants=("anon", "svc"))
    v = _v("v", _OWN_T, owner="svc", grants=(_grant("anon", ("SELECT",)),))
    p = _proof(_prove([t], [v]), "public.t", "anon")
    assert p.status == "leak" and p.witness and p.witness.get("is_public") is True, p


def test_prove_a_read_through_a_queried_parent_is_the_roles_own() -> None:
    parent = _t("p", policies=(_policy(roles=("PUBLIC",), using="true"),),
                grants=(_grant("anon", ("SELECT",)),))
    child = _t("p1", rls=False, partition_of=("public", "p"))
    m = _prove([parent, child], cols=("anon",))
    p = _proof(m, "public.p1", "anon")
    assert (p.status, p.witness) == ("leak", {}), p


def test_matrix_cli_rejects_bad_identity_columns_before_connecting(tmp_path) -> None:
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint.rules.SEC021]\nidentity_columns = "tenant_id"\n')
    result = CliRunner().invoke(main, [
        "matrix", "--database-url", "postgresql://u@127.0.0.1:1/db", "--prove",
        "--config", str(cfg),
    ])
    assert result.exit_code == 2, result.output
    assert "identity_columns must be a list" in result.output


def test_prove_escapes_role_names_and_witness_values_in_html() -> None:
    evil = 'ev"il<b>|x'
    t = _sel("tenant_id = auth.uid() OR email = '<script>|'", grants=(evil,))
    m = build_matrix(_s([t], roles=[_r(evil), _r("own")]), roles=(evil,), prove=True,
                     anon_roles={evil})
    page = render_html(m, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert "<script>" not in page and "<b>" not in page
    md = render_markdown(m)
    assert "<script>|" not in md and 'ev"il<b>|x' not in md


_PM_ROLES = ("pgrls_pm_anon", "pgrls_pm_auth")


def _pm_drop(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        for role in _PM_ROLES:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
            if cur.fetchone() is not None:
                cur.execute(f"DROP OWNED BY {role} CASCADE")
                cur.execute(f"DROP ROLE {role}")
        cur.execute("DROP SCHEMA IF EXISTS auth CASCADE")
        cur.execute("DROP SCHEMA IF EXISTS pgrls_pm_priv CASCADE")


@requires_docker
def test_live_every_proof_agrees_with_a_real_session(pg_conn: psycopg.Connection) -> None:
    """PROVEN means a real session reads no such row; LEAK means it does — for
    the anonymous model (any row, no JWT claim) and the cross-tenant one (a
    row of another tenant, with tenant a's claim)."""
    from psycopg import sql as _sql  # noqa: PLC0415

    from pgrls.matrix import introspect_for_matrix  # noqa: PLC0415

    _pm_drop(pg_conn)
    try:
        with pg_conn.cursor() as cur:
            cur.execute("""
                CREATE ROLE pgrls_pm_anon NOLOGIN; CREATE ROLE pgrls_pm_auth NOLOGIN;
                -- The fixture grants CREATE on public to PUBLIC (the pre-PG15
                -- default): any role could then shadow what auth.uid() resolves.
                REVOKE CREATE ON SCHEMA public FROM PUBLIC;
                CREATE SCHEMA auth;
                CREATE FUNCTION auth.uid() RETURNS text LANGUAGE sql STABLE AS
                  $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '') $$;
                GRANT USAGE ON SCHEMA auth TO pgrls_pm_anon, pgrls_pm_auth;
            """)
            for table, using in (
                ("notes", "auth.uid() IS NULL OR tenant_id = auth.uid()"),
                ("orders", "tenant_id = auth.uid()"),
                ("invoices", "tenant_id = auth.uid() OR is_public"),
            ):
                cur.execute(f"""
                    CREATE TABLE public.{table} (id int, tenant_id text, is_public bool);
                    INSERT INTO public.{table} VALUES (1, 'a', false), (2, 'b', false),
                                                      (3, 'b', true);
                    ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;
                    CREATE POLICY p ON public.{table} FOR SELECT USING ({using});
                    GRANT SELECT ON public.{table} TO pgrls_pm_anon, pgrls_pm_auth;
                """)
            # Readable by policy and grant, but only one role holds USAGE.
            cur.execute("""
                CREATE SCHEMA pgrls_pm_priv;
                CREATE TABLE pgrls_pm_priv.secrets (id int, tenant_id text);
                INSERT INTO pgrls_pm_priv.secrets VALUES (1, 'b');
                ALTER TABLE pgrls_pm_priv.secrets ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p ON pgrls_pm_priv.secrets FOR SELECT USING (true);
                GRANT SELECT ON pgrls_pm_priv.secrets TO pgrls_pm_anon, pgrls_pm_auth;
                GRANT USAGE ON SCHEMA pgrls_pm_priv TO pgrls_pm_auth;
            """)

        def reads(role: str, table: str, claim: str | None, schema_name: str = "public") -> bool:
            """Whether the session sees a row it should not: any row for the
            anonymous model, a row of another tenant for the cross-tenant one."""
            with pg_conn.transaction(force_rollback=True), pg_conn.cursor() as cur:
                cur.execute(_sql.SQL("SET LOCAL ROLE {}").format(_sql.Identifier(role)))
                if claim is not None:
                    cur.execute("SELECT set_config('request.jwt.claim.sub', %s, true)", (claim,))
                    cur.execute(_sql.SQL("SELECT count(*) FROM {}.{} WHERE tenant_id <> %s")
                                .format(_sql.Identifier(schema_name), _sql.Identifier(table)),
                                (claim,))
                else:
                    cur.execute(_sql.SQL("SELECT count(*) FROM {}.{}")
                                .format(_sql.Identifier(schema_name), _sql.Identifier(table)))
                return int(cur.fetchone()[0]) > 0

        schema, grid = introspect_for_matrix(pg_conn, ["public", "pgrls_pm_priv"])
        owners = dict(schema.function_owners or ())
        with pg_conn.cursor() as cur:
            cur.execute("SELECT current_user")
            assert owners.get("auth.uid") == cur.fetchone()[0]
        m = build_matrix(schema, roles=_PM_ROLES, grid=grid, prove=True,
                         anon_roles={"pgrls_pm_anon"})
        anon = _proof(m, "pgrls_pm_priv.secrets", "pgrls_pm_anon")
        assert anon.status == "possible" and "no USAGE on schema pgrls_pm_priv" in (
            anon.detail or "")
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="schema"), \
                pg_conn.transaction(force_rollback=True), pg_conn.cursor() as cur:
            cur.execute("SET LOCAL ROLE pgrls_pm_anon")
            cur.execute("SELECT count(*) FROM pgrls_pm_priv.secrets")
        assert _proof(m, "pgrls_pm_priv.secrets", "pgrls_pm_auth").status == "leak"
        assert reads("pgrls_pm_auth", "secrets", "a", schema_name="pgrls_pm_priv")
        seen = {}
        for table in ("notes", "orders", "invoices"):
            q = f"public.{table}"
            for role, claim in (("pgrls_pm_anon", None), ("pgrls_pm_auth", "a")):
                p = _proof(m, q, role)
                assert p.status in ("proven", "leak"), (q, role, p)
                assert (p.status == "leak") is reads(role, table, claim), (q, role, p)
                seen[(table, role)] = p.status
        # The shapes the grid exists to show.
        assert seen[("notes", "pgrls_pm_anon")] == "leak"
        assert seen[("notes", "pgrls_pm_auth")] == "proven"
        assert seen[("orders", "pgrls_pm_anon")] == "proven"
        assert seen[("invoices", "pgrls_pm_auth")] == "leak"
    finally:
        _pm_drop(pg_conn)


@requires_docker
def test_live_matrix_cli_prove_reports_a_leak_and_exits_0(
    pg_url: str, pg_conn: psycopg.Connection, tmp_path,
) -> None:
    """End to end: --prove keeps the exit code at 0 with a LEAK in the grid,
    and --auth-function makes a project's own helper a tenant identity."""
    _pm_drop(pg_conn)
    try:
        with pg_conn.cursor() as cur:
            cur.execute("""
                CREATE ROLE pgrls_pm_anon NOLOGIN; CREATE ROLE pgrls_pm_auth NOLOGIN;
                -- The fixture grants CREATE on public to PUBLIC (the pre-PG15
                -- default): any role could then shadow what auth.uid() resolves.
                REVOKE CREATE ON SCHEMA public FROM PUBLIC;
                CREATE SCHEMA auth;
                CREATE FUNCTION auth.uid() RETURNS text LANGUAGE sql STABLE AS
                  $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '') $$;
                CREATE FUNCTION auth.tenant() RETURNS text LANGUAGE sql STABLE AS
                  $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '') $$;
                GRANT USAGE ON SCHEMA auth TO pgrls_pm_anon, pgrls_pm_auth;
                CREATE TABLE public.notes (id int, tenant_id text);
                ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p ON public.notes FOR SELECT
                  USING (auth.uid() IS NULL OR tenant_id = auth.uid());
                CREATE TABLE public.orders (id int, tenant_id text);
                ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p ON public.orders FOR SELECT USING (tenant_id = auth.tenant());
                GRANT SELECT ON public.notes, public.orders TO pgrls_pm_anon, pgrls_pm_auth;
            """)
        cfg = tmp_path / "pgrls.toml"
        cfg.write_text('[lint.rules.SEC004]\nanon_roles = ["pgrls_pm_anon"]\n')
        cfg_args = ["--database-url", pg_url, "--prove", "--format", "json",
                    "--roles", ",".join(_PM_ROLES), "--config", str(cfg)]

        def proofs(*extra: str) -> dict[tuple[str, str], str]:
            result = CliRunner().invoke(main, ["matrix", *cfg_args, *extra])
            assert result.exit_code == 0, result.output
            payload = json.loads(result.output)
            return {
                (r["table"], role): c["proof"]["status"]
                for r in payload["rows"] if r["command"] == "SELECT"
                for role, c in r["access"].items()
            }

        plain = proofs()
        assert plain[("public.notes", "pgrls_pm_anon")] == "leak"  # exit 0 all the same
        assert plain[("public.notes", "pgrls_pm_auth")] == "proven"
        assert plain[("public.orders", "pgrls_pm_auth")] == "unknown"  # auth.tenant() opaque
        named = proofs("--auth-function", "auth.tenant")
        assert named[("public.orders", "pgrls_pm_auth")] == "proven"
    finally:
        _pm_drop(pg_conn)


@requires_docker
def test_live_a_temp_table_shadows_a_helper_unless_pg_temp_is_last(
    pg_conn: psycopg.Connection,
) -> None:
    """Measured, and what --prove says about it: a helper reading `cfg` by
    bare name under a pinned search_path that does not end in pg_temp reads
    the session's own temp table; ending the path in pg_temp stops it."""
    from pgrls.matrix import introspect_for_matrix  # noqa: PLC0415

    def drop() -> None:
        with pg_conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS public.shadow_a, public.shadow_b")
            cur.execute("DROP SCHEMA IF EXISTS pgrls_pm_app CASCADE")
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'pgrls_pm_auth'")
            if cur.fetchone() is not None:
                cur.execute("DROP OWNED BY pgrls_pm_auth CASCADE")
                cur.execute("DROP ROLE pgrls_pm_auth")

    drop()
    try:
        with pg_conn.cursor() as cur:
            cur.execute("""
                -- LOGIN: a raw SQL session, which can create temp tables.
                CREATE ROLE pgrls_pm_auth LOGIN;
                CREATE SCHEMA pgrls_pm_app;
                GRANT USAGE ON SCHEMA pgrls_pm_app TO pgrls_pm_auth;
                CREATE TABLE pgrls_pm_app.cfg (tenant text);
                INSERT INTO pgrls_pm_app.cfg VALUES ('a');
                GRANT SELECT ON pgrls_pm_app.cfg TO pgrls_pm_auth;
                CREATE FUNCTION pgrls_pm_app.cur_a() RETURNS text LANGUAGE sql STABLE
                  SET search_path = pgrls_pm_app AS $$ SELECT tenant FROM cfg $$;
                CREATE FUNCTION pgrls_pm_app.cur_b() RETURNS text LANGUAGE sql STABLE
                  SET search_path = pgrls_pm_app, pg_temp AS $$ SELECT tenant FROM cfg $$;
            """)
            for t, fn in (("shadow_a", "cur_a"), ("shadow_b", "cur_b")):
                cur.execute(f"""
                    CREATE TABLE public.{t} (id int, tenant_id text);
                    INSERT INTO public.{t} VALUES (1, 'a'), (2, 'b');
                    ALTER TABLE public.{t} ENABLE ROW LEVEL SECURITY;
                    CREATE POLICY p ON public.{t} FOR SELECT
                      USING (tenant_id = pgrls_pm_app.{fn}());
                    GRANT SELECT ON public.{t} TO pgrls_pm_auth;
                """)

        def other_tenant_rows(table: str) -> int:
            with pg_conn.transaction(force_rollback=True), pg_conn.cursor() as cur:
                cur.execute("SET LOCAL ROLE pgrls_pm_auth")
                cur.execute("CREATE TEMP TABLE cfg (tenant text) ON COMMIT DROP")
                cur.execute("INSERT INTO cfg VALUES ('b')")
                cur.execute(f"SELECT count(*) FROM public.{table} WHERE tenant_id <> 'a'")
                return int(cur.fetchone()[0])

        assert other_tenant_rows("shadow_a") == 1  # the temp table took cfg's place
        assert other_tenant_rows("shadow_b") == 0

        # The fixture's public schema lets PUBLIC create objects: a session
        # could also shadow a name the helper resolves, so nothing is PROVEN.
        schema, grid = introspect_for_matrix(pg_conn, ["public"])
        m = build_matrix(schema, roles=("pgrls_pm_auth",), grid=grid, prove=True,
                         auth_functions={"pgrls_pm_app.cur_a", "pgrls_pm_app.cur_b"})
        b = _proof(m, "public.shadow_b", "pgrls_pm_auth")
        assert b.status == "unknown" and "schema public" in (b.detail or ""), b
        with pg_conn.cursor() as cur:
            cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")

        schema, grid = introspect_for_matrix(pg_conn, ["public"])
        m = build_matrix(schema, roles=("pgrls_pm_auth",), grid=grid, prove=True,
                         auth_functions={"pgrls_pm_app.cur_a", "pgrls_pm_app.cur_b"})
        a = _proof(m, "public.shadow_a", "pgrls_pm_auth")
        assert a.status == "unknown" and "pg_temp" in (a.detail or ""), a
        assert _proof(m, "public.shadow_b", "pgrls_pm_auth").status == "proven"
    finally:
        drop()


@requires_docker
def test_live_createrole_self_granting_is_captured_before_pg16(pg_conn: psycopg.Connection) -> None:
    from pgrls.matrix import introspect_for_matrix  # noqa: PLC0415

    with pg_conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS pgrls_pm_cr")
        cur.execute("CREATE ROLE pgrls_pm_cr LOGIN CREATEROLE")
        cur.execute("SELECT current_setting('server_version_num')::int")
        pre16 = cur.fetchone()[0] < 160000
    try:
        schema, _ = introspect_for_matrix(pg_conn, ["public"])
        assert ("pgrls_pm_cr" in (schema.self_granting_roles or ())) is pre16
        # The database owner can create schemas; a role granted nothing cannot.
        with pg_conn.cursor() as cur:
            cur.execute("SELECT pg_get_userbyid(datdba) FROM pg_database "
                        "WHERE datname = current_database()")
            owner = cur.fetchone()[0]
        assert owner in (schema.database_create or ())
        assert "pgrls_pm_cr" not in (schema.database_create or ())
    finally:
        with pg_conn.cursor() as cur:
            cur.execute("DROP ROLE pgrls_pm_cr")


@requires_docker
def test_live_a_plpgsql_identity_over_a_writable_table_is_not_proven(
    pg_conn: psycopg.Connection,
) -> None:
    """Measured: the session inserts a membership for another tenant and its
    identity function then returns that tenant."""
    from psycopg import sql as _sql  # noqa: PLC0415

    from pgrls.matrix import introspect_for_matrix  # noqa: PLC0415

    def drop() -> None:
        with pg_conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS public.idocs, public.imembers")
            cur.execute("DROP FUNCTION IF EXISTS public.itenant()")
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'pgrls_pm_auth'")
            if cur.fetchone() is not None:
                cur.execute("DROP OWNED BY pgrls_pm_auth CASCADE")
                cur.execute("DROP ROLE pgrls_pm_auth")

    drop()
    try:
        with pg_conn.cursor() as cur:
            cur.execute("""
                REVOKE CREATE ON SCHEMA public FROM PUBLIC;
                CREATE ROLE pgrls_pm_auth NOLOGIN;
                CREATE TABLE public.imembers (member text, tenant_id text);
                INSERT INTO public.imembers VALUES ('pgrls_pm_auth', 'a');
                GRANT SELECT, INSERT ON public.imembers TO pgrls_pm_auth;
                CREATE FUNCTION public.itenant() RETURNS text LANGUAGE plpgsql STABLE
                  SET search_path = public, pg_temp AS $$
                BEGIN
                  RETURN (SELECT tenant_id FROM public.imembers
                          WHERE member = current_user ORDER BY tenant_id DESC LIMIT 1);
                END $$;
                CREATE TABLE public.idocs (id int, tenant_id text);
                INSERT INTO public.idocs VALUES (1, 'a'), (2, 'b');
                ALTER TABLE public.idocs ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p ON public.idocs FOR SELECT USING (tenant_id = public.itenant());
                GRANT SELECT ON public.idocs TO pgrls_pm_auth;
            """)
        with pg_conn.transaction(force_rollback=True), pg_conn.cursor() as cur:
            cur.execute(_sql.SQL("SET LOCAL ROLE pgrls_pm_auth"))
            cur.execute("INSERT INTO public.imembers VALUES ('pgrls_pm_auth', 'b')")
            cur.execute("SELECT count(*) FROM public.idocs WHERE tenant_id <> 'a'")
            assert cur.fetchone()[0] == 1  # it became tenant b

        schema, grid = introspect_for_matrix(pg_conn, ["public"])
        m = build_matrix(schema, roles=("pgrls_pm_auth",), grid=grid, prove=True,
                         auth_functions={"public.itenant", "itenant"})
        p = _proof(m, "public.idocs", "pgrls_pm_auth")
        assert p.status == "unknown" and "public.imembers" in (p.detail or ""), p
    finally:
        drop()


@requires_docker
def test_live_a_request_header_policy_is_not_proven_but_a_tenant_setting_is(
    pg_conn: psycopg.Connection,
) -> None:
    """Postgres stores the setting name as 'name'::text: a header read in the
    policy itself is still caught, and an ordinary tenant setting stays
    PROVEN."""
    from pgrls.matrix import introspect_for_matrix  # noqa: PLC0415

    def drop() -> None:
        with pg_conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS public.hdr_e, public.hdr_d")
            cur.execute("DROP ROLE IF EXISTS pgrls_pm_auth")

    drop()
    try:
        with pg_conn.cursor() as cur:
            cur.execute("""
                REVOKE CREATE ON SCHEMA public FROM PUBLIC;
                CREATE ROLE pgrls_pm_auth NOLOGIN;
                CREATE TABLE public.hdr_e (id int, tenant_id text);
                CREATE TABLE public.hdr_d (id int, tenant_id text);
                ALTER TABLE public.hdr_e ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public.hdr_d ENABLE ROW LEVEL SECURITY;
                CREATE POLICY p ON public.hdr_e FOR SELECT
                  USING (tenant_id = current_setting('request.header.tenant', true));
                CREATE POLICY p ON public.hdr_d FOR SELECT
                  USING (tenant_id = current_setting('app.tenant_id', true));
                GRANT SELECT ON public.hdr_e, public.hdr_d TO pgrls_pm_auth;
            """)
        schema, grid = introspect_for_matrix(pg_conn, ["public"])
        m = build_matrix(schema, roles=("pgrls_pm_auth",), grid=grid, prove=True)
        e = _proof(m, "public.hdr_e", "pgrls_pm_auth")
        assert e.status == "unknown" and "request.header.tenant" in (e.detail or ""), e
        assert _proof(m, "public.hdr_d", "pgrls_pm_auth").status == "proven"
    finally:
        with pg_conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS public.hdr_e, public.hdr_d")
            cur.execute("DROP OWNED BY pgrls_pm_auth")
        drop()
