"""Unit tests for `pgrls matrix` — the effective access matrix."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import psycopg
import pytest
from click.testing import CliRunner

from pgrls.cli import main
from pgrls.introspect import introspect
from pgrls.matrix import (
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
    schema = Schema(tables=(_table("t", rls=True, policies=(_policy(),)),))
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
    )
    assert _cell(build_matrix(schema), "public.t", "SELECT", "admin").verdict == "denied"


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
    m = build_matrix(Schema(tables=(t,)), roles=("reader",))
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
        )
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
            _table("a", rls=False, grants=(_grant(),)),  # 4 open (one per command)
            _table("b", rls=True),  # 4 denied (no grant) x 3 roles
        )
    )
    s = build_matrix(schema).summary
    assert s["open"] + s["denied"] + s["conditional"] == s["cells"]
    assert s["cells"] == s["tables"] * len(("S", "I", "U", "D")) * s["roles"]


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
            )
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
        "tables", "roles", "cells", "open", "denied", "conditional"
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
    # header + separator + (1 table x 4 commands) = 6 rows, all the same width.
    assert len(pipe_rows) == 6
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
    cell = _cell(build_matrix(schema), "public.flat", "SELECT", "anon")
    # anon inherits the PUBLIC grant; RLS off → open with the RLS-off note.
    assert cell.verdict == "open"
    assert cell.note == "RLS off"
