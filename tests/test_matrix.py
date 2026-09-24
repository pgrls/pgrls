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
            _table("a", rls=False, grants=(_grant(),)),  # 4 open (one per command)
            _table("b", rls=True),  # 4 denied (no grant) x 3 roles
        )
    )
    s = build_matrix(schema).summary
    assert s["open"] + s["denied"] + s["conditional"] + s["undecided"] == s["cells"]
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
    cell = _cell(build_matrix(schema), "public.flat", "SELECT", "anon")
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
    assert "4 undecided" in _summary_line(undecided)


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


def test_doors_never_touch_write_commands() -> None:
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


# --- live differential: every cell against a real SET ROLE session ------------
#
# Each matrix claim is checked against Postgres itself. The command runs under
# SET LOCAL ROLE in a rolled-back transaction: a SELECT count, two INSERTs (one
# row a tenant predicate admits, one it rejects), and UPDATE / DELETE row
# counts. SELECT takes the widest of the direct read and every door — two
# definer views, an invoker view, two SECURITY DEFINER functions. This is the
# test that caught policies being applied through NOINHERIT edges. NOINHERIT
# comes from the role attribute so the test runs on PG15, which has no
# per-grant INHERIT option.

_MXD_ROLES = (
    "mxd_pub", "mxd_grp", "mxd_mid", "mxd_inh", "mxd_noinh", "mxd_nested",
    "mxd_owner", "mxd_owner_m", "mxd_owner_m_noinh", "mxd_su", "mxd_byp",
    "mxd_byp_nogrant", "mxd_rad", "mxd_wad", "mxd_colr", "mxd_colw",
    "mxd_door_owner", "mxd_vowner", "mxd_vuser", "mxd_invuser", "mxd_fnuser",
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
GRANT mxd_grp TO mxd_inh, mxd_noinh, mxd_mid;
GRANT mxd_mid TO mxd_nested;
GRANT mxd_owner TO mxd_owner_m, mxd_owner_m_noinh;
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
GRANT SELECT ON t_open TO mxd_grp;

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
GRANT SELECT ON t_bypass TO mxd_byp;

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

SELECT pg_temp.mk('t_nested');
GRANT SELECT ON t_nested TO mxd_mid;
"""

# Each door, and the base table whose rows it returns.
_MXD_DOORS = {
    "v_def": "public.t_door",
    "v_inv": "public.t_door",
    "f_door()": "public.t_door",
    "v_def2": "public.t_door_filtered",
    "f_pub()": "public.t_fn_pub",
}
_MXD_RANK = {"all": 3, "some": 1, "none": 0}
_MXD_VERDICT_RANK = {"open": 3, "undecided": 2, "conditional": 1, "denied": 0}


def _mxd_run(conn: psycopg.Connection, role: str, stmt: str) -> tuple[bool, int]:
    """Run `stmt` as `role` with app.tenant = 'a', roll back, and return
    (succeeded, row count — the count(*) value for a SELECT)."""
    with conn.cursor() as cur:
        cur.execute("BEGIN")
        try:
            cur.execute("SET LOCAL app.tenant = 'a'")
            cur.execute(f'SET LOCAL ROLE "{role}"')
            cur.execute(stmt)
            n = cur.fetchone()[0] if cur.description else cur.rowcount
            return True, n
        except psycopg.Error:
            return False, 0
        finally:
            cur.execute("ROLLBACK")


@requires_docker
def test_every_cell_matches_a_live_set_role_session(pg_conn: psycopg.Connection) -> None:
    roles = ("PUBLIC",) + _MXD_ROLES[1:]
    as_db = {"PUBLIC": "mxd_pub"}  # a role with no memberships stands in for PUBLIC

    def reach(ok: bool, n: int, total: int) -> str:
        return "none" if not ok or n == 0 else ("all" if n == total else "some")

    with pg_conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS " + ", ".join(_MXD_ROLES))
    try:
        with pg_conn.cursor() as cur:
            cur.execute(_MXD_DDL)
        schema = introspect(pg_conn, schemas=["public"])
        m = build_matrix(schema, roles=roles)
        totals = {}
        with pg_conn.cursor() as cur:
            for t in {r.qualified_name for r in m.rows}:
                cur.execute(f"SELECT count(*) FROM {t}")
                totals[t] = cur.fetchone()[0]

        door_reach: dict[tuple[str, str], str] = {}
        for role in roles:
            for door, base in _MXD_DOORS.items():
                got = reach(*_mxd_run(pg_conn, as_db.get(role, role),
                                      f"SELECT count(*) FROM {door}"), totals[base])
                if _MXD_RANK[got] > _MXD_RANK[door_reach.get((role, base), "none")]:
                    door_reach[(role, base)] = got

        wrong = []
        for row in m.rows:
            total = totals[row.qualified_name]
            for role, cell in zip(m.roles, row.cells):
                db = as_db.get(role, role)
                t = row.qualified_name
                if row.command == "SELECT":
                    truth = reach(*_mxd_run(pg_conn, db, f"SELECT count(*) FROM {t}"), total)
                    door = door_reach.get((role, t), "none")
                    truth = max(truth, door, key=_MXD_RANK.__getitem__)
                elif row.command == "INSERT":
                    ins = f"INSERT INTO {t} (id, tenant_id, owner_name) VALUES "
                    good = _mxd_run(pg_conn, db, ins + "(100, 'a', current_user)")[0]
                    bad = _mxd_run(pg_conn, db, ins + "(101, 'zzz', 'nobody')")[0]
                    truth = "all" if good and bad else ("some" if good or bad else "none")
                else:
                    stmt = (f"UPDATE {t} SET note = 'x'" if row.command == "UPDATE"
                            else f"DELETE FROM {t}")
                    truth = reach(*_mxd_run(pg_conn, db, stmt), total)
                if _MXD_VERDICT_RANK[cell.verdict] != _MXD_RANK[truth]:
                    wrong.append((t, row.command, role, cell.verdict, truth))
        assert wrong == [], wrong
        # Not vacuous: every verdict a live schema can produce shows up.
        seen = {c.verdict for r in m.rows for c in r.cells}
        assert seen == {"open", "conditional", "denied"}, seen

        # The sensitive-columns section lists exactly what each role can read.
        readable = set()
        for role in roles:
            for relation, base in [(t, t) for t in totals] + list(_MXD_DOORS.items()):
                for col in ("email", "ssn"):
                    ok, n = _mxd_run(pg_conn, as_db.get(role, role),
                                     f"SELECT count({col}) FROM {relation}")
                    if ok and n:
                        readable.add((role, base, col))
        assert {(e.role, e.table, e.column) for e in m.exposures} == readable
    finally:
        # Roles are cluster-wide (two carry SUPERUSER / BYPASSRLS, which later
        # tests would see): drop every one that exists. DROP OWNED has no
        # IF EXISTS, and a failed DDL batch rolls back as one transaction.
        with pg_conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public")
            cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)",
                        (list(_MXD_ROLES),))
            existing = [r[0] for r in cur.fetchall()]
            if existing:
                cur.execute("DROP OWNED BY " + ", ".join(existing))
                cur.execute("DROP ROLE " + ", ".join(existing))
