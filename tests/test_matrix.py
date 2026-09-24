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
