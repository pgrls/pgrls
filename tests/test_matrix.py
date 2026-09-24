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


@pytest.mark.parametrize(("predicate", "dependent"), [
    ("owner_name = current_user", True),
    ("owner_name = session_user", True),
    ("pg_has_role('admin', 'MEMBER')", True),
    ("has_table_privilege('t', 'SELECT')", True),
    ("public.is_admin()", True),
    ("tenant_id = current_setting('app.tenant', true)", False),
    ("tenant_id = auth.uid()", False),
    ("((((", True),
])
def test_which_filters_depend_on_the_session(predicate: str, dependent: bool) -> None:
    from pgrls.access import _session_dependent  # noqa: PLC0415

    assert _session_dependent(predicate) is dependent


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
