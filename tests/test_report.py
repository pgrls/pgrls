"""Unit tests for `pgrls report` — the RLS posture summary."""
from __future__ import annotations

import json

from click.testing import CliRunner

from pgrls.cli import main
from pgrls.model import Policy, Schema, Table
from pgrls.report import (
    build_report,
    render_json,
    render_markdown,
    render_text,
)


def _policy(permissive: bool = True, name: str = "p") -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=("public",),
        using_sql="true",
        with_check_sql=None,
    )


def _table(
    name: str,
    *,
    rls: bool,
    force: bool,
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
    )


def test_status_precedence() -> None:
    schema = Schema(
        tables=(
            # RLS off, but has policies → still "rls-off" (dormant).
            _table("off", rls=False, force=True, policies=(_policy(),)),
            _table("nopol", rls=True, force=True, policies=()),
            _table("unforced", rls=True, force=False, policies=(_policy(),)),
            _table("good", rls=True, force=True, policies=(_policy(),)),
        )
    )
    statuses = {t.qualified_name: t.status for t in build_report(schema).tables}
    assert statuses["public.off"] == "rls-off"
    assert statuses["public.nopol"] == "no-policies"
    assert statuses["public.unforced"] == "not-forced"
    assert statuses["public.good"] == "protected"


def test_partition_child_covered_by_rls_parent() -> None:
    # Postgres doesn't propagate relrowsecurity to partition children,
    # but queries through the parent apply its policies — so a child of
    # an RLS-enabled parent is "covered-by-parent", not "rls-off"
    # (mirrors how SEC001 skips such children).
    parent = _table("events", rls=True, force=True, policies=(_policy(),))
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    rep = build_report(Schema(tables=(parent, child)))
    statuses = {t.qualified_name: t.status for t in rep.tables}
    assert statuses["public.events"] == "protected"
    assert statuses["public.events_2026"] == "covered-by-parent"
    assert rep.summary["status_covered_by_parent"] == 1


def test_partition_child_rls_off_when_parent_has_no_rls() -> None:
    # No RLS-enabled ancestor → the child is genuinely "rls-off".
    parent = _table("events", rls=False, force=False)
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    statuses = {
        t.qualified_name: t.status
        for t in build_report(Schema(tables=(parent, child))).tables
    }
    assert statuses["public.events_2026"] == "rls-off"


def test_permissive_restrictive_counts() -> None:
    schema = Schema(
        tables=(
            _table(
                "t",
                rls=True,
                force=True,
                policies=(
                    _policy(True, "a"),
                    _policy(False, "b"),
                    _policy(True, "c"),
                ),
            ),
        )
    )
    [t] = build_report(schema).tables
    assert t.policy_count == 3
    assert t.permissive_count == 2
    assert t.restrictive_count == 1


def test_summary_aggregates() -> None:
    schema = Schema(
        tables=(
            _table("off", rls=False, force=False),
            _table("good", rls=True, force=True, policies=(_policy(),)),
        )
    )
    s = build_report(schema).summary
    assert s["tables"] == 2
    assert s["rls_enabled"] == 1
    assert s["forced"] == 1
    assert s["with_policies"] == 1
    assert s["status_rls_off"] == 1
    assert s["status_protected"] == 1


def test_tables_sorted_by_qualified_name() -> None:
    schema = Schema(
        tables=(
            _table("z", rls=True, force=True, policies=(_policy(),)),
            _table("a", rls=True, force=True, policies=(_policy(),)),
        )
    )
    names = [t.qualified_name for t in build_report(schema).tables]
    assert names == ["public.a", "public.z"]


def test_render_text_has_headers_rows_and_summary() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_text(build_report(schema))
    assert "TABLE" in out and "STATUS" in out and "POLICIES" in out
    assert "public.good" in out
    assert "protected" in out
    assert "1 table: 1 protected." in out  # pluralized, non-zero only


def test_render_text_empty_schema() -> None:
    assert "No tables found" in render_text(build_report(Schema(tables=())))


def test_render_json_shape() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    payload = json.loads(render_json(build_report(schema)))
    assert payload["summary"]["tables"] == 1
    row = payload["tables"][0]
    assert row["table"] == "public.good"
    assert row["status"] == "protected"
    assert row["rls_enabled"] is True
    assert row["force_rls"] is True
    assert row["policies"] == 1


def test_render_markdown_table() -> None:
    schema = Schema(
        tables=(_table("good", rls=True, force=True, policies=(_policy(),)),)
    )
    out = render_markdown(build_report(schema))
    assert "# RLS posture" in out
    assert "| Table | Status | RLS | FORCE | Policies |" in out
    assert "| public.good | protected | yes | yes | 1 |" in out


def test_report_cli_help() -> None:
    result = CliRunner().invoke(main, ["report", "--help"])
    assert result.exit_code == 0
    assert "RLS posture" in result.output


def test_report_cli_errors_without_database_url() -> None:
    # No --database-url and DATABASE_URL forced empty → ToolError exit 2.
    result = CliRunner().invoke(
        main, ["report"], env={"DATABASE_URL": ""}
    )
    assert result.exit_code == 2
    assert "No database connection" in result.output
