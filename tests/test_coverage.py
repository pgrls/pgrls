"""Unit tests for `pgrls coverage` — the RLS test-coverage report."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pgrls.cli import main
from pgrls.coverage import (
    ARTIFACT_VERSION,
    CoverageData,
    CoverageReport,
    ExercisedTuple,
    PolicyCoverage,
    ambiguous_relation_names,
    build_coverage,
    exercised_from_sql,
    is_policy_covered,
    load_artifact,
    render,
    render_markdown,
    render_text,
    write_artifact,
)
from pgrls.model import Policy, Schema, Table

_AWARE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _policy(name: str, command: str, roles: tuple[str, ...]) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=roles,
        using_sql="true",
        with_check_sql=None,
    )


def _one_table_schema(*policies: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="invoices",
                rls_enabled=True,
                force_rls=True,
                policies=policies,
            ),
        )
    )


def _data(*tuples: ExercisedTuple) -> CoverageData:
    return CoverageData(exercised=frozenset(tuples))


# ---------- exercised_from_sql ----------


def test_exercised_from_sql_select() -> None:
    assert exercised_from_sql("SELECT id FROM invoices") == [
        (None, "invoices", "SELECT")
    ]


def test_exercised_from_sql_keeps_schema_qualifier() -> None:
    assert exercised_from_sql("SELECT 1 FROM public.invoices") == [
        ("public", "invoices", "SELECT")
    ]


def test_exercised_from_sql_write_commands() -> None:
    assert exercised_from_sql("INSERT INTO t (a) VALUES (1)") == [
        (None, "t", "INSERT")
    ]
    assert exercised_from_sql("UPDATE t SET a = 1") == [(None, "t", "UPDATE")]
    assert exercised_from_sql("DELETE FROM t WHERE a = 1") == [
        (None, "t", "DELETE")
    ]


def test_exercised_from_sql_insert_select_splits_target_and_source() -> None:
    # The write target is credited INSERT; the read source is SELECT.
    out = set(exercised_from_sql("INSERT INTO audit SELECT * FROM invoices"))
    assert out == {(None, "audit", "INSERT"), (None, "invoices", "SELECT")}


def test_exercised_from_sql_merge_credits_each_when_command() -> None:
    # MERGE is multi-command: the target gets EVERY command its WHEN
    # clauses perform (UPDATE + INSERT here), the source is a read.
    # Regression — a MERGE previously mapped to no command at all, so
    # it contributed zero coverage and HYG004 reported an exercised
    # write policy as uncovered.
    out = set(
        exercised_from_sql(
            "MERGE INTO t USING s ON t.id = s.id "
            "WHEN MATCHED THEN UPDATE SET x = 1 "
            "WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)"
        )
    )
    assert out == {
        (None, "t", "UPDATE"),
        (None, "t", "INSERT"),
        (None, "s", "SELECT"),
    }


def test_exercised_from_sql_non_dml_and_parse_failure() -> None:
    assert exercised_from_sql("CREATE TABLE x (id int)") == []
    assert exercised_from_sql("SET LOCAL ROLE admin") == []
    assert exercised_from_sql("this is not valid sql ;;;") == []


def test_exercised_from_sql_data_modifying_cte_credits_write_command() -> None:
    # The 0.7.1 fix: a writable CTE's target gets its OWN command, not the
    # outer SELECT — Postgres applies the write-command policy to it, so
    # crediting it as a SELECT read would falsely cover the SELECT policy.
    # The CTE alias (`d`) is not a real relation and is dropped.
    assert set(
        exercised_from_sql(
            "WITH d AS (DELETE FROM secret RETURNING *) SELECT * FROM d"
        )
    ) == {(None, "secret", "DELETE")}
    assert set(
        exercised_from_sql(
            "WITH u AS (UPDATE accts SET x = 1 RETURNING *) "
            "SELECT count(*) FROM u"
        )
    ) == {(None, "accts", "UPDATE")}


def test_exercised_from_sql_select_into_excludes_created_table() -> None:
    # `SELECT … INTO newt` creates newt (a write), it does not read it;
    # only the source is a SELECT read.
    assert exercised_from_sql("SELECT * INTO newt FROM src") == [
        (None, "src", "SELECT")
    ]


def test_exercised_from_sql_sibling_and_nested_cte_aliases_dropped() -> None:
    # A CTE can reference an earlier sibling; that alias is not a real
    # relation and must not leak as a phantom SELECT (it could otherwise
    # false-cover a real table sharing the alias name).
    assert (
        exercised_from_sql(
            "WITH a AS (SELECT 1 AS x), b AS (SELECT * FROM a) SELECT * FROM b"
        )
        == []
    )
    assert exercised_from_sql(
        "WITH a AS (DELETE FROM secret RETURNING id), "
        "b AS (SELECT * FROM a) SELECT * FROM b"
    ) == [(None, "secret", "DELETE")]
    # Nested WITH inside a CTE body — inner alias dropped via inherited scope.
    assert (
        exercised_from_sql(
            "WITH o AS (WITH i AS (SELECT 1) SELECT * FROM i) SELECT * FROM o"
        )
        == []
    )
    # A real, schema-qualified table that happens to share an alias name is
    # NOT dropped (only bare references to alias names are).
    assert exercised_from_sql("WITH a AS (SELECT 1) SELECT * FROM public.a") == [
        ("public", "a", "SELECT")
    ]


# ---------- is_policy_covered ----------


def test_covered_requires_matching_command() -> None:
    table = _one_table_schema().tables[0]
    sel = _policy("sel", "SELECT", ("authenticated",))
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    assert is_policy_covered(table, sel, data) is True
    delete = _policy("del", "DELETE", ("authenticated",))
    assert is_policy_covered(table, delete, data) is False


def test_all_command_policy_covered_by_any_command() -> None:
    table = _one_table_schema().tables[0]
    p = _policy("all", "ALL", ("authenticated",))
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "DELETE"))
    assert is_policy_covered(table, p, data) is True


def test_role_must_match_or_be_public() -> None:
    table = _one_table_schema().tables[0]
    admin = _policy("a", "SELECT", ("admin",))
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    assert is_policy_covered(table, admin, data) is False
    public = _policy("p", "SELECT", ("PUBLIC",))
    assert is_policy_covered(table, public, data) is True


def test_schema_qualifier_must_match_when_present() -> None:
    table = _one_table_schema().tables[0]  # schema=public
    p = _policy("p", "SELECT", ("PUBLIC",))
    # A tuple captured against a different schema must not match.
    other = _data(ExercisedTuple("other", "invoices", "r", "SELECT"))
    assert is_policy_covered(table, p, other) is False
    # A bare (schema-less) tuple matches by relation name.
    bare = _data(ExercisedTuple(None, "invoices", "r", "SELECT"))
    assert is_policy_covered(table, p, bare) is True


# ---------- multi-tenant ambiguity (no false-covered) ----------


def _two_tenant_schema() -> Schema:
    def pol() -> Policy:
        return _policy("isolation", "SELECT", ("app_user",))

    return Schema(
        tables=(
            Table("tenant_a", "events", True, True, (pol(),)),  # type: ignore[arg-type]
            Table("tenant_b", "events", True, True, (pol(),)),  # type: ignore[arg-type]
        )
    )


def test_ambiguous_relation_names_detects_cross_schema_dupes() -> None:
    assert ambiguous_relation_names(_two_tenant_schema()) == frozenset({"events"})
    assert ambiguous_relation_names(_one_table_schema(_policy("p", "SELECT", ("r",)))) == frozenset()


def test_unqualified_tuple_does_not_cross_credit_same_named_tables() -> None:
    # The bug guard: a test that exercised only tenant_a.events via an
    # unqualified `FROM events` (schema=None) must NOT mark tenant_b's
    # same-named policy covered. Over-credit is the dangerous direction.
    schema = _two_tenant_schema()
    data = _data(ExercisedTuple(None, "events", "app_user", "SELECT"))
    covered = {p.location: p.covered for p in build_coverage(schema, data).policies}
    assert covered == {
        "tenant_a.events.isolation": False,
        "tenant_b.events.isolation": False,
    }


def test_qualified_tuple_credits_only_its_schema() -> None:
    schema = _two_tenant_schema()
    data = _data(ExercisedTuple("tenant_a", "events", "app_user", "SELECT"))
    covered = {p.location: p.covered for p in build_coverage(schema, data).policies}
    assert covered == {
        "tenant_a.events.isolation": True,
        "tenant_b.events.isolation": False,
    }


def test_unique_name_still_covered_by_unqualified_tuple() -> None:
    # No regression for the common single-schema case: an unambiguous bare
    # name is still credited by an unqualified tuple.
    schema = _one_table_schema(_policy("sel", "SELECT", ("app_user",)))
    data = _data(ExercisedTuple(None, "invoices", "app_user", "SELECT"))
    assert build_coverage(schema, data).policies[0].covered is True


# ---------- artifact round-trip ----------


def test_artifact_round_trip(tmp_path) -> None:
    path = str(tmp_path / "cov.json")
    tuples = [
        ExercisedTuple("public", "invoices", "authenticated", "SELECT"),
        ExercisedTuple(None, "orders", "PUBLIC", "INSERT"),
    ]
    write_artifact(path, tuples, generated_at=_AWARE)
    loaded = load_artifact(path)
    assert loaded.exercised == frozenset(tuples)
    raw = json.loads((tmp_path / "cov.json").read_text())
    assert raw["pgrls_coverage_version"] == ARTIFACT_VERSION
    assert raw["generated_at"] == "2026-01-01T12:00:00Z"


def test_artifact_rejects_unknown_version() -> None:
    try:
        CoverageData.from_dict({"pgrls_coverage_version": 999, "exercised": []})
    except ValueError as exc:
        assert "version" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")


def test_artifact_rejects_malformed_shape() -> None:
    # Structurally wrong but valid JSON must raise ValueError (so the CLI
    # turns it into a clean ToolError), never a raw KeyError/AttributeError.
    bad_payloads = [
        [1, 2, 3],  # top-level not an object
        {"pgrls_coverage_version": ARTIFACT_VERSION, "exercised": [42]},  # row not a dict
        {
            "pgrls_coverage_version": ARTIFACT_VERSION,
            "exercised": [{"schema": "public"}],  # row missing required keys
        },
    ]
    for payload in bad_payloads:
        try:
            CoverageData.from_dict(payload)  # type: ignore[arg-type]
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected ValueError for {payload!r}")


def test_cli_coverage_malformed_artifact_errors_clearly(tmp_path) -> None:
    path = tmp_path / "cov.json"
    path.write_text('{"pgrls_coverage_version": 1, "exercised": [42]}')
    res = _run_coverage(tmp_path, ["--coverage", str(path)], schema=Schema(tables=()))
    assert res.exit_code == 2
    assert "Cannot read coverage artifact" in res.output
    assert res.exception is None or isinstance(res.exception, SystemExit)


# ---------- build_coverage + summary ----------


def test_build_coverage_summary() -> None:
    schema = _one_table_schema(
        _policy("sel", "SELECT", ("authenticated",)),
        _policy("del", "DELETE", ("admin",)),
    )
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    report = build_coverage(schema, data)
    s = report.summary
    assert (s["policies"], s["covered"], s["uncovered"]) == (2, 1, 1)
    assert s["coverage_pct"] == 50.0
    locations = {p.location: p.covered for p in report.policies}
    assert locations == {
        "public.invoices.sel": True,
        "public.invoices.del": False,
    }


def test_summary_no_policies_is_fully_covered() -> None:
    report = build_coverage(Schema(tables=()), _data())
    assert report.summary == {
        "policies": 0,
        "covered": 0,
        "uncovered": 0,
        "coverage_pct": 100.0,
    }


# ---------- renderers ----------


def test_all_renderers_agree_on_counts() -> None:
    schema = _one_table_schema(
        _policy("sel", "SELECT", ("authenticated",)),
        _policy("del", "DELETE", ("admin",)),
    )
    data = _data(ExercisedTuple(None, "invoices", "authenticated", "SELECT"))
    report = build_coverage(schema, data)

    text = render(report, "text")
    assert "1 covered, 1 uncovered (50.0%)" in text

    payload = json.loads(render(report, "json"))
    assert payload["summary"]["coverage_pct"] == 50.0
    assert len(payload["policies"]) == 2

    md = render(report, "markdown")
    assert md.startswith("# RLS test coverage")

    html = render(report, "html")
    assert html.startswith("<!DOCTYPE html>")
    assert "50.0%" in html


def _one_policy_report(*, policy: str, roles: tuple[str, ...]) -> CoverageReport:
    return CoverageReport(
        policies=(
            PolicyCoverage(
                schema="public",
                table="invoices",
                policy=policy,
                command="SELECT",  # type: ignore[arg-type]
                roles=roles,
                covered=False,
            ),
        )
    )


def _coverage_md_data_rows(out: str) -> list[str]:
    return [
        ln
        for ln in out.splitlines()
        if ln.startswith("|") and "---" not in ln and "| Policy |" not in ln
    ]


def test_render_markdown_pipe_in_location_and_role_no_corruption() -> None:
    # A `|` in the policy name (→ location) or in a role name must be
    # escaped so it doesn't add a phantom GFM column. Regression for
    # audit finding #16.
    report = _one_policy_report(policy="pol|icy", roles=("ro|le", "two"))
    out = render_markdown(report)
    data_rows = _coverage_md_data_rows(out)
    assert len(data_rows) == 1
    row = data_rows[0]
    assert "public.invoices.pol\\|icy" in row
    assert "ro\\|le" in row
    # 4 columns → 5 unescaped pipe delimiters.
    assert row.replace("\\|", "").count("|") == 5


def test_render_markdown_newline_in_location_does_not_split_row() -> None:
    # Regression for #16: a `\n` in the location would end the GFM row
    # early. `safe_location` rewrites it to the two-char `\n` text.
    report = _one_policy_report(policy="pol\nicy", roles=("authenticated",))
    out = render_markdown(report)
    data_rows = _coverage_md_data_rows(out)
    assert len(data_rows) == 1
    assert "public.invoices.pol\\nicy" in data_rows[0]


def test_render_text_newline_in_location_and_role_no_split() -> None:
    # Regression for audit finding #23: a `\n` in the location or a
    # role name must not split the fixed-width text row.
    report = _one_policy_report(policy="pol\nicy", roles=("ro\nle", "two"))
    out = render_text(report)
    data_lines = [ln for ln in out.splitlines() if "invoices" in ln]
    assert len(data_lines) == 1
    assert "public.invoices.pol\\nicy" in data_lines[0]
    assert "ro\\nle,two" in data_lines[0]


# ---------- CLI command (mocked introspection) ----------


def _run_coverage(tmp_path, args, *, schema: Schema):
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=schema
    ):
        return CliRunner().invoke(
            main, ["coverage", "--database-url", "postgresql://x", *args]
        )


def test_cli_coverage_reports_and_fail_under(tmp_path) -> None:
    path = str(tmp_path / "cov.json")
    write_artifact(
        path,
        [ExercisedTuple(None, "invoices", "authenticated", "SELECT")],
        generated_at=_AWARE,
    )
    schema = _one_table_schema(
        _policy("sel", "SELECT", ("authenticated",)),
        _policy("del", "DELETE", ("admin",)),
    )
    # Plain report: exit 0, shows both policies.
    res = _run_coverage(tmp_path, ["--coverage", path, "--format", "json"], schema=schema)
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["summary"]["coverage_pct"] == 50.0
    # --fail-under above actual coverage → exit 1.
    res2 = _run_coverage(
        tmp_path, ["--coverage", path, "--fail-under", "80"], schema=schema
    )
    assert res2.exit_code == 1, res2.output
    assert "below --fail-under" in res2.output
    # --fail-under at/under actual coverage → exit 0.
    res3 = _run_coverage(
        tmp_path, ["--coverage", path, "--fail-under", "50"], schema=schema
    )
    assert res3.exit_code == 0, res3.output


def test_cli_lint_coverage_enables_hyg004(tmp_path) -> None:
    # The lint --coverage wiring: HYG004 is inert without the artifact and
    # fires on uncovered policies with it. Guards the inject path end-to-end.
    path = str(tmp_path / "cov.json")
    write_artifact(
        path,
        [ExercisedTuple(None, "invoices", "authenticated", "SELECT")],
        generated_at=_AWARE,
    )
    schema = _one_table_schema(
        _policy("sel", "SELECT", ("authenticated",)),
        _policy("del", "DELETE", ("admin",)),
    )
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=schema
    ):
        off = CliRunner().invoke(
            main,
            ["lint", "--database-url", "postgresql://x", "--rule", "HYG004"],
        )
        on = CliRunner().invoke(
            main,
            [
                "lint", "--database-url", "postgresql://x",
                "--rule", "HYG004", "--coverage", path,
            ],
        )
    assert "HYG004" not in off.output  # inert without the artifact
    # HYG004 is info severity, so it's reported but doesn't breach the
    # default fail-on threshold (exit 0) — gate via `--fail-on info` or
    # `pgrls coverage --fail-under` instead.
    assert "HYG004" in on.output
    assert "public.invoices.del" in on.output  # the uncovered policy
    assert "public.invoices.sel" not in on.output  # covered → not flagged


def test_cli_coverage_missing_artifact_errors(tmp_path) -> None:
    res = _run_coverage(
        tmp_path,
        ["--coverage", str(tmp_path / "nope.json")],
        schema=Schema(tables=()),
    )
    assert res.exit_code == 2
    assert "not found" in res.output
