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
    ExercisedTuple,
    build_coverage,
    exercised_from_sql,
    is_policy_covered,
    load_artifact,
    render,
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


def test_exercised_from_sql_non_dml_and_parse_failure() -> None:
    assert exercised_from_sql("CREATE TABLE x (id int)") == []
    assert exercised_from_sql("SET LOCAL ROLE admin") == []
    assert exercised_from_sql("this is not valid sql ;;;") == []


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
