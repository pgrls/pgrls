"""Tests for the offline schema-source CLI helpers and wiring."""
import io
import json

import pytest
from click.testing import CliRunner

from pgrls.cli import _resolve_offline_schema
# Confirm ToolError's module first: `grep -n "class ToolError" src/pgrls/*.py`
from pgrls.cli import main, ToolError  # re-exported in cli; adjust if needed

DOCS_DDL = """
CREATE TABLE public.docs (id uuid, tenant_id uuid, body text);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT TO anon
  USING (auth.uid() IS NULL OR tenant_id = auth.uid());
"""


def test_resolve_returns_none_when_no_offline_flag():
    assert _resolve_offline_schema(
        sql_file=(), snapshot=None, schemas_csv=None, command="lint"
    ) is None


def test_resolve_reads_sql_file(tmp_path):
    f = tmp_path / "schema.sql"
    f.write_text(DOCS_DDL)
    schema, source = _resolve_offline_schema(
        sql_file=(str(f),), snapshot=None, schemas_csv=None, command="lint"
    )
    assert source == "sql"
    assert any(t.name == "docs" for t in schema.tables)


def test_resolve_concatenates_multiple_files_in_order(tmp_path):
    a = tmp_path / "a.sql"
    a.write_text("CREATE TABLE public.docs (id uuid);\n")
    b = tmp_path / "b.sql"
    b.write_text("ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n")
    schema, _ = _resolve_offline_schema(
        sql_file=(str(a), str(b)), snapshot=None, schemas_csv=None, command="lint"
    )
    docs = next(t for t in schema.tables if t.name == "docs")
    assert docs.rls_enabled is True  # the ALTER in b attached to the CREATE in a


def test_resolve_reads_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(DOCS_DDL))
    schema, source = _resolve_offline_schema(
        sql_file=("-",), snapshot=None, schemas_csv=None, command="lint"
    )
    assert source == "sql" and any(t.name == "docs" for t in schema.tables)


def test_resolve_rejects_both_sources(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(DOCS_DDL)
    with pytest.raises(ToolError):
        _resolve_offline_schema(
            sql_file=(str(f),), snapshot=str(f), schemas_csv=None, command="lint"
        )


def test_resolve_bad_sql_is_toolerror(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("this is not sql;;;"))
    with pytest.raises(ToolError):
        _resolve_offline_schema(
            sql_file=("-",), snapshot=None, schemas_csv=None, command="lint"
        )


def test_resolve_rejects_oversize_input(monkeypatch):
    huge = "-- x\n" * (3 * 1024 * 1024)  # > 8 MiB
    monkeypatch.setattr("sys.stdin", io.StringIO(huge))
    with pytest.raises(ToolError):
        _resolve_offline_schema(
            sql_file=("-",), snapshot=None, schemas_csv=None, command="lint"
        )


def test_resolve_emits_warning_to_stderr(tmp_path, capsys):
    f = tmp_path / "s.sql"
    f.write_text(DOCS_DDL)
    _resolve_offline_schema(
        sql_file=(str(f),), snapshot=None, schemas_csv=None, command="lint"
    )
    err = capsys.readouterr().err
    assert "no live database" in err.lower() or "not a proof" in err.lower()


# ---------------------------------------------------------------------------
# CLI integration tests: lint offline wiring
# ---------------------------------------------------------------------------

SEC004_DDL = DOCS_DDL


def test_lint_sql_file_finds_sec004(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(SEC004_DDL)
    res = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--format", "json"]
    )
    payload = json.loads(res.stdout)
    assert any(v["rule_id"] == "SEC004" for v in payload["violations"])
    assert payload["schema_source"] == "sql"
    assert "SEC016" in payload["skipped_rules"]


def test_lint_stdin(tmp_path):
    res = CliRunner().invoke(
        main, ["lint", "--sql-file", "-", "--format", "json"], input=SEC004_DDL
    )
    assert any(v["rule_id"] == "SEC004" for v in json.loads(res.stdout)["violations"])


def test_lint_reports_skipped_on_stderr(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(SEC004_DDL)
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(f)])
    assert "skipped" in res.stderr.lower() and "SEC016" in res.stderr


def test_lint_snapshot_skips_and_reports(tmp_path):
    """Lint via --snapshot: skip notice fires on stderr; JSON includes coverage keys."""
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql(SEC004_DDL).to_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")

    # Text output: stderr skip notice fires and mentions a known catalog rule.
    res_text = CliRunner().invoke(
        main, ["lint", "--snapshot", str(path)]
    )
    assert "skipped" in res_text.stderr.lower()
    assert "SEC016" in res_text.stderr

    # JSON output: coverage keys are present.
    res_json = CliRunner().invoke(
        main, ["lint", "--snapshot", str(path), "--format", "json"]
    )
    payload = json.loads(res_json.stdout)
    assert payload["schema_source"] == "snapshot"
    assert "SEC016" in payload["skipped_rules"]


def test_lint_require_full_coverage_fails_offline(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text("CREATE TABLE public.t (id int);\n")
    res = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--require-full-coverage"]
    )
    assert res.exit_code != 0
    assert "coverage" in res.stderr.lower()


def test_lint_offline_conflicts_with_database_url(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(SEC004_DDL)
    res = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--database-url", "postgres://x/y"]
    )
    assert res.exit_code != 0 and "one schema source" in res.stderr.lower()


def test_lint_offline_conflicts_with_migrations(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(SEC004_DDL)
    mig = tmp_path / "m"
    mig.mkdir()
    res = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--migrations", str(mig)]
    )
    assert res.exit_code != 0 and "one schema source" in res.stderr.lower()


def test_lint_live_json_unchanged_has_no_coverage_keys():
    # Backward-compat: a non-offline json payload must NOT gain the new keys.
    from pgrls.formatters.json import format_json

    assert "schema_source" not in json.loads(format_json([]))
