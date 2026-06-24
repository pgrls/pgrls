"""Tests for the offline schema-source CLI helpers and wiring."""
import io
import pytest

from pgrls.cli import _resolve_offline_schema
# Confirm ToolError's module first: `grep -n "class ToolError" src/pgrls/*.py`
from pgrls.cli import ToolError  # re-exported in cli; adjust if needed

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
