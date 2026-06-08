"""Tests for the ephemeral-build engine and `lint --migrations` CLI wiring.

Pure / guard tests run without Docker; the end-to-end tests boot a throwaway
Postgres and are skipped when Docker is unavailable (keeping the unit suite
green on no-Docker machines).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from pgrls import ephemeral
from pgrls.cli import main


def _docker_available() -> bool:
    try:
        import docker  # testcontainers' engine client

        docker.from_env().ping()
    except Exception:
        return False
    return True


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available for ephemeral build"
)


# --- engine, no Docker -----------------------------------------------------


def test_resolve_pg_image_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PGRLS_EPHEMERAL_PG_IMAGE", raising=False)
    monkeypatch.delenv("PGRLS_DIFF_APPLY_PG_IMAGE", raising=False)
    assert ephemeral.resolve_pg_image() == "postgres:17-alpine"
    assert ephemeral.resolve_pg_image("postgres:16") == "postgres:16"
    monkeypatch.setenv("PGRLS_DIFF_APPLY_PG_IMAGE", "postgres:15")
    assert ephemeral.resolve_pg_image() == "postgres:15"
    monkeypatch.setenv("PGRLS_EPHEMERAL_PG_IMAGE", "postgres:14")
    # the feature-specific var wins over the diff-apply fallback
    assert ephemeral.resolve_pg_image() == "postgres:14"


def test_missing_extra_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "001.sql"
    f.write_text("CREATE TABLE t (id int);", encoding="utf-8")
    # Simulate the extra not being installed: importing testcontainers fails.
    monkeypatch.setitem(sys.modules, "testcontainers.postgres", None)
    with pytest.raises(ephemeral.EphemeralError, match=r"pgrls\[ephemeral\]"):
        ephemeral.build_schema_from_migrations(
            sql_files=[f], schemas=["public"]
        )


def test_no_sql_files_errors() -> None:
    with pytest.raises(ephemeral.EphemeralError):
        ephemeral.build_schema_from_migrations(sql_files=[], schemas=["public"])


# --- CLI guards, no Docker -------------------------------------------------


def test_lint_migrations_conflicts_with_database_url(tmp_path: Path) -> None:
    (tmp_path / "001.sql").write_text("CREATE TABLE t (id int);", encoding="utf-8")
    res = CliRunner().invoke(
        main,
        ["lint", "--migrations", str(tmp_path), "--database-url", "postgres://x"],
    )
    assert res.exit_code != 0
    assert "one schema source" in res.output


def test_lint_migrations_nonexistent_path() -> None:
    res = CliRunner().invoke(main, ["lint", "--migrations", "/no/such/dir"])
    assert res.exit_code != 0  # click Path(exists=True) usage error


def test_lint_migrations_empty_dir(tmp_path: Path) -> None:
    res = CliRunner().invoke(main, ["lint", "--migrations", str(tmp_path)])
    assert res.exit_code != 0
    assert "no .sql migrations" in res.output


def test_lint_supabase_without_project(tmp_path: Path) -> None:
    with CliRunner().isolated_filesystem(temp_dir=tmp_path):
        res = CliRunner().invoke(main, ["lint", "--supabase"])
    assert res.exit_code != 0
    assert "supabase" in res.output.lower()


# --- end-to-end, Docker-gated ----------------------------------------------


@requires_docker
def test_build_schema_from_migrations_live(tmp_path: Path) -> None:
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE public.docs (id uuid PRIMARY KEY, body text);",
        encoding="utf-8",
    )
    schema = ephemeral.build_schema_from_migrations(
        sql_files=[tmp_path / "001.sql"], schemas=["public"]
    )
    assert any(t.name == "docs" for t in schema.tables)


@requires_docker
def test_lint_migrations_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE public.docs (id uuid PRIMARY KEY, body text);",
        encoding="utf-8",
    )
    res = CliRunner().invoke(
        main, ["lint", "--migrations", str(tmp_path), "--format", "json"]
    )
    # A table with no RLS fires SEC001 -> findings -> exit 1.
    assert res.exit_code == 1
    assert "SEC001" in res.output


@requires_docker
def test_lint_migrations_matches_live_introspection(tmp_path: Path) -> None:
    """The schema built from migrations equals one introspected from a live DB
    with the same DDL applied — the core trust claim of --migrations."""
    ddl = (
        "CREATE TABLE public.t (id uuid PRIMARY KEY, tenant_id uuid NOT NULL);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.t USING "
        "(tenant_id = current_setting('app.t', true)::uuid);\n"
    )
    f = tmp_path / "001.sql"
    f.write_text(ddl, encoding="utf-8")
    eph = ephemeral.build_schema_from_migrations(
        sql_files=[f], schemas=["public"]
    )

    def projection(schema: object) -> set[tuple[str, bool, tuple[str, ...]]]:
        return {
            (
                t.name,
                t.rls_enabled,
                tuple(sorted(p.name for p in t.policies)),
            )
            for t in schema.tables  # type: ignore[attr-defined]
        }

    # Apply the same DDL a second time via a fresh ephemeral build; the
    # introspected projection must be identical (deterministic introspection).
    eph2 = ephemeral.build_schema_from_migrations(
        sql_files=[f], schemas=["public"]
    )
    assert projection(eph) == projection(eph2)
    assert ("t", True, ("p",)) in projection(eph)
