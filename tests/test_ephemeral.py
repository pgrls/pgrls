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


# --- guard / error-handling regressions (no Docker) ------------------------


def test_lint_migrations_ignores_ambient_database_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An ambient $DATABASE_URL must NOT trip the conflict guard — that is the
    # headline CI setup. With an empty dir we reach (and fail at) layout
    # resolution, proving the conflict guard did not fire on the env var.
    monkeypatch.setenv("DATABASE_URL", "postgres://env/db")
    res = CliRunner().invoke(main, ["lint", "--migrations", str(tmp_path)])
    assert res.exit_code != 0
    assert "one schema source" not in res.output
    assert "no .sql migrations" in res.output


def test_lint_supabase_conflicts_with_explicit_database_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with CliRunner().isolated_filesystem(temp_dir=tmp_path):
        res = CliRunner().invoke(
            main, ["lint", "--supabase", "--database-url", "postgres://x"]
        )
    assert res.exit_code != 0
    assert "one schema source" in res.output


def test_non_utf8_migration_clean_error(tmp_path: Path) -> None:
    pytest.importorskip("testcontainers")  # need to reach the read loop
    f = tmp_path / "001.sql"
    f.write_bytes(b"-- caf\xe9\nCREATE TABLE t (id int);\n")  # 0xe9 = Latin-1 é
    with pytest.raises(ephemeral.EphemeralError, match="cannot read"):
        ephemeral.build_schema_from_migrations(sql_files=[f], schemas=["public"])


# --- role provisioning + diagnostics, Docker-gated -------------------------


@requires_docker
def test_supabase_roles_provisioned(tmp_path: Path) -> None:
    # A FOR SELECT TO authenticated policy only applies if `authenticated`
    # exists and auth.uid() resolves — regression for the DO-block param crash.
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE public.docs (id uuid PRIMARY KEY, owner_id uuid);\n"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs FOR SELECT TO authenticated "
        "USING (owner_id = auth.uid());\n",
        encoding="utf-8",
    )
    schema = ephemeral.build_schema_from_migrations(
        sql_files=[tmp_path / "001.sql"],
        schemas=["public"],
        provision_supabase=True,
    )
    assert any(t.name == "docs" for t in schema.tables)


@requires_docker
def test_create_role_provisioned(tmp_path: Path) -> None:
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE public.t (id int);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.t TO app_user USING (true);\n",
        encoding="utf-8",
    )
    schema = ephemeral.build_schema_from_migrations(
        sql_files=[tmp_path / "001.sql"],
        schemas=["public"],
        extra_roles=("app_user",),
    )
    assert any(t.name == "t" for t in schema.tables)


@requires_docker
def test_failing_migration_names_the_file(tmp_path: Path) -> None:
    from pgrls.migrations_layout import resolve_plan

    (tmp_path / "20240101_init").mkdir()
    (tmp_path / "20240101_init" / "migration.sql").write_text(
        "CREATE TABLE public.a (id int);", encoding="utf-8"
    )
    (tmp_path / "20240202_bad").mkdir()
    (tmp_path / "20240202_bad" / "migration.sql").write_text(
        "THIS IS NOT SQL;", encoding="utf-8"
    )
    plan = resolve_plan(tmp_path, layout="prisma")
    # Prisma basenames are all "migration.sql" — the error must name the dir.
    with pytest.raises(ephemeral.EphemeralError, match="20240202_bad"):
        ephemeral.build_schema_from_migrations(
            sql_files=plan.files, schemas=["public"]
        )


def test_lint_ephemeral_flags_require_migrations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Ephemeral-only flags without --migrations/--supabase must error, not
    # silently lint the live DB (or give a baffling "no database" message).
    monkeypatch.delenv("DATABASE_URL", raising=False)
    for args in (
        ["lint", "--create-role", "app_user"],
        ["lint", "--migrations-layout", "glob"],
        ["lint", "--pg-image", "postgres:16"],
    ):
        res = CliRunner().invoke(main, args)
        assert res.exit_code != 0, args
        assert "ephemeral build" in res.output, args


@requires_docker
def test_create_role_public_is_skipped(tmp_path: Path) -> None:
    # `public` is a reserved pseudo-role; CREATE ROLE public would fail. The
    # filter must drop it case-insensitively.
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE public.t (id int);", encoding="utf-8"
    )
    schema = ephemeral.build_schema_from_migrations(
        sql_files=[tmp_path / "001.sql"],
        schemas=["public"],
        extra_roles=("public", "PUBLIC"),
    )
    assert any(t.name == "t" for t in schema.tables)


@requires_docker
def test_bad_schema_surfaces_real_error(tmp_path: Path) -> None:
    # A --schemas typo must surface introspect's real message, not the
    # misleading "Is Docker running?" container hint.
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE public.t (id int);", encoding="utf-8"
    )
    with pytest.raises(ephemeral.EphemeralError) as ei:
        ephemeral.build_schema_from_migrations(
            sql_files=[tmp_path / "001.sql"], schemas=["does_not_exist"]
        )
    msg = str(ei.value)
    assert "Docker" not in msg
    assert "does_not_exist" in msg


def test_supabase_honors_explicit_glob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    res = CliRunner().invoke(
        main,
        [
            "lint", "--supabase", "--migrations", str(tmp_path),
            "--migrations-glob", "sub/*.sql",
        ],
    )
    assert res.exit_code != 0
    # the glob layout was used, not silently overridden to supabase
    assert "matched no files" in res.output


def test_supabase_honors_explicit_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    res = CliRunner().invoke(
        main,
        [
            "lint", "--supabase", "--migrations", str(tmp_path),
            "--migrations-layout", "flyway",
        ],
    )
    assert res.exit_code != 0
    assert "Flyway" in res.output  # flyway resolver ran, not supabase


@requires_docker
def test_bare_create_extension_applies(tmp_path: Path) -> None:
    # A bare CREATE EXTENSION (no IF NOT EXISTS) must apply once, not collide
    # with a pre-install.
    (tmp_path / "001.sql").write_text(
        "CREATE EXTENSION pgcrypto;\nCREATE TABLE public.t (id int);",
        encoding="utf-8",
    )
    schema = ephemeral.build_schema_from_migrations(
        sql_files=[tmp_path / "001.sql"], schemas=["public"]
    )
    assert any(t.name == "t" for t in schema.tables)


@requires_docker
def test_create_index_concurrently_applies(tmp_path: Path) -> None:
    # CONCURRENTLY can't run in the implicit multi-statement transaction; the
    # engine must retry the file statement-by-statement.
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE public.t (id int);\n"
        "CREATE INDEX CONCURRENTLY idx_t ON public.t (id);",
        encoding="utf-8",
    )
    schema = ephemeral.build_schema_from_migrations(
        sql_files=[tmp_path / "001.sql"], schemas=["public"]
    )
    assert any(t.name == "t" for t in schema.tables)
