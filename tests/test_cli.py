from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import main


def test_root_help_lists_lint():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "lint" in result.output


def test_lint_help_runs():
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--help"])
    assert result.exit_code == 0
    for flag in ("--database-url", "--config", "--schemas", "--fail-on"):
        assert flag in result.output


def test_root_version_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.0.1" in result.output


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_lint_against_known_bad_db_exits_nonzero(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "SEC001" in result.output
    assert "public.users" in result.output
    assert "public.orders" not in result.output


def test_lint_clean_db_exits_zero(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    assert "no issues" in result.output.lower()


def test_lint_missing_database_url_errors_clearly(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["lint"])
    assert result.exit_code != 0
    assert "DATABASE_URL" in result.output or "database-url" in result.output


def test_lint_disable_skips_rule(pg_url: str, apply_sql, tmp_path) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint]\ndisable = ["SEC001"]\n')
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code == 0, result.output
    assert "SEC001" not in result.output


def test_lint_schemas_flag_overrides_config(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE SCHEMA tenant;
        CREATE TABLE public.public_t (id INT);
        CREATE TABLE tenant.tenant_t (id INT);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--schemas", "tenant"]
    )
    assert "tenant.tenant_t" in result.output
    assert "public.public_t" not in result.output
