from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import _merge_overrides, _should_fail, main
from pgrls.config import Config
from pgrls.violations import Violation


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
    assert "0.0.2" in result.output


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_lint_against_known_bad_db_exits_nonzero(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "SEC001" in result.output
    assert "public.users" in result.output


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
    cfg.write_text('[lint]\ndisable = ["SEC001", "SEC003"]\n')
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
    assert result.exit_code == 1, result.output
    assert "tenant.tenant_t" in result.output
    assert "public.public_t" not in result.output


def test_lint_unknown_schema_errors_clearly(pg_url: str) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--schemas", "does_not_exist"]
    )
    assert result.exit_code != 0
    assert "does_not_exist" in result.output
    assert "Traceback" not in result.output


def test_lint_empty_schemas_errors_clearly(pg_url: str) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--schemas", ",,,"]
    )
    assert result.exit_code != 0
    assert "empty schema list" in result.output.lower()


def test_lint_bad_allowlist_type_errors_clearly(pg_url: str, tmp_path) -> None:
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC001]\nallowlist = "users"\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "allowlist" in result.output


def test_lint_allowlist_via_config_exempts_table(pg_url: str, apply_sql, tmp_path) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC001]\nallowlist = ["users"]\n'
        '[lint.rules.SEC003]\nallowlist = ["public.orders.orders_owner"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code == 0, result.output
    assert "SEC001" not in result.output


def test_lint_fail_on_info_flag_accepted(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--fail-on", "info"]
    )
    assert result.exit_code == 1, result.output
    assert "SEC001" in result.output


def _violation(severity: str) -> Violation:
    return Violation(
        rule_id="X",
        severity=severity,  # type: ignore[arg-type]
        title="t",
        message="m",
        location=None,
    )


def test_should_fail_returns_true_when_violation_meets_threshold() -> None:
    assert _should_fail([_violation("error")], threshold="error") is True
    assert _should_fail([_violation("error")], threshold="warning") is True
    assert _should_fail([_violation("error")], threshold="info") is True
    assert _should_fail([_violation("warning")], threshold="warning") is True
    assert _should_fail([_violation("warning")], threshold="info") is True
    assert _should_fail([_violation("info")], threshold="info") is True


def test_should_fail_returns_false_below_threshold() -> None:
    assert _should_fail([_violation("warning")], threshold="error") is False
    assert _should_fail([_violation("info")], threshold="warning") is False
    assert _should_fail([_violation("info")], threshold="error") is False
    assert _should_fail([], threshold="info") is False


def test_merge_overrides_cli_takes_precedence_over_config() -> None:
    config = Config(
        database_url="postgres://config",
        schemas=["config_schema"],
        disable=[],
        fail_on="error",
        rule_options={},
    )
    merged = _merge_overrides(
        config,
        database_url="postgres://cli",
        schemas_csv="cli_a,cli_b",
        fail_on="warning",
    )
    assert merged.database_url == "postgres://cli"
    assert merged.schemas == ["cli_a", "cli_b"]
    assert merged.fail_on == "warning"


def test_merge_overrides_falls_back_to_config_when_cli_missing() -> None:
    config = Config(
        database_url="postgres://config",
        schemas=["config_schema"],
        disable=["X"],
        fail_on="error",
        rule_options={"R": {"k": "v"}},
    )
    merged = _merge_overrides(
        config, database_url=None, schemas_csv=None, fail_on=None
    )
    assert merged.database_url == "postgres://config"
    assert merged.schemas == ["config_schema"]
    assert merged.fail_on == "error"
    assert merged.disable == ["X"]
    assert merged.rule_options == {"R": {"k": "v"}}


def test_introspect_populates_policy_using_ast(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT, tenant_id TEXT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.t
            FOR SELECT TO PUBLIC
            USING (tenant_id = current_setting('app.tenant_id'));
        """
    )
    import psycopg
    from pgrls.introspect import introspect

    with psycopg.connect(pg_url) as conn:
        schema = introspect(conn, schemas=["public"])

    table = next(t for t in schema.tables if t.name == "t")
    policy = table.policies[0]
    assert policy.using_sql is not None
    assert policy.using_ast is not None
    assert policy.with_check_sql is None
    assert policy.with_check_ast is None


def test_introspect_populates_table_columns(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.cols_test (id INT, email TEXT, tenant_id TEXT);
        """
    )
    import psycopg
    from pgrls.introspect import introspect

    with psycopg.connect(pg_url) as conn:
        schema = introspect(conn, schemas=["public"])

    table = next(t for t in schema.tables if t.name == "cols_test")
    assert table.columns == ("id", "email", "tenant_id")


def test_introspect_omits_dropped_columns(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.dropped_cols (id INT, gone TEXT, kept TEXT);
        ALTER TABLE public.dropped_cols DROP COLUMN gone;
        """
    )
    import psycopg
    from pgrls.introspect import introspect

    with psycopg.connect(pg_url) as conn:
        schema = introspect(conn, schemas=["public"])

    table = next(t for t in schema.tables if t.name == "dropped_cols")
    assert "gone" not in table.columns
    assert table.columns == ("id", "kept")


def test_lint_fires_sec002_on_missing_force(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "sec002_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "SEC002" in result.output
    assert "public.sec002_target" in result.output
    assert "public.sec002_clean" not in result.output


def test_lint_sec002_allowlist_via_config_exempts(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec002_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC002]\nallowlist = ["sec002_target"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert result.exit_code == 0, result.output
    assert "SEC002" not in result.output


def test_lint_fires_sec003_on_permissive_public_policy(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec003_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "SEC003" in result.output
    assert "public.sec003_target.public_read" in result.output
    assert "sec003_clean" not in result.output


def test_lint_sec003_allowlist_via_config_exempts(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec003_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC003]\n'
        'allowlist = ["public.sec003_target.public_read"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert "SEC003" not in result.output


def test_lint_fires_sec006_on_update_and_all_without_with_check(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec006_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "SEC006" in result.output
    assert "public.sec006_update.update_bad" in result.output
    assert "public.sec006_all.all_bad" in result.output
    assert "public.sec006_clean" not in result.output


def test_lint_sec006_allowlist_via_config_exempts(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec006_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC006]\n'
        'allowlist = ["public.sec006_update.update_bad", '
        '"public.sec006_all.all_bad"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert "SEC006" not in result.output


def test_lint_fires_sec004_on_lovable_cve_pattern(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "SEC004" in result.output
    assert "public.sec004_target.inverted_auth" in result.output
    assert "sec004_clean" not in result.output


def test_lint_sec004_auth_functions_override_suppresses(
    pg_url: str, apply_sql, tmp_path
) -> None:
    apply_sql((FIXTURES_DIR / "sec004_bad.sql").read_text())
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text(
        '[lint.rules.SEC004]\nauth_functions = ["my.custom_auth"]\n'
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert "SEC004" not in result.output


def test_lint_fires_hyg001_on_orphaned_column_ref(
    pg_url: str, apply_sql
) -> None:
    # Simulate the orphaned-column state: the column 'gone' is marked as
    # dropped in pg_attribute (Postgres 16+ prevents DROP COLUMN when a
    # policy depends on it, so we replicate the internal state directly).
    # Postgres renders dropped column refs as '?dropped?column?' in pg_get_expr.
    apply_sql((FIXTURES_DIR / "hyg001_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "HYG001" in result.output
    assert "public.hyg001_target.orphaned" in result.output
    assert "?dropped?column?" in result.output
    assert "hyg001_clean" not in result.output


def test_lint_fires_every_rule_in_combined_fixture(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "all_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    for rule_id in ("SEC001", "SEC002", "SEC003", "SEC004", "SEC006", "HYG001"):
        assert rule_id in result.output, (
            f"{rule_id} missing from output: {result.output}"
        )
