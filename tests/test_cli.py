from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import _merge_overrides, _run_rules, _should_fail, main
from pgrls.config import Config
from pgrls.model import Schema, Table
from pgrls.rules import all_rules
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
    # Pull the version from the package itself rather than
    # hard-coding the literal — release bumps that forget to
    # update test_cli.py would otherwise pass for substring-
    # of-substring reasons (e.g. "0.0.7" is in "0.0.71").
    from pgrls import __version__

    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Derive from the rule registry so a new rule lands without the
# tuple drifting silently. `all_rules()` itself is covered by
# tests/test_readme_currency.py against the README rules table.
_ALL_RULE_IDS = tuple(rule.id for rule in all_rules())


def _assert_rules_fire_exactly(output: str, expected: set[str]) -> None:
    """Assert exactly `expected` rule IDs appear in lint output.

    Pins which rules a fixture is meant to exercise, so silent
    cross-firing or silent regressions on other rules show up as
    test failures rather than going unnoticed.
    """
    found = {rid for rid in _ALL_RULE_IDS if rid in output}
    assert found == expected, (
        f"expected {sorted(expected)}, got {sorted(found)}\n"
        f"output:\n{output}"
    )


def test_lint_against_known_bad_db_exits_nonzero(pg_url: str, apply_sql) -> None:
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "public.users" in result.output
    # users → SEC001. orders.orders_owner is permissive PUBLIC → SEC003.
    # orders has only that one permissive policy → SEC007 (info).
    _assert_rules_fire_exactly(
        result.output, {"SEC001", "SEC003", "SEC007"}
    )


def test_lint_clean_db_exits_zero(pg_url: str, apply_sql) -> None:
    # RLS + FORCE + a PERMISSIVE-non-PUBLIC policy + a RESTRICTIVE
    # floor + PRIMARY KEY = the canonical clean shape:
    #   - SEC001: RLS on
    #   - SEC002: FORCE on
    #   - SEC003: PERMISSIVE is to postgres, not PUBLIC
    #   - SEC005: USING references the own column `id`
    #   - SEC006: SELECT-only policies, no WITH CHECK needed
    #   - SEC007: at least one RESTRICTIVE → not all-permissive
    #   - SEC009: at least one policy → not RLS-without-policies
    #   - SEC012: at least one PERMISSIVE → not silent deny-all
    #   - PERF003: PRIMARY KEY creates an implicit B-tree on `id`,
    #     so the `id > 0` predicate has a leading-column index
    apply_sql(
        """
        CREATE TABLE public.t (id INT PRIMARY KEY);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        CREATE POLICY t_permit ON public.t
            FOR SELECT TO postgres USING (id > 0);
        CREATE POLICY t_lock ON public.t
            AS RESTRICTIVE FOR SELECT TO postgres USING (id > 0);
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
    # Tool error (config / setup), not findings — exit code 2
    # distinguishes "your DATABASE_URL is wrong" from "your schema
    # has an RLS bug" so CI alerts can route differently.
    assert result.exit_code == 2
    assert "DATABASE_URL" in result.output or "database-url" in result.output


def test_lint_exit_code_1_is_violations_at_threshold_only(
    pg_url: str, apply_sql
) -> None:
    # Pin the contract: exit 1 means "lint completed, findings
    # reached threshold." Bad TOML, missing DB, unknown schema all
    # produce exit 2 (tested below). This separation lets `pgrls
    # lint && deploy` distinguish the two.
    apply_sql((FIXTURES_DIR / "known_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1
    assert "SEC001" in result.output


def test_lint_unknown_schema_exits_2_not_1(
    pg_url: str,
) -> None:
    # `--schemas` typo is a setup error, not a findings result.
    # Pin exit 2 explicitly so a future regression that reroutes
    # introspect.ValueError through `sys.exit(1)` fails this.
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--schemas", "no_such_schema"],
    )
    assert result.exit_code == 2


def test_lint_bad_toml_exits_2_not_1(tmp_path) -> None:
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text("[database\n")  # malformed TOML
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--config", str(cfg)])
    assert result.exit_code == 2


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


def test_run_rules_applies_severity_override() -> None:
    # An RLS-disabled table trips SEC001 (declared severity: error)
    # and nothing else. `_run_rules` must remap every SEC001
    # violation to the configured override severity.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    base = _run_rules(schema, config=Config())
    assert [(v.rule_id, v.severity) for v in base] == [("SEC001", "error")]

    demoted = _run_rules(
        schema, config=Config(severity_overrides={"SEC001": "info"})
    )
    assert [(v.rule_id, v.severity) for v in demoted] == [
        ("SEC001", "info")
    ]
    # The remap is direction-agnostic — a non-overridden run is
    # unaffected, an overridden run takes the configured value
    # verbatim. The violation's other fields are preserved.
    assert demoted[0].location == base[0].location
    assert demoted[0].message == base[0].message


def test_run_rules_severity_override_remaps_every_violation() -> None:
    # Two RLS-disabled tables trip SEC001 twice. The remap is
    # per-violation — every finding must land at the override
    # severity, not just the first.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="a",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
            Table(
                schema="public",
                name="b",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    found = _run_rules(
        schema, config=Config(severity_overrides={"SEC001": "info"})
    )
    assert {v.rule_id for v in found} == {"SEC001"}
    assert [v.severity for v in found] == ["info", "info"]


def test_run_rules_severity_override_inert_when_rule_disabled() -> None:
    # `disable` wins over `severity`: a disabled rule never runs, so
    # its override has nothing to remap. Pins the contrast the
    # feature draws — `severity` re-tiers, `disable` silences.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    found = _run_rules(
        schema,
        config=Config(
            disable=["SEC001"],
            severity_overrides={"SEC001": "info"},
        ),
    )
    assert found == []


def test_run_rules_severity_override_remaps_what_survives_allowlist() -> None:
    # The allowlist filters inside the rule's check(); the override
    # remaps whatever survives. Table `a` is allowlisted out, `b` is
    # not — the single surviving SEC001 finding is remapped.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="a",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
            Table(
                schema="public",
                name="b",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    surviving = schema.tables[1]  # "public.b"
    found = _run_rules(
        schema,
        config=Config(
            rule_options={"SEC001": {"allowlist": ["a"]}},
            severity_overrides={"SEC001": "info"},
        ),
    )
    assert [(v.rule_id, v.location, v.severity) for v in found] == [
        ("SEC001", surviving.qualified_name, "info")
    ]


def test_lint_severity_override_changes_exit_code(
    pg_url: str, apply_sql, tmp_path
) -> None:
    # An RLS-disabled table trips SEC001 (error). With the default
    # fail_on=warning that is exit 1. A `[lint.rules.SEC001]
    # severity = "info"` override demotes it below the threshold —
    # exit 0 — while the finding still prints, now at info.
    apply_sql("CREATE TABLE public.t (id INT);")
    runner = CliRunner()

    base = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert base.exit_code == 1, base.output
    assert "SEC001" in base.output
    assert "ERROR" in base.output

    cfg = tmp_path / "pgrls.toml"
    cfg.write_text('[lint.rules.SEC001]\nseverity = "info"\n')
    overridden = runner.invoke(
        main, ["lint", "--database-url", pg_url, "--config", str(cfg)]
    )
    assert overridden.exit_code == 0, overridden.output
    # Still reported — the override demotes, it does not silence.
    assert "SEC001" in overridden.output
    assert "INFO" in overridden.output


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


def test_merge_overrides_preserves_diff_fail_on() -> None:
    # `_merge_overrides` is a lint-side helper, but every command
    # that goes through it (`lint`, `fix`, `snapshot`) must round-
    # trip every Config field. Dropping `diff_fail_on` would let
    # a hypothetical caller chain `lint`/`fix` and then `diff` and
    # silently lose the user's `[diff].fail_on` setting. Pin the
    # threading so a future refactor of the Config(...) constructor
    # call can't regress it.
    config = Config(
        database_url="postgres://config",
        schemas=["public"],
        disable=[],
        fail_on="warning",
        rule_options={},
        diff_fail_on="requires-review",
    )
    merged = _merge_overrides(
        config, database_url=None, schemas_csv=None, fail_on=None
    )
    assert merged.diff_fail_on == "requires-review"


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


def test_lint_sec002_fires_on_partition_child_with_self_enabled_rls(
    pg_url: str, apply_sql
) -> None:
    # Pins that SEC002 stays partition-agnostic: a partition child that
    # the operator explicitly RLS-enables but forgot to FORCE must fire,
    # regardless of whether the parent itself has FORCE. The semantics:
    # direct queries on the child use the child's own flags only, and
    # the operator opted into RLS on this specific child — they meant
    # to FORCE it too. A future regression that gives SEC002 the same
    # ancestor-suppression as SEC001 would silence this case incorrectly.
    apply_sql(
        """
        CREATE TABLE public.events (id INT, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.events_2026 ENABLE ROW LEVEL SECURITY;
        -- Child intentionally lacks FORCE — owner can bypass on direct
        -- access to this partition. SEC002 must catch that.
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert "SEC002  public.events_2026\n" in result.output
    # Parent has FORCE, so it must NOT fire.
    assert "SEC002  public.events\n" not in result.output


def test_lint_fires_sec003_on_permissive_public_policy(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "sec003_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    assert "public.sec003_target.public_read" in result.output
    assert "sec003_clean" not in result.output
    # sec003_target has only one permissive PUBLIC policy → SEC003 +
    # SEC007 (info: no RESTRICTIVE floor). sec003_clean is RESTRICTIVE.
    _assert_rules_fire_exactly(result.output, {"SEC003", "SEC007"})


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
    assert "public.sec006_update.update_bad" in result.output
    assert "public.sec006_all.all_bad" in result.output
    assert "public.sec006_clean" not in result.output
    # The three bad policies are permissive PUBLIC → SEC003 + SEC007.
    # update_bad / all_bad have unwrapped current_setting → PERF001.
    # insert_bad's WITH CHECK (true) has no own-col ref → SEC005.
    _assert_rules_fire_exactly(
        result.output,
        {"SEC003", "SEC005", "SEC006", "SEC007", "PERF001"},
    )


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
    assert "public.sec004_target.inverted_auth" in result.output
    assert "sec004_clean" not in result.output
    # inverted_auth is permissive PUBLIC → SEC003 + SEC007 (only
    # permissive on the table). USING has unwrapped current_setting →
    # PERF001. sec004_clean policy is RESTRICTIVE so SEC003/SEC007
    # don't fire on that table.
    _assert_rules_fire_exactly(
        result.output, {"SEC003", "SEC004", "SEC007", "PERF001"}
    )


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
    assert "public.hyg001_target.orphaned" in result.output
    assert "?dropped?column?" in result.output
    assert "hyg001_clean" not in result.output
    # `orphaned` is permissive PUBLIC → SEC003 + SEC007 (only permissive
    # on the table). The dropped column is excluded from table.columns,
    # so SEC005 fires too — the policy has no live own-col ref. HYG001
    # is the headline. hyg001_clean is RESTRICTIVE.
    _assert_rules_fire_exactly(
        result.output, {"SEC003", "SEC005", "SEC007", "HYG001"}
    )


def test_lint_does_not_fire_sec001_on_child_of_rls_enabled_parent(
    pg_url: str, apply_sql
) -> None:
    # Postgres declarative partitioning: parent has RLS + a tenant policy,
    # children inherit it at query time. Before the partition fix,
    # introspection skipped the parent (relkind='p') and SEC001 falsely
    # fired on every child because their relrowsecurity is independently
    # false. With the fix the parent is visible AND SEC001 walks
    # `partition_of` to recognize ancestor coverage.
    apply_sql(
        """
        CREATE TABLE public.events (id BIGINT, tenant_id UUID, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_read ON public.events FOR SELECT TO PUBLIC
            USING (tenant_id = current_setting('app.t', true)::uuid);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    # No SEC001/SEC002 on parent or child.
    assert "SEC001  public.events" not in result.output
    assert "SEC002  public.events" not in result.output
    # SEC003 still fires on the parent's permissive PUBLIC policy — that
    # behavior is untouched by the partition fix and is correct.
    assert "SEC003  public.events.tenant_read\n" in result.output


def test_lint_fires_sec001_on_partition_child_when_parent_has_no_rls(
    pg_url: str, apply_sql
) -> None:
    # Conservative side of the suppression: when no ancestor has RLS,
    # SEC001 still fires on every level — parent and child.
    apply_sql(
        """
        CREATE TABLE public.events (id INT, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert "SEC001  public.events\n" in result.output
    assert "SEC001  public.events_2026\n" in result.output


def test_lint_emits_unscoped_chain_message_when_parent_in_unscoped_schema(
    pg_url: str, apply_sql
) -> None:
    # End-to-end coverage of the differentiated SEC001 message: parent
    # lives in a schema not passed to `--schemas`, so pgrls cannot
    # verify upstream RLS coverage. The unit test in test_sec001.py
    # builds Schema by hand; this test exercises the real Postgres
    # path including pg_inherits resolution across schemas.
    apply_sql(
        """
        CREATE SCHEMA private;
        CREATE TABLE private.events (id INT, day DATE)
            PARTITION BY RANGE (day);
        ALTER TABLE private.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE private.events FORCE ROW LEVEL SECURITY;
        CREATE TABLE public.events_2026 PARTITION OF private.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["lint", "--database-url", pg_url, "--schemas", "public"],
    )
    assert "SEC001  public.events_2026" in result.output
    assert "leaves the scanned schemas" in result.output
    # The classic message must NOT appear for this child — the rule
    # was specifically refactored to differentiate the two.
    classic_for_child = (
        "Table public.events_2026 does not have row-level security"
    )
    assert classic_for_child not in result.output


def test_lint_partition_x_sec003_fires_on_parent_policy(
    pg_url: str, apply_sql
) -> None:
    # Cross-rule integration: when partition suppression silences
    # SEC001 on a child, the per-policy rules must still fire on the
    # parent's policies. Pins that partition awareness is scoped to
    # SEC001 and doesn't leak into SEC003/SEC008 (the two that fire
    # on a `USING (true) TO PUBLIC` permissive policy).
    apply_sql(
        """
        CREATE TABLE public.events (id INT, tenant_id UUID, day DATE)
            PARTITION BY RANGE (day);
        CREATE TABLE public.events_2026 PARTITION OF public.events
            FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
        ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
        CREATE POLICY all_read ON public.events
            FOR SELECT TO PUBLIC USING (true);
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    # SEC001 quiet on both parent (RLS enabled) and child (ancestor
    # covers).
    assert "SEC001  public.events\n" not in result.output
    assert "SEC001  public.events_2026" not in result.output
    # Per-policy rules fire on the parent's policy.
    assert "SEC003  public.events.all_read\n" in result.output
    assert "SEC008  public.events.all_read\n" in result.output
    # Children have no policies of their own → no per-policy rules
    # touch them.
    assert "SEC003  public.events_2026" not in result.output
    assert "SEC008  public.events_2026" not in result.output


def test_lint_handles_partition_cycle_with_clean_error(
    pg_url: str, monkeypatch
) -> None:
    # Postgres cannot produce a cycle in pg_inherits; only corrupted
    # introspection state can. The CLI catches `ValueError` from the
    # rule loop and turns it into a ClickException — pin that the
    # path is exercised by something, since it is otherwise
    # unreachable from any real database. Patch `introspect` to hand
    # back a hand-built cycle Schema and verify the CLI exits cleanly
    # without a Python traceback in the output.
    import pgrls.cli as cli_mod
    from pgrls.model import Schema, Table

    a = Table(
        schema="public",
        name="a",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "b"),
    )
    b = Table(
        schema="public",
        name="b",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "a"),
    )
    cycle = Schema(tables=(a, b))
    monkeypatch.setattr(
        cli_mod, "introspect", lambda conn, schemas: cycle
    )

    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code != 0
    assert "cycle" in result.output.lower()
    # ClickException prints the message; an unhandled exception would
    # leak a Python traceback. Pin the absence.
    assert "Traceback" not in result.output


def test_lint_fires_every_registered_rule_in_combined_fixture(
    pg_url: str, apply_sql
) -> None:
    # Cross-rule combined fixture — every shipped rule must fire
    # at least once. Renaming from "every rule" to "every
    # registered rule" makes the contract explicit: when a new
    # rule is added to default_registry(), this test fails until
    # all_bad.sql gets a block that triggers it. Catches a class
    # of silent under-coverage drift (e.g., when SEC011, PERF002,
    # HYG002 were added to the registry but missing from the
    # then-current fixture).
    #
    # all_bad.sql's SEC016 block creates a cluster-global BYPASSRLS
    # role (roles are not reset by the per-test schema teardown); the
    # `finally` drops it so it can't leak into the shared container
    # and trip SEC016 in the clean-DB e2e test.
    try:
        apply_sql((FIXTURES_DIR / "all_bad.sql").read_text())
        runner = CliRunner()
        result = runner.invoke(main, ["lint", "--database-url", pg_url])
        assert result.exit_code == 1, result.output
        from pgrls.rules import all_rules

        expected = {r.id for r in all_rules()}
        _assert_rules_fire_exactly(result.output, expected)
        # Pin each (rule, location) pair to its intended target.
        # Substring plus trailing newline anchors against the
        # output's `RULE  LOC\n` shape (formatters/text.py) so a
        # rule drifting onto the wrong policy fails loudly instead
        # of silently slipping by. SEC016's location is a bare role
        # name — roles have no schema, so no `public.` prefix.
        for rule_loc in (
            "SEC001  public.allbad_sec001\n",
            "SEC002  public.allbad_sec002\n",
            "SEC003  public.allbad_sec003.public_perm\n",
            "SEC004  public.allbad_sec004.inverted\n",
            "SEC005  public.allbad_sec003.public_perm\n",
            "SEC005  public.allbad_hyg001.orphan\n",
            "SEC005  public.allbad_sec010.block_all\n",
            "SEC006  public.allbad_sec006.update_no_check\n",
            "SEC007  public.allbad_sec003\n",
            "SEC008  public.allbad_sec003.public_perm\n",
            "SEC009  public.allbad_sec002\n",
            "SEC010  public.allbad_sec010.block_all\n",
            "SEC011  public.allbad_sec011.or_true_bypass\n",
            "SEC013  public.allbad_sec013.audit_writes\n",
            "SEC016  allbad_sec016_role\n",
            "SEC017  public.allbad_sec017_leaky\n",
            "SEC018  public.allbad_sec018.owner_is_current_user\n",
            "SEC019  public.allbad_sec019.tenant_scope\n",
            "SEC020  public.allbad_sec020.open_write_check\n",
            "PERF001  public.allbad_sec004.inverted\n",
            "PERF003  public.allbad_perf003.tenant_unindexed\n",
            "PERF001  public.allbad_sec006.update_no_check\n",
            "PERF002  public.allbad_perf002.randomized\n",
            "HYG001  public.allbad_hyg001.orphan\n",
            "HYG002  public.allbad_hyg002.todo_replace_me_later\n",
            "VIEW001  public.allbad_view001\n",
            "VIEW002  public.allbad_view002\n",
            "VIEW003  public.allbad_view003\n",
            "VIEW004  public.allbad_view004\n",
        ):
            assert rule_loc in result.output, (
                f"{rule_loc!r} missing from output:\n{result.output}"
            )
    finally:
        apply_sql("DROP ROLE IF EXISTS allbad_sec016_role")


# ============================================================
# `pgrls fix` integration tests
# ============================================================

def test_fix_dry_run_emits_sec002_sql_without_applying(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_target (id INT);
        ALTER TABLE public.fix_target ENABLE ROW LEVEL SECURITY;
        -- FORCE intentionally missing → SEC002 fixable
        CREATE POLICY p ON public.fix_target
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url]
    )
    assert result.exit_code == 0, result.output
    # SQL was printed but not executed.
    assert "ALTER TABLE public.fix_target FORCE ROW LEVEL SECURITY;" in result.output
    assert "dry-run" in result.output

    # Verify the DB was NOT modified — connect and check force_rls.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid = 'public.fix_target'::regclass"
            )
            (force,) = cur.fetchone()
            assert force is False


def test_fix_apply_executes_sec002_sql(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_apply_target (id INT);
        ALTER TABLE public.fix_apply_target ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_apply_target
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert result.exit_code == 0, result.output
    assert "applied 1 fix" in result.output

    # Verify the DB WAS modified.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid = 'public.fix_apply_target'::regclass"
            )
            (force,) = cur.fetchone()
            assert force is True


def test_fix_rule_filter_limits_to_requested_rule(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_filter_a (id INT);
        ALTER TABLE public.fix_filter_a ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_filter_a
            FOR SELECT TO postgres USING (id > 0);
        -- ^ SEC002 fixable

        CREATE TABLE public.fix_filter_b (id INT, user_id TEXT);
        ALTER TABLE public.fix_filter_b ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_filter_b FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_filter_b
            AS RESTRICTIVE FOR SELECT TO PUBLIC
            USING (user_id = current_setting('app.user', true));
        -- ^ PERF001 fixable
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix", "--database-url", pg_url,
            "--rule", "SEC002",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "fix_filter_a" in result.output
    assert "fix_filter_b" not in result.output


def test_fix_no_violations_emits_clear_message(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE TABLE public.fix_clean (id INT);
        ALTER TABLE public.fix_clean ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.fix_clean FORCE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_clean
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["fix", "--database-url", pg_url]
    )
    assert result.exit_code == 0, result.output
    assert "no auto-fixable" in result.output


def test_fix_missing_database_url_errors_clearly(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["fix"])
    assert result.exit_code != 0
    assert "DATABASE_URL" in result.output or "database-url" in result.output


def test_fix_apply_handles_multiple_fixes(
    pg_url: str, apply_sql
) -> None:
    # Two SEC002-fixable tables. `--apply` runs both ALTER TABLE
    # statements in one shot.
    apply_sql(
        """
        CREATE TABLE public.fix_multi_a (id INT);
        ALTER TABLE public.fix_multi_a ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_multi_a
            FOR SELECT TO postgres USING (id > 0);

        CREATE TABLE public.fix_multi_b (id INT);
        ALTER TABLE public.fix_multi_b ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_multi_b
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC002", "--apply"],
    )
    assert result.exit_code == 0, result.output
    assert "applied 2 fixes" in result.output

    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relname FROM pg_catalog.pg_class "
                "WHERE relrowsecurity AND relforcerowsecurity "
                "AND relname LIKE 'fix_multi_%' "
                "ORDER BY relname"
            )
            assert [row[0] for row in cur.fetchall()] == [
                "fix_multi_a",
                "fix_multi_b",
            ]


def test_fix_apply_is_idempotent(pg_url: str, apply_sql) -> None:
    # First --apply executes; second --apply finds nothing to do.
    apply_sql(
        """
        CREATE TABLE public.fix_idempotent (id INT);
        ALTER TABLE public.fix_idempotent ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_idempotent
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    first = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert first.exit_code == 0
    assert "applied 1 fix" in first.output

    second = runner.invoke(
        main, ["fix", "--database-url", pg_url, "--apply"]
    )
    assert second.exit_code == 0
    assert "no auto-fixable" in second.output


def test_fix_unknown_rule_filter_errors_clearly(
    pg_url: str, apply_sql
) -> None:
    # `--rule SEC999` is a typo. Producing zero fixes silently
    # would be indistinguishable from "DB is clean" — confusing.
    # Validate eagerly and tell the user which rules are
    # auto-fixable.
    apply_sql(
        """
        CREATE TABLE public.fix_unknown (id INT);
        ALTER TABLE public.fix_unknown ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_unknown
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC999"],
    )
    assert result.exit_code != 0
    assert "unknown auto-fixable rule" in result.output
    assert "SEC999" in result.output
    # The error message should list the actually-fixable rules
    # so the user can spot their typo.
    assert "SEC002" in result.output
    assert "PERF001" in result.output
    assert "VIEW001" in result.output
    assert "VIEW002" in result.output


def test_fix_rule_filter_normalizes_case(
    pg_url: str, apply_sql
) -> None:
    # `--rule sec002` is the same as `--rule SEC002` — mirrors the
    # case-insensitive contract on `[lint].disable`,
    # `[lint.rules.<ID>]`, `--fail-on`, etc. Without normalization,
    # lowercase input would error with "unknown auto-fixable rule"
    # even though the rule exists.
    apply_sql(
        """
        CREATE TABLE public.fix_case_norm (id INT);
        ALTER TABLE public.fix_case_norm ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_case_norm
            AS RESTRICTIVE FOR SELECT TO PUBLIC USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "sec002"],
    )
    assert result.exit_code == 0
    # SEC002 emits ALTER TABLE … FORCE ROW LEVEL SECURITY; the
    # canonical fix output should reach stdout despite the
    # lowercase input.
    assert "FORCE ROW LEVEL SECURITY" in result.output


def test_fix_unknown_rule_does_not_block_known_rule_in_same_invocation(
    pg_url: str, apply_sql
) -> None:
    # `--rule SEC002 --rule SEC999` — one valid, one typo. The
    # validation rejects the whole invocation rather than silently
    # filtering out the typo.
    apply_sql(
        """
        CREATE TABLE public.fix_mixed (id INT);
        ALTER TABLE public.fix_mixed ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_mixed
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "fix",
            "--database-url", pg_url,
            "--rule", "SEC002",
            "--rule", "SEC999",
        ],
    )
    assert result.exit_code != 0
    assert "SEC999" in result.output


def test_fix_apply_rolls_back_on_statement_failure(
    pg_url: str, apply_sql, monkeypatch
) -> None:
    # Force the second SEC002 fix to fail at execute time and
    # confirm that the all-or-nothing semantic holds: the first
    # fix is rolled back, the user sees a clear ClickException
    # with the offending (rule_id, location), and exit code is
    # nonzero.
    apply_sql(
        """
        CREATE TABLE public.fix_rollback_a (id INT);
        ALTER TABLE public.fix_rollback_a ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_rollback_a
            FOR SELECT TO postgres USING (id > 0);

        CREATE TABLE public.fix_rollback_b (id INT);
        ALTER TABLE public.fix_rollback_b ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_rollback_b
            FOR SELECT TO postgres USING (id > 0);
        """
    )

    # Inject a fixer that returns a deliberately-broken second
    # statement so we can observe rollback.
    from pgrls.fixers import Fix
    import pgrls.cli as cli_mod

    real_generate = cli_mod.generate_fixes

    def fake(schema, *, rule_options, rule_filter=None):
        real = real_generate(
            schema, rule_options=rule_options, rule_filter=rule_filter
        )
        # Replace the second SEC002 fix with one that will fail at
        # execute time (table doesn't exist).
        out: list[Fix] = []
        for i, f in enumerate(real):
            if i == 1 and f.rule_id == "SEC002":
                out.append(
                    Fix(
                        rule_id="SEC002",
                        location="public.does_not_exist",
                        sql="ALTER TABLE public.does_not_exist FORCE ROW LEVEL SECURITY;",
                        description="will fail",
                    )
                )
            else:
                out.append(f)
        return out

    monkeypatch.setattr(cli_mod, "generate_fixes", fake)
    # Pin that the patch actually replaced the symbol cli.py
    # references; if a future refactor changes the import shape
    # to `import pgrls.fixers as F; F.generate_fixes(...)` the
    # monkeypatch would silently no-op and this test would pass
    # vacuously. The assert below catches that.
    assert cli_mod.generate_fixes is fake

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fix", "--database-url", pg_url, "--rule", "SEC002", "--apply"],
    )
    assert result.exit_code != 0
    assert "fix 2/2 failed" in result.output
    assert "public.does_not_exist" in result.output
    assert "No fixes were applied" in result.output

    # The first fix's table should NOT have FORCE applied — proving
    # rollback worked.
    import psycopg
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                "WHERE oid = 'public.fix_rollback_a'::regclass"
            )
            (force,) = cur.fetchone()
            assert force is False, "rollback failed: fix 1's change persisted"


def test_fix_routes_sql_to_stdout_and_status_to_stderr(
    pg_url: str, apply_sql
) -> None:
    # `pgrls fix > migration.sql` must produce a clean SQL file —
    # no "dry-run" status lines mixed in. Status messages go to
    # stderr; SQL bodies (and their `-- [rule] description`
    # comments) go to stdout.
    apply_sql(
        """
        CREATE TABLE public.fix_streams (id INT);
        ALTER TABLE public.fix_streams ENABLE ROW LEVEL SECURITY;
        CREATE POLICY p ON public.fix_streams
            FOR SELECT TO postgres USING (id > 0);
        """
    )
    # Click 8.2 dropped the `mix_stderr` kwarg; stderr is exposed
    # separately on the result by default.
    runner = CliRunner()
    result = runner.invoke(main, ["fix", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    # SQL body lands on stdout.
    assert (
        "ALTER TABLE public.fix_streams FORCE ROW LEVEL SECURITY;"
        in result.stdout
    )
    # Status messages land on stderr.
    assert "dry-run" in result.stderr
    assert "dry-run" not in result.stdout
