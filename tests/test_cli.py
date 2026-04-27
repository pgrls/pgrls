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
    assert "0.0.4" in result.output


FIXTURES_DIR = Path(__file__).parent / "fixtures"

_ALL_RULE_IDS = (
    "SEC001",
    "SEC002",
    "SEC003",
    "SEC004",
    "SEC005",
    "SEC006",
    "SEC007",
    "SEC008",
    "PERF001",
    "HYG001",
)


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


def test_lint_fires_every_rule_in_combined_fixture(
    pg_url: str, apply_sql
) -> None:
    apply_sql((FIXTURES_DIR / "all_bad.sql").read_text())
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--database-url", pg_url])
    assert result.exit_code == 1, result.output
    _assert_rules_fire_exactly(
        result.output,
        {
            "SEC001",
            "SEC002",
            "SEC003",
            "SEC004",
            "SEC005",
            "SEC006",
            "SEC007",
            "SEC008",
            "PERF001",
            "HYG001",
        },
    )
    # Pin each (rule, location) pair to its intended target. Substring
    # plus trailing newline anchors against the output's `RULE  LOC\n`
    # shape (formatters/text.py) so a rule drifting onto the wrong
    # policy fails loudly instead of silently slipping by.
    for rule_loc in (
        "SEC001  public.allbad_sec001\n",
        "SEC002  public.allbad_sec002\n",
        "SEC003  public.allbad_sec003.public_perm\n",
        "SEC004  public.allbad_sec004.inverted\n",
        "SEC005  public.allbad_sec003.public_perm\n",
        "SEC005  public.allbad_hyg001.orphan\n",
        "SEC006  public.allbad_sec006.update_no_check\n",
        "SEC007  public.allbad_sec003\n",
        "SEC008  public.allbad_sec003.public_perm\n",
        "PERF001  public.allbad_sec004.inverted\n",
        "PERF001  public.allbad_sec006.update_no_check\n",
        "HYG001  public.allbad_hyg001.orphan\n",
    ):
        assert rule_loc in result.output, (
            f"{rule_loc!r} missing from output:\n{result.output}"
        )
