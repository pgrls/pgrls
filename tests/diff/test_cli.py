"""Unit tests for `pgrls snapshot` and `pgrls diff` CLI."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import main

# ---------------------------------------------------------------------------
# Minimal snapshot fixtures
# ---------------------------------------------------------------------------

# Snapshot v3 layout (matches Schema.to_snapshot in src/pgrls/model.py):
#  * top-level "policies" array — canonical location, indexed by
#    (table_schema, table_name, policy_name) on load.
#  * per-table "policies" key — accepted by Schema.from_snapshot as
#    a legacy fallback (used by manual fixtures + v2 baselines).
# These fixtures use neither — the tables have no policies, so an
# empty layout works for both readers. When adding a fixture WITH
# policies, prefer the top-level form to match what `pgrls snapshot`
# emits in production.
_EMPTY_SNAP = {"version": 3, "tables": []}

# A table with RLS enabled — no dangerous changes vs another enabled-RLS table.
_TABLE_WITH_RLS = {
    "version": 3,
    "tables": [
        {
            "schema": "public",
            "name": "t",
            "rls_enabled": True,
            "force_rls": False,
            "policies": [],
            "columns": [],
            "partition_of": None,
            "grants": [],
        }
    ],
}

# Same table but RLS disabled — disabling RLS is a "dangerous" change.
_TABLE_WITHOUT_RLS = {
    "version": 3,
    "tables": [
        {
            "schema": "public",
            "name": "t",
            "rls_enabled": False,
            "force_rls": False,
            "policies": [],
            "columns": [],
            "partition_of": None,
            "grants": [],
        }
    ],
}

# A table added with RLS already enabled — TABLE_ADDED_WITH_RLS is "safe".
_TABLE_ADDED_WITH_RLS = {
    "version": 3,
    "tables": [
        {
            "schema": "public",
            "name": "new_table",
            "rls_enabled": True,
            "force_rls": False,
            "policies": [],
            "columns": [],
            "partition_of": None,
            "grants": [],
        }
    ],
}


def test_snapshot_writes_to_stdout(pg_url: str, apply_sql) -> None:
    apply_sql(
        """
        CREATE TABLE public.t (id INT);
        ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.t FORCE ROW LEVEL SECURITY;
        """
    )
    runner = CliRunner()
    result = runner.invoke(main, ["snapshot", "--database-url", pg_url])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["version"] == 5
    assert any(t["name"] == "t" for t in payload["tables"])


def test_snapshot_writes_to_output_file(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    apply_sql("CREATE TABLE public.t (id INT);")
    out = tmp_path / "snap.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--output", str(out)],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["version"] == 5
    # File ends with newline (POSIX-friendly).
    assert out.read_text(encoding="utf-8").endswith("\n")


def test_snapshot_short_output_flag_works(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    apply_sql("CREATE TABLE public.t (id INT);")
    out = tmp_path / "snap.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "-o", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()


def test_snapshot_missing_database_url_exits_2(monkeypatch) -> None:
    # Same three-tier exit-code semantics as `pgrls lint`: tool error
    # (no DB configured) → exit 2, not 1.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("PGRLS_TEST_DATABASE_URL", raising=False)
    runner = CliRunner()
    result = runner.invoke(main, ["snapshot"])
    assert result.exit_code == 2
    assert "DATABASE_URL" in result.output


def test_snapshot_filters_by_schemas(
    pg_url: str, apply_sql
) -> None:
    apply_sql(
        """
        CREATE SCHEMA other;
        CREATE TABLE public.in_public (id INT);
        CREATE TABLE other.in_other (id INT);
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "other"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    table_names = {t["name"] for t in payload["tables"]}
    assert "in_other" in table_names
    assert "in_public" not in table_names


# ---------------------------------------------------------------------------
# pgrls diff — snapshot-vs-snapshot (file-based, no DB needed)
# ---------------------------------------------------------------------------


def test_diff_snapshot_vs_snapshot_text_format(tmp_path: Path) -> None:
    """Two identical snapshots → no dangerous changes → exit 0, text output."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_TABLE_WITH_RLS), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_WITH_RLS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(base), str(head)])

    assert result.exit_code == 0, result.output
    # Text format: plain string output (not valid JSON).
    assert isinstance(result.output, str)
    assert result.output.strip()  # non-empty


def test_diff_with_dangerous_change_exits_1(tmp_path: Path) -> None:
    """RLS disabled in head (was enabled in base) → dangerous → exit 1."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_TABLE_WITH_RLS), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_WITHOUT_RLS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(base), str(head)])

    assert result.exit_code == 1, result.output


def test_diff_fail_on_safe_includes_safe_changes(tmp_path: Path) -> None:
    """--fail-on safe with a safe change → exit 1."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    # base is empty; head adds a table with RLS — TABLE_ADDED_WITH_RLS is safe.
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_ADDED_WITH_RLS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main, ["diff", str(base), str(head), "--fail-on", "safe"]
    )

    assert result.exit_code == 1, result.output


def test_diff_fail_on_dangerous_excludes_safe_changes(tmp_path: Path) -> None:
    """--fail-on dangerous (default) with only safe changes → exit 0."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    # base is empty; head adds a table with RLS — TABLE_ADDED_WITH_RLS is safe.
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_ADDED_WITH_RLS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main, ["diff", str(base), str(head), "--fail-on", "dangerous"]
    )

    assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# pgrls diff — --format flag
# ---------------------------------------------------------------------------


def test_diff_json_format_returns_parseable_json(tmp_path: Path) -> None:
    """--format json → valid JSON with 'violations' and 'summary' keys."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_TABLE_WITH_RLS), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_WITH_RLS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main, ["diff", str(base), str(head), "--format", "json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "violations" in payload
    assert "summary" in payload


def test_diff_sarif_format_returns_parseable_sarif(tmp_path: Path) -> None:
    """--format sarif → valid JSON with SARIF top-level keys."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_TABLE_WITH_RLS), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_WITH_RLS), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main, ["diff", str(base), str(head), "--format", "sarif"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "$schema" in payload
    assert "version" in payload
    assert "runs" in payload


# ---------------------------------------------------------------------------
# pgrls diff — source resolution errors (all should exit 2)
# ---------------------------------------------------------------------------


def test_diff_nonexistent_file_exits_2(tmp_path: Path) -> None:
    """Non-existent path (no '://') → exit 2 with helpful message."""
    head = tmp_path / "head.json"
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    nonexistent = str(tmp_path / "does_not_exist.json")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", nonexistent, str(head)])

    assert result.exit_code == 2, result.output
    # Message should explain both URL and file possibilities.
    assert "://" in result.output
    assert "file" in result.output.lower()


def test_diff_invalid_json_file_exits_2(tmp_path: Path) -> None:
    """File exists but contains invalid JSON → exit 2 mentioning JSON."""
    base = tmp_path / "base.txt"
    head = tmp_path / "head.json"
    base.write_text("this is not json at all", encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(base), str(head)])

    assert result.exit_code == 2, result.output
    assert "JSON" in result.output or "json" in result.output.lower()


def test_diff_snapshot_file_unsupported_version_exits_2(tmp_path: Path) -> None:
    """Snapshot with unsupported version (999) → exit 2."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps({"version": 999, "tables": []}), encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(base), str(head)])

    assert result.exit_code == 2, result.output


# ---------------------------------------------------------------------------
# pgrls diff — default head behaviour
# ---------------------------------------------------------------------------


def test_diff_missing_head_with_no_database_url_exits_2(
    tmp_path: Path, monkeypatch
) -> None:
    """No <head> arg and no DATABASE_URL → exit 2 mentioning DATABASE_URL."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("PGRLS_TEST_DATABASE_URL", raising=False)

    base = tmp_path / "base.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(base)])

    assert result.exit_code == 2, result.output
    assert "DATABASE_URL" in result.output


def test_diff_no_changes_emits_no_changes_summary(tmp_path: Path) -> None:
    """Both base and head are identical empty snapshots → exit 0, 'no changes' line."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(base), str(head), "--format", "text"])

    assert result.exit_code == 0, result.output
    assert result.output.rstrip("\n").endswith("pgrls diff: no changes.")


def test_diff_uses_diff_fail_on_from_pgrls_toml(tmp_path: Path) -> None:
    """[diff].fail_on in pgrls.toml is honored when --fail-on is not
    on the CLI. Pin the fallback chain end-to-end.

    Fixture: a SAFE-only diff (added RESTRICTIVE, classified safe).
    Default `--fail-on dangerous` would exit 0; if we set
    `[diff].fail_on = "safe"` in TOML, the SAFE change should
    trip the threshold and exit 1.
    """
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_ADDED_WITH_RLS), encoding="utf-8")

    toml_path = tmp_path / "pgrls.toml"
    toml_path.write_text(
        '[diff]\nfail_on = "safe"\n',
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base),
            str(head),
            "--config",
            str(toml_path),
        ],
    )
    # SAFE change × fail_on=safe ⇒ change meets threshold ⇒ exit 1.
    assert result.exit_code == 1, result.output


def test_diff_cli_fail_on_overrides_pgrls_toml(tmp_path: Path) -> None:
    """When both --fail-on and [diff].fail_on are set, the CLI flag wins."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_TABLE_ADDED_WITH_RLS), encoding="utf-8")

    toml_path = tmp_path / "pgrls.toml"
    # TOML says fail-on safe (would exit 1).
    toml_path.write_text(
        '[diff]\nfail_on = "safe"\n',
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base),
            str(head),
            "--config",
            str(toml_path),
            # CLI overrides to dangerous → SAFE change is below threshold → exit 0.
            "--fail-on",
            "dangerous",
        ],
    )
    assert result.exit_code == 0, result.output


def test_diff_accepts_file_scheme_url_as_path(tmp_path: Path) -> None:
    """`file:///abs/path/snap.json` should resolve as a local file,
    not be passed to psycopg as a connection string.

    The naive `://` heuristic catches `file://` and treats it as a
    DB URL — psycopg then errors with a connection-shaped message
    that doesn't hint "did you mean a file path?". v0.2.1 strips
    the file:// prefix and falls through to the file-path branch.
    """
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    # `file://` + absolute path — works on POSIX. URL-encoded paths
    # (with %20 etc.) are out of scope; this test pins the simple
    # case that everyday tools (e.g. shell completions, CI
    # variables) would emit.
    base_url = f"file://{base}"
    head_url = f"file://{head}"

    runner = CliRunner()
    result = runner.invoke(main, ["diff", base_url, head_url])

    # Two identical empty snapshots → exit 0, no changes.
    assert result.exit_code == 0, result.output
    assert "no changes" in result.output


def test_diff_invalid_config_toml_exits_2(tmp_path: Path) -> None:
    """Mirror of the lint command's invalid-config test for diff.

    `pgrls diff --config <bad.toml>` should reach the same
    `load_config → ConfigError → ToolError` pipeline as `pgrls lint
    --config` and exit 2 (tool error). Without this regression test,
    a refactor that drops the early `load_config` call from `diff`
    (e.g. inlining toml-loading into the source resolver) could
    silently change the exit code from 2 to 1, fooling CI gates.
    """
    bad_config = tmp_path / "broken.toml"
    bad_config.write_text("[ this is not valid TOML ]] ", encoding="utf-8")

    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base),
            str(head),
            "--config",
            str(bad_config),
        ],
    )
    assert result.exit_code == 2, result.output


def test_diff_warns_when_schemas_passed_with_two_file_inputs(
    tmp_path: Path,
) -> None:
    """--schemas is silently ignored when both <base> and <head> are
    snapshot files (snapshots are pre-filtered at capture time). Without
    a stderr warning, a user typing `pgrls diff base.json head.json
    --schemas app` gets a misleadingly-passing run that didn't filter
    at all. Pin the warning so a refactor that drops it surfaces here."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base),
            str(head),
            "--schemas",
            "app",
        ],
        # CliRunner mixes stdout and stderr by default; use
        # mix_stderr=False would split them but Click's runner has
        # changed signatures across versions. Just check the combined
        # output contains the warning text.
    )
    assert result.exit_code == 0, result.output
    assert "--schemas is ignored" in result.output


def test_diff_warns_when_schemas_passed_with_file_scheme_urls(
    tmp_path: Path,
) -> None:
    """`file://` URLs resolve as snapshot files in the source resolver
    (the prefix is stripped). The --schemas warning gate must treat
    them as files too, not as URL-shaped DB connections — otherwise
    a user passing `--schemas` alongside two `file://` arguments
    would silently miss the "filter is ineffective" warning."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            f"file://{base}",
            f"file://{head}",
            "--schemas",
            "app",
        ],
    )
    assert result.exit_code == 0, result.output
    # `_is_db_url` strips file:// before the URL-substring check, so
    # both inputs count as file-shaped → the warning fires.
    assert "--schemas is ignored" in result.output


def test_diff_picks_up_database_url_env_when_no_pgrls_toml(
    pg_url: str, tmp_path: Path, monkeypatch
) -> None:
    """Regression: $DATABASE_URL must be honored as head fallback even
    when no pgrls.toml exists.

    The earlier implementation read DATABASE_URL only via load_config's
    [database].url interpolation, which silently failed when no toml
    file was present — leaving CI users with `DATABASE_URL` set but no
    config file getting an exit-2 error message instructing them to
    "set DATABASE_URL" — which they had already done.

    Using the real pg_url fixture (which already targets a live test
    DB) confirms the full fallback chain end-to-end: --database-url
    reads $DATABASE_URL via Click's envvar=, the source resolver
    treats it as a URL, introspect runs, the diff emits zero changes
    (empty snapshot vs empty live DB on a freshly-rolled-back schema
    will produce table-added Changes for any tables in the test DB,
    but the test only pins exit_code != 2 — i.e., the fallback chain
    completed without a tool error, which is the contract that broke).
    """
    monkeypatch.setenv("DATABASE_URL", pg_url)
    monkeypatch.delenv("PGRLS_TEST_DATABASE_URL", raising=False)

    # Empty base snapshot, no head arg, no pgrls.toml — must reach
    # introspect via $DATABASE_URL.
    base = tmp_path / "base.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(base)])

    # exit_code may be 0 or 1 depending on the live DB's tables
    # (table-added findings are dangerous when RLS is off). The
    # regression we're guarding against is exit_code == 2 with
    # "set DATABASE_URL" — the env-var path was never reached.
    assert result.exit_code != 2, result.output
