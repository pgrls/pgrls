"""End-to-end tests for `pgrls diff --apply migration.sql`.

The flag spins up an ephemeral Postgres testcontainer, restores
the captured baseline via `Schema.to_sql()`, applies the
migration, and introspects the result for the head schema.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pgrls.cli import main


def _capture_baseline(pg_url: str) -> Path:
    """Run `pgrls snapshot` against `pg_url` and return path to the JSON."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert result.exit_code == 0, result.output
    return result.output  # JSON string


def test_diff_apply_classifies_safe_migration_as_clean(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration that adds a SAFE-class change (e.g. RESTRICTIVE
    policy add) should classify accordingly. End-to-end smoke test
    for the --apply path: snapshot a baseline, write a migration
    that ALTERs the schema, run `pgrls diff base.json --apply`."""
    apply_sql(
        """
        CREATE TABLE public.invoices (
            id BIGSERIAL,
            tenant_id UUID NOT NULL,
            amount NUMERIC(12, 2)
        );
        ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        # Adding a RESTRICTIVE policy is SAFE (tightens access).
        "CREATE POLICY tenant_lock ON public.invoices "
        "AS RESTRICTIVE FOR ALL TO PUBLIC "
        "USING (tenant_id IS NOT NULL) "
        "WITH CHECK (tenant_id IS NOT NULL);\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    # Adding a RESTRICTIVE policy is SAFE — the diff JSON reuses
    # the lint Violation shape (`violations`, with each entry
    # exposing `rule_id`, `severity`, `title`, `message`,
    # `location`). The DIFF_POLICY_ADDED_RESTRICTIVE rule_id maps
    # to severity=info (SAFE classification per AGENTS.md).
    rule_ids = {v["rule_id"] for v in payload["violations"]}
    assert "DIFF_POLICY_ADDED_RESTRICTIVE" in rule_ids


def test_diff_apply_classifies_dangerous_migration_as_failing(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration that adds a DANGEROUS-class change should make
    `pgrls diff --apply` exit 1 (the default --fail-on=dangerous)."""
    apply_sql(
        """
        CREATE TABLE public.users_apply_test (
            id BIGSERIAL,
            email TEXT,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.users_apply_test ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.users_apply_test FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_lock ON public.users_apply_test
            AS RESTRICTIVE FOR ALL TO PUBLIC
            USING (tenant_id IS NOT NULL);
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        # Adding a PERMISSIVE-PUBLIC policy is DANGEROUS (broadens
        # access). With --fail-on=dangerous (default), exit 1.
        "CREATE POLICY public_read ON public.users_apply_test "
        "FOR SELECT TO PUBLIC USING (true);\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    # Dangerous changes surface as severity=error in the violation
    # JSON shape (per diff.formatters' Change → Violation map).
    error_violations = [
        v for v in payload["violations"] if v["severity"] == "error"
    ]
    assert error_violations, payload


def test_diff_apply_rejects_combined_with_head_argument(
    tmp_path: Path,
) -> None:
    """`<head>` and --apply are mutually exclusive — pin the error."""
    base = tmp_path / "base.json"
    base.write_text(
        json.dumps({"version": 5, "tables": [], "policies": [], "views": [], "security_definer_functions": []}),
        encoding="utf-8",
    )
    migration = tmp_path / "m.sql"
    migration.write_text("-- empty\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "diff",
            str(base),
            "postgres://x/y",
            "--apply",
            str(migration),
        ],
    )
    assert result.exit_code != 0
    assert "--apply" in result.output and "head" in result.output


def test_diff_apply_surfaces_migration_sql_error_clearly(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration with bad SQL should surface the psycopg error
    via the `--apply: migration <path> failed` ToolError shape."""
    apply_sql(
        """
        CREATE TABLE public.things_apply_err (id BIGSERIAL);
        ALTER TABLE public.things_apply_err ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.things_apply_err FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    migration_path = tmp_path / "broken.sql"
    migration_path.write_text(
        "CREATE POLICY my_policy ON public.does_not_exist FOR SELECT TO PUBLIC USING (true);\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
        ],
    )
    assert result.exit_code != 0
    assert "--apply" in result.output
    assert "failed" in result.output


def test_diff_apply_with_extension_flag_pre_installs_extension(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """`--extension citext` pre-installs the extension in the
    testcontainer before restoring the baseline. Without the flag,
    a baseline that uses ``citext`` columns would fail to restore
    because the type is unknown until the extension is installed.

    Pin the v0.5.1 contract: passing --extension makes the migration
    apply succeed against a baseline whose Schema.to_sql() emits a
    ``citext`` column type.
    """
    # Baseline uses citext — the extension is installed in the
    # *source* DB so introspection captures the column as
    # data_type='citext'. The testcontainer used by --apply is
    # ephemeral and does NOT have citext, hence --extension.
    apply_sql(
        """
        CREATE EXTENSION IF NOT EXISTS citext;
        CREATE TABLE public.contacts_ext_test (
            id BIGSERIAL,
            email CITEXT,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.contacts_ext_test ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.contacts_ext_test FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    # Sanity check: baseline really does carry a citext column.
    # If snapshot stopped emitting that, the test would silently
    # stop covering the case.
    base_payload = json.loads(snap_result.output)
    contacts = next(
        t for t in base_payload["tables"]
        if t["schema"] == "public" and t["name"] == "contacts_ext_test"
    )
    assert any(
        col["data_type"] == "citext"
        for col in contacts.get("column_details", [])
    ), contacts

    # Migration that doesn't touch citext at all — only adds a new
    # plain-text column. Without --extension citext, the baseline
    # restore inside the testcontainer would fail at the
    # `email CITEXT` line.
    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "ALTER TABLE public.contacts_ext_test ADD COLUMN note TEXT;\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--extension",
            "citext",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    # The migration only adds a column — no diff classification
    # should fire. Pin the smoke-test invariant: empty violations
    # list (column adds aren't an RLS-related diff change).
    payload = json.loads(result.output)
    assert payload["violations"] == [], payload


def test_diff_apply_auto_detects_create_extension_in_migration(
    pg_url: str, apply_sql, tmp_path: Path
) -> None:
    """A migration with ``CREATE EXTENSION pgcrypto;`` followed by a
    column default that calls ``gen_random_uuid()`` should apply
    cleanly without --extension, because the v0.5.1 auto-detect
    walks the migration AST and pre-installs every extension it
    declares.
    """
    apply_sql(
        """
        CREATE TABLE public.tokens_autodetect (
            id BIGSERIAL,
            tenant_id UUID NOT NULL
        );
        ALTER TABLE public.tokens_autodetect ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.tokens_autodetect FORCE ROW LEVEL SECURITY;
        """
    )

    runner = CliRunner()
    snap_result = runner.invoke(
        main,
        ["snapshot", "--database-url", pg_url, "--schemas", "public"],
    )
    assert snap_result.exit_code == 0, snap_result.output
    base_path = tmp_path / "base.json"
    base_path.write_text(snap_result.output, encoding="utf-8")

    # Migration declares the extension itself; auto-detect picks
    # it up from the migration's CreateExtensionStmt — no
    # --extension flag needed. Pre-installing under `IF NOT EXISTS`
    # is idempotent with the migration's own statement.
    migration_path = tmp_path / "migration.sql"
    migration_path.write_text(
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
        "ALTER TABLE public.tokens_autodetect "
        "ADD COLUMN token UUID DEFAULT gen_random_uuid();\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        [
            "diff",
            str(base_path),
            "--apply",
            str(migration_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output


def test_diff_apply_rejects_v4_baseline_with_clear_message(
    tmp_path: Path,
) -> None:
    """A v4 baseline (no column_details) → clear "re-capture against
    v0.5+" error rather than a confusing internal traceback."""
    v4_payload = {
        "version": 4,
        "tables": [
            {
                "schema": "public",
                "name": "t",
                "rls_enabled": False,
                "force_rls": False,
                "columns": ["id"],
                "partition_of": None,
                "grants": [],
            }
        ],
        "policies": [],
        "views": [],
        "security_definer_functions": [],
    }
    base = tmp_path / "base.json"
    base.write_text(json.dumps(v4_payload), encoding="utf-8")
    migration = tmp_path / "m.sql"
    migration.write_text("CREATE TABLE public.x (id INT);\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["diff", str(base), "--apply", str(migration)],
    )
    assert result.exit_code != 0
    assert "column_details" in result.output
    assert "v0.5" in result.output or "0.5" in result.output
