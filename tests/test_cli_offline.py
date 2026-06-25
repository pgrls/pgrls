"""Tests for the offline schema-source CLI helpers and wiring."""
import io
import json

import pytest
from click.testing import CliRunner

from pgrls.cli import _resolve_offline_schema
from pgrls.cli import main, ToolError

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

    payload = json.loads(format_json([]))
    assert "schema_source" not in payload
    assert "skipped_rules" not in payload


ENABLE_ME_DDL = "CREATE TABLE public.t (id int);\n"  # SEC001


def test_fix_sql_file_emits_enable_rls(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(ENABLE_ME_DDL)
    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f), "--rule", "SEC001"]
    )
    assert res.exit_code == 0
    assert "ENABLE ROW LEVEL SECURITY" in res.stdout
    assert "generated offline" in res.stdout  # provenance header


def test_fix_apply_rejected_offline(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(ENABLE_ME_DDL)
    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f), "--apply"]
    )
    assert res.exit_code != 0
    assert "apply" in res.stderr.lower() and "offline" in res.stderr.lower()


# ---------------------------------------------------------------------------
# CLI integration tests: generate offline wiring
# ---------------------------------------------------------------------------

GEN_DDL = "CREATE TABLE public.orgs (id uuid, tenant_id uuid, name text);\n"


def test_generate_sql_file_emits_policy(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(GEN_DDL)
    res = CliRunner().invoke(main, ["generate", "--sql-file", str(f)])
    assert res.exit_code == 0
    assert "CREATE POLICY" in res.stdout
    assert "generated offline" in res.stdout  # provenance header
    assert "generation reflects only" in res.stderr.lower()


def test_generate_apply_rejected_offline(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(GEN_DDL)
    res = CliRunner().invoke(
        main, ["generate", "--sql-file", str(f), "--apply"]
    )
    assert res.exit_code != 0
    assert "apply" in res.stderr.lower() and "offline" in res.stderr.lower()


def test_verify_rejects_offline_flags():
    # R2.5: the deliberate verify exclusion must not be silently undone.
    res = CliRunner().invoke(
        main, ["verify", "--sql-file", "-"], input="CREATE TABLE t (id int);"
    )
    assert res.exit_code != 0  # Click: "no such option: --sql-file"


# ---------------------------------------------------------------------------
# Fix 1 — PERF003 must NOT fire offline (table.indexes is always empty offline)
# ---------------------------------------------------------------------------

TENANT_POLICY_NO_INDEX_DDL = """
CREATE TABLE public.tenant_docs (
    id uuid,
    tenant_id uuid,
    body text
);
ALTER TABLE public.tenant_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.tenant_docs
    FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
"""


def test_lint_sql_file_does_not_emit_perf003_offline(tmp_path):
    """Offline lint must NOT fire PERF003 — table.indexes is always empty
    after sql parsing, so any PERF003 finding would be a false positive
    (we can't see CREATE INDEX in missing DDL). The under-report contract
    requires PERF003 be inert offline."""
    f = tmp_path / "schema.sql"
    f.write_text(TENANT_POLICY_NO_INDEX_DDL)
    res = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--format", "json"]
    )
    payload = json.loads(res.stdout)
    rule_ids = [v["rule_id"] for v in payload["violations"]]
    assert "PERF003" not in rule_ids, (
        "PERF003 fired offline — false positive; table.indexes is always empty "
        "after DDL-only parsing, so no-index is not meaningful."
    )
    assert "PERF003" in payload["skipped_rules"], (
        "PERF003 should appear in skipped_rules when running offline."
    )


# ---------------------------------------------------------------------------
# Fix 2 — offline `fix` must NOT emit a bogus PERF003 CREATE INDEX
# ---------------------------------------------------------------------------


def test_fix_sql_file_does_not_emit_perf003_create_index(tmp_path):
    """Offline fix --sql-file must not emit a CREATE INDEX for PERF003.
    PERF003 is inert offline (no indexes visible), so its fixer would
    generate a bogus statement. It must be filtered out before output."""
    f = tmp_path / "schema.sql"
    f.write_text(TENANT_POLICY_NO_INDEX_DDL)
    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f)]
    )
    assert "CREATE INDEX" not in res.stdout, (
        "fix --sql-file must not emit a CREATE INDEX (PERF003 is inert offline)."
    )


# ---------------------------------------------------------------------------
# Fix 3 — SEC023 and VIEW002 in inert list for accurate skipped_rules
# ---------------------------------------------------------------------------


def test_sec023_is_in_inert_rule_ids():
    """SEC023 reads schema.bypassrls_roles which is never populated offline."""
    from pgrls.schema_sources import inert_rule_ids
    assert "SEC023" in inert_rule_ids("sql"), (
        "SEC023 reads bypassrls_roles (never populated offline) — "
        "it must be in the inert set."
    )


def test_view002_is_in_inert_rule_ids():
    """VIEW002 reads schema.views which is never populated offline."""
    from pgrls.schema_sources import inert_rule_ids
    assert "VIEW002" in inert_rule_ids("sql"), (
        "VIEW002 reads schema.views (never populated offline) — "
        "it must be in the inert set."
    )


# ---------------------------------------------------------------------------
# Fix 4 — --snapshot byte-cap (reuse _OFFLINE_MAX_BYTES)
# ---------------------------------------------------------------------------


def test_resolve_snapshot_rejects_oversize_file(tmp_path):
    """A snapshot file larger than _OFFLINE_MAX_BYTES must raise ToolError
    with a size/MiB message BEFORE json.load is attempted (DoS guard).
    A valid JSON would parse fine but we must never attempt to load > 8 MiB."""
    import json as _json
    from pgrls.cli import _resolve_offline_schema, ToolError
    from pgrls.schema_sources import schema_from_sql

    # Write a VALID snapshot JSON that is over 8 MiB by padding the content.
    # We put the real schema payload inside + big padding so json.load would
    # succeed if called, but we want the size check to fire first.
    snap_payload = schema_from_sql(
        "CREATE TABLE public.t (id int);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
    ).to_snapshot()
    # Pad the JSON to exceed 8 MiB — add a big dummy key the parser ignores.
    snap_payload["_pad"] = "x" * (9 * 1024 * 1024)
    snap = tmp_path / "big.json"
    snap.write_text(_json.dumps(snap_payload), encoding="utf-8")
    assert snap.stat().st_size > 8 * 1024 * 1024  # sanity

    with pytest.raises(ToolError, match="[Mm][Ii][Bb]|exceed|[Ss]napshot.*size|size.*[Ss]napshot"):
        _resolve_offline_schema(
            sql_file=(), snapshot=str(snap), schemas_csv=None, command="lint"
        )


# ---------------------------------------------------------------------------
# Wave-2 fixes: Fix 1 — gating_skipped scoped to rules-in-play
# ---------------------------------------------------------------------------


def test_lint_rule_sec004_require_full_coverage_passes(tmp_path):
    """--rule SEC004 --require-full-coverage must not fail due to coverage gate offline.

    SEC004 is analyzable offline (it is NOT in the inert set), so
    gating_skipped for a --rule SEC004 run should be empty, meaning
    --require-full-coverage must NOT cause a coverage failure.
    Use DDL that doesn't trigger a SEC004 violation so the exit code
    is purely governed by the coverage gate (not the violation path).
    """
    # A table with RLS enabled and a safe policy — no SEC004 violation
    safe_ddl = (
        "CREATE TABLE public.t (id uuid, tenant_id uuid);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.t FOR SELECT TO anon\n"
        "  USING (tenant_id = auth.uid());\n"
    )
    f = tmp_path / "s.sql"
    f.write_text(safe_ddl)
    res = CliRunner().invoke(
        main,
        ["lint", "--sql-file", str(f), "--rule", "SEC004",
         "--require-full-coverage", "--format", "json"],
    )
    payload = json.loads(res.stdout)
    # gating_skipped for a --rule SEC004 run should be empty
    assert payload.get("skipped_rules", []) == [], (
        "skipped_rules should be empty when only running SEC004 (analyzable offline)"
    )
    assert res.exit_code == 0, (
        f"Expected exit 0 (SEC004 analyzable; coverage gate should pass), "
        f"got {res.exit_code}.\nstderr: {res.stderr}"
    )


def test_lint_rule_sec016_offline_surfaces_in_notice_and_json(tmp_path):
    """--rule SEC016 offline must surface SEC016 in the skip notice and json.

    SEC016 is inert offline (catalog-only), so a --rule SEC016 run should:
    - exit 0 (no violations, no coverage failure)
    - emit SEC016 in the stderr skip notice
    - include SEC016 in json skipped_rules
    Previously it was silent (empty gating set → no notice).
    """
    f = tmp_path / "s.sql"
    f.write_text("CREATE TABLE public.t (id int);\n")
    # Text output — check stderr notice
    res_text = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--rule", "SEC016"]
    )
    assert res_text.exit_code == 0, f"Expected exit 0, got {res_text.exit_code}"
    assert "SEC016" in res_text.stderr, (
        "stderr skip notice must mention SEC016 when --rule SEC016 is inert offline"
    )
    # JSON output — check skipped_rules
    res_json = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--rule", "SEC016", "--format", "json"]
    )
    payload = json.loads(res_json.stdout)
    assert "SEC016" in payload.get("skipped_rules", []), (
        "json skipped_rules must contain SEC016 for an offline --rule SEC016 run"
    )


def test_lint_require_full_coverage_with_rule_sec016_fails(tmp_path):
    """--rule SEC016 --require-full-coverage offline must fail.

    SEC016 is inert, so gating_skipped is non-empty and the flag must reject.
    """
    f = tmp_path / "s.sql"
    f.write_text("CREATE TABLE public.t (id int);\n")
    res = CliRunner().invoke(
        main,
        ["lint", "--sql-file", str(f), "--rule", "SEC016",
         "--require-full-coverage"],
    )
    assert res.exit_code != 0, "Expected non-zero exit when only inert rule requested"
    assert "coverage" in res.stderr.lower(), (
        "Coverage failure message expected in stderr"
    )


# ---------------------------------------------------------------------------
# Wave-2 fixes: Fix 2 — offline generate validates --config
# ---------------------------------------------------------------------------


def test_generate_offline_bad_config_is_error(tmp_path):
    """generate --sql-file --config <broken.toml> must exit non-zero.

    Previously, offline generate skipped config loading entirely, so a
    broken --config silently exited 0.  Fix 2 adds an unconditional
    validation step.
    """
    f = tmp_path / "s.sql"
    f.write_text(GEN_DDL)
    bad_config = tmp_path / "bad.toml"
    bad_config.write_text("[lint\n")  # malformed TOML
    res = CliRunner().invoke(
        main, ["generate", "--sql-file", str(f), "--config", str(bad_config)]
    )
    assert res.exit_code != 0, (
        "generate --sql-file with a broken --config must exit non-zero"
    )
    assert res.stderr or res.output, "Some error output expected"


# ---------------------------------------------------------------------------
# Wave-2 fixes: Fix 3 — reject --update-baseline + --require-full-coverage
# ---------------------------------------------------------------------------


def test_lint_update_baseline_with_require_full_coverage_rejected(tmp_path):
    """--update-baseline and --require-full-coverage cannot be combined.

    --update-baseline exits 0 after recording findings (before the coverage
    gate), so combining the flags silently swallows --require-full-coverage.
    The pair must be rejected up-front with a descriptive error.
    """
    f = tmp_path / "s.sql"
    f.write_text("CREATE TABLE public.t (id int);\n")
    baseline = tmp_path / "b.json"
    res = CliRunner().invoke(
        main,
        ["lint", "--sql-file", str(f),
         "--update-baseline", "--baseline", str(baseline),
         "--require-full-coverage"],
    )
    assert res.exit_code != 0, (
        "Expected non-zero exit when --update-baseline and "
        "--require-full-coverage are combined"
    )
    assert "update-baseline" in res.stderr.lower() or "update_baseline" in res.stderr.lower(), (
        "Error message should mention --update-baseline"
    )
