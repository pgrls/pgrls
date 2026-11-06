"""Tests for the offline schema-source CLI helpers and wiring."""
import io
import json

import pytest
from click.testing import CliRunner

from pgrls.cli import _resolve_offline_schema
from pgrls.cli import main, ToolError
from pgrls.schema_sources import _CATALOG_DEPENDENT_RULES

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
    schema, source, _ = _resolve_offline_schema(
        sql_file=(str(f),), snapshot=None, schemas_csv=None, command="lint"
    )
    assert source == "sql"
    assert any(t.name == "docs" for t in schema.tables)


def test_resolve_concatenates_multiple_files_in_order(tmp_path):
    a = tmp_path / "a.sql"
    a.write_text("CREATE TABLE public.docs (id uuid);\n")
    b = tmp_path / "b.sql"
    b.write_text("ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n")
    schema, _, _ = _resolve_offline_schema(
        sql_file=(str(a), str(b)), snapshot=None, schemas_csv=None, command="lint"
    )
    docs = next(t for t in schema.tables if t.name == "docs")
    assert docs.rls_enabled is True  # the ALTER in b attached to the CREATE in a


def test_resolve_reads_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(DOCS_DDL))
    schema, source, _ = _resolve_offline_schema(
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
    """Lint via an OLD-version --snapshot: rules whose fields the snapshot
    predates are skipped on stderr; JSON includes coverage keys.

    SEC016 needs `bypassrls_roles` (snapshot v9), so a v8 snapshot must skip and
    report it rather than silently no-op."""
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql(SEC004_DDL).to_snapshot()
    snap["version"] = 8  # predates SEC016's bypassrls_roles (v9)
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


def test_lint_current_snapshot_runs_full_rule_set(tmp_path):
    """A current-version snapshot meets every field threshold, so NO catalog
    rule is skipped — the coverage gate is usable on it (the HIGH fix)."""
    from pgrls.schema_sources import schema_from_sql

    # A clean, RLS-correct table so the only thing the gate can fail on is a
    # skipped rule (there are none on a current snapshot).
    snap = schema_from_sql("CREATE TABLE public.t (id int);\n").to_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")

    res = CliRunner().invoke(
        main,
        ["lint", "--snapshot", str(path), "--rule", "SEC047",
         "--require-full-coverage", "--format", "json"],
    )
    payload = json.loads(res.stdout)
    assert payload["skipped_rules"] == []  # SEC047 (v20) runs on a current snapshot
    assert res.exit_code == 0  # nothing skipped → coverage gate passes


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
# Regression: every catalog-dependent rule must be SURFACED in skipped_rules on
# an offline sql= run (never silently no-op + falsely pass coverage). Locks in
# the SEC035/SEC041/SEC043/SEC048 false-clean fix and guards the whole set.
# ---------------------------------------------------------------------------

# A schema with RLS on but nothing a catalog rule reads (no triggers, indexes,
# FKs, BYPASSRLS roles, views, …). Offline, EVERY catalog-dependent rule should
# report itself skipped rather than produce a misleading clean result.
_CATALOG_PROBE_DDL = (
    "CREATE TABLE public.accounts (id uuid, tenant_id integer, email text);\n"
    "ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;\n"
    "CREATE POLICY p ON public.accounts USING (tenant_id = 1);\n"
    "CREATE UNIQUE INDEX accounts_email_key ON public.accounts (email);\n"
)


@pytest.mark.parametrize("rule", sorted(_CATALOG_DEPENDENT_RULES))
def test_offline_noop_rule_lands_in_skipped_rules(tmp_path, rule):
    f = tmp_path / "probe.sql"
    f.write_text(_CATALOG_PROBE_DDL)
    res = CliRunner().invoke(
        main, ["lint", "--sql-file", str(f), "--rule", rule, "--format", "json"]
    )
    payload = json.loads(res.stdout)
    assert payload["skipped_rules"] == [rule], (
        f"{rule} is inert offline and must be surfaced in skipped_rules, not "
        f"silently no-op (got {payload['skipped_rules']!r})."
    )


@pytest.mark.parametrize("rule", ["SEC035", "SEC041", "SEC043", "SEC048"])
def test_offline_noop_rule_fails_require_full_coverage(tmp_path, rule):
    """The reviewer's blocker: an offline sql= run of a rule whose live verdict
    would matter must FAIL --require-full-coverage, never exit 0 as clean."""
    f = tmp_path / "probe.sql"
    f.write_text(_CATALOG_PROBE_DDL)
    res = CliRunner().invoke(
        main,
        ["lint", "--sql-file", str(f), "--rule", rule, "--require-full-coverage"],
    )
    assert res.exit_code != 0
    assert "coverage" in res.stderr.lower()


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


# ---------------------------------------------------------------------------
# Wave-3 fixes: Fix 1 — offline provenance reaches --output files
# ---------------------------------------------------------------------------


def test_fix_sql_file_output_carries_offline_caveat(tmp_path):
    """fix --sql-file x --output out.sql → file must contain offline caveat.

    The persisted migration is the highest-risk artifact. It must carry the
    offline provenance header, not the false "snapshot of the database" header.
    """
    f = tmp_path / "s.sql"
    f.write_text(ENABLE_ME_DDL)
    out = tmp_path / "out.sql"
    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f), "--rule", "SEC001",
               "--output", str(out)]
    )
    assert res.exit_code == 0, f"Expected exit 0; stderr: {res.stderr}"
    content = out.read_text(encoding="utf-8")
    assert "generated offline" in content.lower() or "not validated" in content.lower(), (
        f"Offline caveat missing from --output file:\n{content}"
    )
    assert "snapshot of the database" not in content, (
        f"False live-DB header must not appear in offline --output file:\n{content}"
    )


def test_generate_sql_file_output_carries_offline_caveat(tmp_path):
    """generate --sql-file x --output out.sql → file must contain offline caveat."""
    f = tmp_path / "s.sql"
    f.write_text(GEN_DDL)
    out = tmp_path / "out.sql"
    res = CliRunner().invoke(
        main, ["generate", "--sql-file", str(f), "--output", str(out)]
    )
    assert res.exit_code == 0, f"Expected exit 0; stderr: {res.stderr}"
    content = out.read_text(encoding="utf-8")
    assert "generated offline" in content.lower() or "not validated" in content.lower(), (
        f"Offline caveat missing from generate --output file:\n{content}"
    )
    assert "snapshot of the database" not in content, (
        f"False live-DB header must not appear in offline generate --output file:\n{content}"
    )


def test_fix_sql_file_stdout_provenance_appears_exactly_once(tmp_path):
    """Offline fix stdout emit path: 'generated offline' appears exactly once."""
    f = tmp_path / "s.sql"
    f.write_text(ENABLE_ME_DDL)
    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f), "--rule", "SEC001"]
    )
    assert res.exit_code == 0
    count = res.stdout.lower().count("generated offline")
    assert count == 1, (
        f"'generated offline' should appear exactly once on stdout, got {count}:\n{res.stdout}"
    )


def test_generate_sql_file_stdout_provenance_appears_exactly_once(tmp_path):
    """Offline generate stdout emit path: 'generated offline' appears exactly once."""
    f = tmp_path / "s.sql"
    f.write_text(GEN_DDL)
    res = CliRunner().invoke(main, ["generate", "--sql-file", str(f)])
    assert res.exit_code == 0
    count = res.stdout.lower().count("generated offline")
    assert count == 1, (
        f"'generated offline' should appear exactly once on stdout, got {count}:\n{res.stdout}"
    )


def test_live_render_migration_header_unchanged():
    """Live render_migration (offline=False default) must produce the canonical header."""
    from pgrls.fixers import Fix, render_migration

    fix = Fix(
        rule_id="SEC001",
        location="public.t",
        sql="ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;",
        description="Enable RLS",
    )
    result = render_migration([fix], tool_version="0.0.0-test")
    assert "snapshot of the database" in result, (
        "Live render_migration must still contain 'snapshot of the database':\n" + result
    )
    assert "generated offline" not in result.lower(), (
        "Live render_migration must NOT contain offline caveat:\n" + result
    )


# ---------------------------------------------------------------------------
# Wave-4 tests: fix/generate snapshot, multi-file, stdin, conflicts, check
# ---------------------------------------------------------------------------


def test_fix_snapshot_emits_enable_rls(tmp_path):
    """fix --snapshot snap.json --rule SEC001 → exit 0, stdout has ENABLE ROW LEVEL SECURITY
    and 'generated offline'."""
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql(ENABLE_ME_DDL).to_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")

    res = CliRunner().invoke(
        main, ["fix", "--snapshot", str(path), "--rule", "SEC001"]
    )
    assert res.exit_code == 0, f"Expected exit 0; stderr: {res.stderr}"
    assert "ENABLE ROW LEVEL SECURITY" in res.stdout
    assert "generated offline" in res.stdout


def test_generate_snapshot_emits_policy(tmp_path):
    """generate --snapshot snap.json → exit 0, stdout has CREATE POLICY and
    'generated offline'."""
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql(GEN_DDL).to_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")

    res = CliRunner().invoke(main, ["generate", "--snapshot", str(path)])
    assert res.exit_code == 0, f"Expected exit 0; stderr: {res.stderr}"
    assert "CREATE POLICY" in res.stdout
    assert "generated offline" in res.stdout


def test_fix_multi_file_sql_file_rls_already_enabled(tmp_path):
    """fix --sql-file a.sql --sql-file b.sql where a.sql creates table and
    b.sql enables RLS → SEC001 does NOT fire (RLS enabled by concatenation),
    so 'no auto-fixable violations found' appears on stderr."""
    a = tmp_path / "a.sql"
    a.write_text("CREATE TABLE public.docs2 (id int);\n")
    b = tmp_path / "b.sql"
    b.write_text("ALTER TABLE public.docs2 ENABLE ROW LEVEL SECURITY;\n")

    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(a), "--sql-file", str(b), "--rule", "SEC001"]
    )
    assert res.exit_code == 0
    assert "no auto-fixable violations found" in res.stderr.lower()


def test_generate_multi_file_sql_file_emits_policy(tmp_path):
    """generate --sql-file a.sql --sql-file b.sql combining into a tenant table
    lacking policies → CREATE POLICY emitted."""
    a = tmp_path / "a.sql"
    a.write_text("CREATE TABLE public.tenants2 (id uuid);\n")
    b = tmp_path / "b.sql"
    b.write_text("ALTER TABLE public.tenants2 ADD COLUMN tenant_id uuid;\n")

    res = CliRunner().invoke(
        main, ["generate", "--sql-file", str(a), "--sql-file", str(b)]
    )
    assert res.exit_code == 0, f"Expected exit 0; stderr: {res.stderr}"
    assert "CREATE POLICY" in res.stdout


def test_fix_database_url_conflict(tmp_path):
    """fix --sql-file x --database-url postgres://x/y → non-zero exit, stderr
    contains 'offline' or 'one schema source'."""
    f = tmp_path / "s.sql"
    f.write_text(ENABLE_ME_DDL)

    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f), "--database-url", "postgres://x/y"]
    )
    assert res.exit_code != 0
    assert "offline" in res.stderr.lower() or "one schema source" in res.stderr.lower()


def test_generate_database_url_conflict(tmp_path):
    """generate --sql-file x --database-url postgres://x/y → non-zero exit, stderr
    contains 'offline' or 'one schema source'."""
    f = tmp_path / "s.sql"
    f.write_text(GEN_DDL)

    res = CliRunner().invoke(
        main, ["generate", "--sql-file", str(f), "--database-url", "postgres://x/y"]
    )
    assert res.exit_code != 0
    assert "offline" in res.stderr.lower() or "one schema source" in res.stderr.lower()


def test_fix_check_offline_exits_one_no_sql_emitted(tmp_path):
    """fix --sql-file x --check → exit 1 AND stdout does NOT contain
    ENABLE ROW LEVEL SECURITY (--check lists violations but emits no SQL)."""
    f = tmp_path / "s.sql"
    f.write_text(ENABLE_ME_DDL)

    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f), "--check"]
    )
    assert res.exit_code == 1, (
        f"Expected exit code 1 from fix --check, got {res.exit_code}"
    )
    assert "ENABLE ROW LEVEL SECURITY" not in res.stdout


def test_fix_stdin_emits_enable_rls():
    """fix --sql-file - with input=DDL → emits the fix to stdout
    (has ENABLE ROW LEVEL SECURITY)."""
    res = CliRunner().invoke(
        main, ["fix", "--sql-file", "-", "--rule", "SEC001"],
        input=ENABLE_ME_DDL,
    )
    assert res.exit_code == 0, f"Expected exit 0; stderr: {res.stderr}"
    assert "ENABLE ROW LEVEL SECURITY" in res.stdout


def test_generate_stdin_emits_policy():
    """generate --sql-file - with input=DDL → emits CREATE POLICY."""
    res = CliRunner().invoke(
        main, ["generate", "--sql-file", "-"],
        input=GEN_DDL,
    )
    assert res.exit_code == 0, f"Expected exit 0; stderr: {res.stderr}"
    assert "CREATE POLICY" in res.stdout


def test_lint_require_full_coverage_old_snapshot(tmp_path):
    """An OLD-version snapshot lacks fields newer rules need, so
    --require-full-coverage fails closed and stderr names the coverage gap."""
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql("CREATE TABLE public.t (id int);\n").to_snapshot()
    snap["version"] = 8  # predates SEC016 (v9), SEC047 (v20), …
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")

    res = CliRunner().invoke(
        main, ["lint", "--snapshot", str(path), "--require-full-coverage"]
    )
    assert res.exit_code != 0
    assert "coverage" in res.stderr.lower()


def test_lint_require_full_coverage_current_snapshot_no_coverage_failure(tmp_path):
    """A current-version snapshot meets every field threshold, so
    --require-full-coverage never fails on a *coverage* gap (the HIGH fix).

    Findings may still fail the run, but the coverage-gate message must not fire.
    """
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql("CREATE TABLE public.t (id int);\n").to_snapshot()
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap), encoding="utf-8")

    res = CliRunner().invoke(
        main,
        ["lint", "--snapshot", str(path), "--rule", "SEC047",
         "--require-full-coverage"],
    )
    assert res.exit_code == 0
    assert "require-full-coverage" not in res.stderr


def test_fix_offline_soundness_caveat_on_stderr(tmp_path):
    """fix --sql-file x → a soundness caveat reaches stderr (matches the
    'no live database' / 'not a proof' / 'offline' text from
    schema_source_warnings for command='fix')."""
    f = tmp_path / "s.sql"
    f.write_text(ENABLE_ME_DDL)

    res = CliRunner().invoke(
        main, ["fix", "--sql-file", str(f), "--rule", "SEC001"]
    )
    assert res.exit_code == 0
    err_lower = res.stderr.lower()
    assert (
        "no live database" in err_lower
        or "not a proof" in err_lower
        or "offline" in err_lower
    ), f"Soundness caveat missing from stderr:\n{res.stderr}"


# ---------------------------------------------------------------------------
# CLI integration tests: snapshot offline wiring (the DB-free PR pipeline)
# ---------------------------------------------------------------------------

_TENANT_SCOPED = (
    "CREATE TABLE public.t (id int, tenant_id uuid);\n"
    "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
    "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
    "  USING (tenant_id = current_setting('app.tenant')::uuid)\n"
    "  WITH CHECK (tenant_id = current_setting('app.tenant')::uuid);\n"
)
_UNSCOPED = (
    "CREATE TABLE public.t (id int, tenant_id uuid);\n"
    "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
    "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
    "  USING (true) WITH CHECK (true);\n"
)


def test_snapshot_sql_file_emits_offline_snapshot(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(_TENANT_SCOPED)
    out = tmp_path / "snap.json"
    res = CliRunner().invoke(
        main, ["snapshot", "--sql-file", str(f), "--output", str(out)]
    )
    assert res.exit_code == 0, res.output
    payload = json.loads(out.read_text())
    assert "version" in payload
    assert any(t["name"] == "t" for t in payload["tables"])


def test_snapshot_offline_caveat_on_stderr(tmp_path, capsys):
    # The snapshot-flavored caveat (built from DDL; catalog state absent),
    # distinct from lint's "not a proof of safety" wording.
    f = tmp_path / "s.sql"
    f.write_text(_TENANT_SCOPED)
    _resolve_offline_schema(
        sql_file=(str(f),), snapshot=None, schemas_csv=None, command="snapshot"
    )
    err = capsys.readouterr().err.lower()
    assert "built from the provided sql offline" in err
    assert "catalog-only state" in err


def test_snapshot_offline_conflicts_with_database_url(tmp_path):
    f = tmp_path / "s.sql"
    f.write_text(_TENANT_SCOPED)
    res = CliRunner().invoke(
        main,
        ["snapshot", "--sql-file", str(f), "--database-url", "postgres://x/y"],
    )
    assert res.exit_code != 0 and "one schema source" in res.stderr.lower()


def test_snapshot_roundtrips_via_snapshot_input(tmp_path):
    # snapshot --snapshot IN re-emits an existing artifact (format upgrade).
    f = tmp_path / "s.sql"
    f.write_text(_TENANT_SCOPED)
    first = tmp_path / "a.json"
    assert (
        CliRunner()
        .invoke(main, ["snapshot", "--sql-file", str(f), "-o", str(first)])
        .exit_code
        == 0
    )
    second = tmp_path / "b.json"
    res = CliRunner().invoke(
        main, ["snapshot", "--snapshot", str(first), "-o", str(second)]
    )
    assert res.exit_code == 0, res.output
    assert json.loads(first.read_text()) == json.loads(second.read_text())


def test_db_free_snapshot_diff_catches_dangerous_regression(tmp_path):
    # The keystone of the PR checker: build a snapshot from each migration
    # revision with NO database, then diff base->head. Dropping the tenant
    # predicate to USING(true) is a Z3-verified DANGEROUS loosening, so
    # `--fail-on dangerous` exits nonzero — the CI gate the Action wires up.
    base_sql = tmp_path / "base.sql"
    base_sql.write_text(_TENANT_SCOPED)
    head_sql = tmp_path / "head.sql"
    head_sql.write_text(_UNSCOPED)
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    for src, dst in ((base_sql, base), (head_sql, head)):
        r = CliRunner().invoke(
            main, ["snapshot", "--sql-file", str(src), "-o", str(dst)]
        )
        assert r.exit_code == 0, r.output

    res = CliRunner().invoke(
        main,
        ["diff", str(base), str(head), "--fail-on", "dangerous",
         "--format", "json"],
    )
    assert res.exit_code == 1  # dangerous change present → gate fails
    payload = json.loads(res.stdout)
    classifications = {c["classification"] for c in payload["violations"]}
    assert "dangerous" in classifications


# --- schema_from_sql must REPLAY policy/table mutations (soundness) ----------
# Without this, a migration that loosens a policy via ALTER POLICY (or removes
# an RLS guard via DROP POLICY / DROP TABLE) would be modeled as its pre-change
# form — a silent false-SAFE for the DB-free diff gate above.


def _offline_schema(sql):
    from pgrls.schema_sources import schema_from_sql

    return schema_from_sql(sql)


def test_schema_from_sql_applies_alter_policy_loosening():
    s = _offline_schema(
        _TENANT_SCOPED
        + "ALTER POLICY p ON public.t USING (true) WITH CHECK (true);\n"
    )
    (t,) = [t for t in s.tables if t.name == "t"]
    (p,) = t.policies
    assert p.using_sql.lower() == "true"  # post-ALTER, not the tenant predicate
    assert p.with_check_sql.lower() == "true"


def test_schema_from_sql_alter_policy_preserves_omitted_clause():
    # ALTER POLICY … TO role (no USING) must not wipe the existing USING.
    s = _offline_schema(_TENANT_SCOPED + "ALTER POLICY p ON public.t TO anon;\n")
    (t,) = [t for t in s.tables if t.name == "t"]
    (p,) = t.policies
    assert "tenant_id" in (p.using_sql or "")  # USING untouched


def test_schema_from_sql_applies_drop_policy():
    s = _offline_schema(_TENANT_SCOPED + "DROP POLICY p ON public.t;\n")
    (t,) = [t for t in s.tables if t.name == "t"]
    assert t.policies == ()  # policy removed
    assert t.rls_enabled  # the table + its RLS state survive the policy drop


def test_schema_from_sql_applies_drop_table():
    s = _offline_schema(_TENANT_SCOPED + "DROP TABLE public.t;\n")
    assert [t.name for t in s.tables] == []


def test_db_free_diff_catches_alter_policy_loosening(tmp_path):
    base = tmp_path / "b.sql"
    base.write_text(_TENANT_SCOPED)
    head = tmp_path / "h.sql"
    head.write_text(
        _TENANT_SCOPED
        + "ALTER POLICY p ON public.t USING (true) WITH CHECK (true);\n"
    )
    bj, hj = tmp_path / "b.json", tmp_path / "h.json"
    for src, dst in ((base, bj), (head, hj)):
        assert (
            CliRunner()
            .invoke(main, ["snapshot", "--sql-file", str(src), "-o", str(dst)])
            .exit_code
            == 0
        )
    res = CliRunner().invoke(
        main, ["diff", str(bj), str(hj), "--fail-on", "dangerous"]
    )
    assert res.exit_code == 1  # the ALTER-POLICY loosening is not silently dropped


def test_db_free_diff_catches_restrictive_drop_policy(tmp_path):
    restr = (
        "CREATE TABLE public.t (id int, tenant_id uuid);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
        "  USING (true) WITH CHECK (true);\n"
        "CREATE POLICY r ON public.t AS RESTRICTIVE FOR ALL TO authenticated\n"
        "  USING (tenant_id = current_setting('app.tenant')::uuid);\n"
    )
    base = tmp_path / "b.sql"
    base.write_text(restr)
    head = tmp_path / "h.sql"
    head.write_text(restr + "DROP POLICY r ON public.t;\n")
    bj, hj = tmp_path / "b.json", tmp_path / "h.json"
    for src, dst in ((base, bj), (head, hj)):
        CliRunner().invoke(
            main, ["snapshot", "--sql-file", str(src), "-o", str(dst)]
        )
    res = CliRunner().invoke(
        main, ["diff", str(bj), str(hj), "--fail-on", "dangerous"]
    )
    assert res.exit_code == 1  # dropping a RESTRICTIVE filter loosens access


# --- snapshot --migrations: offline, layout-ordered directory input ---------


def _write_migrations(dir_path, files):
    dir_path.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (dir_path / name).write_text(body)


def test_snapshot_migrations_dir_builds_offline(tmp_path):
    mig = tmp_path / "migrations"
    _write_migrations(
        mig,
        {
            "20240101000000_init.sql": (
                "CREATE TABLE public.t (id int, tenant_id uuid);\n"
                "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
            ),
            "20240102000000_policy.sql": (
                "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
                "  USING (tenant_id = current_setting('app.tenant')::uuid);\n"
            ),
        },
    )
    out = tmp_path / "snap.json"
    res = CliRunner().invoke(
        main, ["snapshot", "--migrations", str(mig), "-o", str(out)]
    )
    assert res.exit_code == 0, res.output
    payload = json.loads(out.read_text())
    assert any(t["name"] == "t" for t in payload["tables"])
    # The policy from file 2 attached to the table from file 1 (ordered concat).
    policy_names = {
        p["policy_name"] for p in payload["policies"] if p["table_name"] == "t"
    }
    assert "p" in policy_names


def test_db_free_diff_via_migrations_catches_loosening(tmp_path):
    # The realistic PR scenario: head adds a NEW migration file that loosens a
    # policy created in an earlier one. The layout-ordered offline snapshot must
    # reflect the net (loosened) state so the diff gate fails — no database.
    common = {
        "20240101000000_init.sql": _TENANT_SCOPED,
    }
    base = tmp_path / "base"
    _write_migrations(base, common)
    head = tmp_path / "head"
    _write_migrations(
        head,
        {
            **common,
            "20240102000000_loosen.sql": (
                "ALTER POLICY p ON public.t USING (true) WITH CHECK (true);\n"
            ),
        },
    )
    bj, hj = tmp_path / "b.json", tmp_path / "h.json"
    for src, dst in ((base, bj), (head, hj)):
        assert (
            CliRunner()
            .invoke(main, ["snapshot", "--migrations", str(src), "-o", str(dst)])
            .exit_code
            == 0
        )
    res = CliRunner().invoke(
        main, ["diff", str(bj), str(hj), "--fail-on", "dangerous"]
    )
    assert res.exit_code == 1


def test_snapshot_migrations_conflicts_with_sql_file(tmp_path):
    mig = tmp_path / "migrations"
    _write_migrations(mig, {"20240101000000_init.sql": _TENANT_SCOPED})
    f = tmp_path / "extra.sql"
    f.write_text(_TENANT_SCOPED)
    res = CliRunner().invoke(
        main, ["snapshot", "--migrations", str(mig), "--sql-file", str(f)]
    )
    assert res.exit_code != 0 and "one offline source" in res.stderr.lower()

# --- pgrls pr: unified base->head verdict (lint-on-head + diff) --------------

# Error-clean (the only findings are info + PERF003, a warning — an offline
# snapshot can't see indexes; gate "pass" tests at the error floor).
# (SELECT current_setting(...)) is the PERF001-safe (InitPlan-cached) form.
_PR_CLEAN = (
    "CREATE TABLE public.t (id int, tenant_id uuid NOT NULL);\n"
    "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
    "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;\n"
    "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
    "  USING (tenant_id = (SELECT current_setting('app.t')::uuid))\n"
    "  WITH CHECK (tenant_id = (SELECT current_setting('app.t')::uuid));\n"
)
_PR_LOOSENED = (
    "CREATE TABLE public.t (id int, tenant_id uuid NOT NULL);\n"
    "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
    "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;\n"
    "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
    "  USING (true) WITH CHECK (true);\n"  # loosened vs the scoped base
)
# A Z3-ANALYZABLE scoped base for the diff-loosening test: the discriminator
# check is NOT wrapped in a (SELECT …) sub-select, so the classifier can prove
# `scoped → USING(true)` is a semantic loosening (DANGEROUS) instead of falling
# back to REQUIRES_REVIEW. (The sub-select form that keeps `_PR_CLEAN` PERF001-
# clean is opaque to the Z3 differ — a deliberate, separate trade-off. The base
# is never linted here, only diffed, so its unwrapped PERF001 shape is fine.)
_PR_SCOPED_BARE = (
    "CREATE TABLE public.t (id int, tenant_id uuid NOT NULL);\n"
    "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
    "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;\n"
    "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
    "  USING (tenant_id = current_setting('app.t')::uuid)\n"
    "  WITH CHECK (tenant_id = current_setting('app.t')::uuid);\n"
)


def _pr_snap(tmp_path, name, sql):
    src = tmp_path / f"{name}.sql"
    src.write_text(sql)
    out = tmp_path / f"{name}.json"
    r = CliRunner().invoke(
        main, ["snapshot", "--sql-file", str(src), "-o", str(out)]
    )
    assert r.exit_code == 0, r.output
    return str(out)


def test_pr_passes_on_clean_no_change(tmp_path):
    snap = _pr_snap(tmp_path, "clean", _PR_CLEAN)
    res = CliRunner().invoke(main, ["pr", snap, snap])
    assert res.exit_code == 0
    assert "PASSED" in res.stdout
    assert "No RLS policy changes" in res.stdout


def test_pr_fails_on_dangerous_loosening(tmp_path):
    base = _pr_snap(tmp_path, "base", _PR_SCOPED_BARE)
    head = _pr_snap(tmp_path, "head", _PR_LOOSENED)
    res = CliRunner().invoke(main, ["pr", base, head])
    assert res.exit_code == 1
    assert "FAILED" in res.stdout
    assert "loosened" in res.stdout.lower()  # the diff (regression) section


def test_pr_surfaces_lint_finding_in_head(tmp_path):
    # head adds an RLS-off table — the lint section flags SEC001 (and the diff
    # section its dangerous add); either alone fails the PR.
    base = _pr_snap(tmp_path, "base", _PR_CLEAN)
    head = _pr_snap(
        tmp_path, "head", _PR_CLEAN + "CREATE TABLE public.leaky (id int);\n"
    )
    res = CliRunner().invoke(main, ["pr", base, head])
    assert res.exit_code == 1
    assert "SEC001" in res.stdout  # lint-on-head section
    assert "Findings in the changed schema" in res.stdout


def test_pr_diff_threshold_gates_independently(tmp_path):
    # Dropping the only policy is a BREAKING diff change (not dangerous) and
    # leaves RLS-on-no-policy (SEC009, a warning). Pin --lint-fail-on error so
    # the incidental warning doesn't mask the DIFF threshold under test.
    base = _pr_snap(tmp_path, "base", _PR_CLEAN)
    head = _pr_snap(
        tmp_path, "head", _PR_CLEAN + "DROP POLICY p ON public.t;\n"
    )
    passed = CliRunner().invoke(
        main, ["pr", base, head, "--lint-fail-on", "error"]
    )
    assert passed.exit_code == 0  # breaking < dangerous; warning < error
    failed = CliRunner().invoke(
        main, ["pr", base, head, "--fail-on", "breaking", "--lint-fail-on", "error"]
    )
    assert failed.exit_code == 1  # now the breaking change trips the diff gate


def test_pr_text_format(tmp_path):
    snap = _pr_snap(tmp_path, "clean", _PR_CLEAN)
    res = CliRunner().invoke(main, ["pr", snap, snap, "--format", "text"])
    assert res.exit_code == 0 and "PASSED" in res.stdout
    # Pin the TEXT-format offline caveat (snap is an offline head → catalog skip).
    assert "not evaluated on this head" in res.stdout
    assert "offline from DDL" in res.stdout


# A schema whose only >=warning finding is SEC002 (RLS without FORCE); the
# policy is PERF001-safe and the discriminator is NOT NULL so nothing else
# above info fires (the catalog-dependent PERF003 is inert on an offline head).
_PR_LINT_DIRTY = (
    "CREATE TABLE public.t (id int, tenant_id uuid NOT NULL);\n"
    "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"  # no FORCE → SEC002
    "CREATE POLICY p ON public.t FOR ALL TO authenticated\n"
    "  USING (tenant_id = (SELECT current_setting('app.t')::uuid));\n"
)


def test_pr_fails_on_lint_only_when_diff_is_clean(tmp_path):
    # Self-diff (no policy change) but the head has a lint error → the lint gate
    # alone fails the PR; the diff section stays clean.
    snap = _pr_snap(tmp_path, "dirty", _PR_LINT_DIRTY)
    res = CliRunner().invoke(main, ["pr", snap, snap])
    assert res.exit_code == 1
    assert "No RLS policy changes" in res.stdout  # diff gate: nothing
    assert "SEC002" in res.stdout  # lint gate: the finding


def test_pr_honors_config_disable(tmp_path):
    # `--config` flows through to the lint pass: disabling the only >=warning
    # rule (SEC002) leaves just SEC007 (info) → the PR passes.
    snap = _pr_snap(tmp_path, "dirty", _PR_LINT_DIRTY)
    cfg = tmp_path / "pgrls.toml"
    cfg.write_text("[lint]\ndisable = ['SEC002']\n", encoding="utf-8")
    res = CliRunner().invoke(main, ["pr", snap, snap, "--config", str(cfg)])
    assert res.exit_code == 0, res.stdout
    assert "PASSED" in res.stdout


def test_pr_markdown_has_both_sections_and_verdict(tmp_path):
    snap = _pr_snap(tmp_path, "clean", _PR_CLEAN)
    out = CliRunner().invoke(main, ["pr", snap, snap]).stdout
    assert "RLS policy changes (base" in out  # regression section
    assert "Findings in the changed schema" in out  # lint section
    assert "pgrls PR check:" in out  # verdict line


def test_pr_bad_snapshot_is_clean_error(tmp_path):
    # A malformed BASE artifact fails with a ToolError (exit 2), not a traceback.
    bad = tmp_path / "bad.json"
    bad.write_text("this is not json", encoding="utf-8")
    good = _pr_snap(tmp_path, "good", _PR_CLEAN)
    res = CliRunner().invoke(main, ["pr", str(bad), good])
    assert res.exit_code == 2
    assert res.exception is None or isinstance(res.exception, SystemExit)


def test_pr_old_snapshot_head_skips_catalog_rules_like_lint(tmp_path):
    # The head snapshot's version drives the inert-rule skip (parity with
    # `lint --snapshot`): a pre-SEC047 snapshot must not run SEC047, so the
    # foreign-key rule can't spuriously fire (or crash) on absent fields.
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql("CREATE TABLE public.t (id int);\n").to_snapshot()
    snap["version"] = 8  # predates most catalog fields
    old = tmp_path / "old.json"
    old.write_text(json.dumps(snap), encoding="utf-8")
    res = CliRunner().invoke(main, ["pr", str(old), str(old)])
    # No crash; a RLS-off table still trips SEC001 (a non-catalog rule).
    assert res.exit_code in (0, 1)
    assert "SEC047" not in res.stdout  # the catalog rule was skipped, not run
    # The caveat must name the TRUE reason — an older snapshot version, not an
    # offline/DDL-built head (this snapshot is live-DB-shaped, just at version 8).
    assert "older pgrls" in res.stdout
    assert "offline from DDL" not in res.stdout


def test_pr_lint_pass_sees_policy_predicates(tmp_path):
    # Regression: the head's policy USING/WITH CHECK ASTs must be reparsed so
    # PREDICATE rules fire in the lint pass (like `lint --snapshot`). Without
    # the reparse, a real anon-read leak (SEC004: `auth.uid() IS NULL OR …`) in
    # the head silently false-PASSes because every predicate rule no-ops.
    leak = (
        "CREATE TABLE public.docs (id uuid, owner_id uuid);\n"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs FOR SELECT TO authenticated\n"
        "  USING (auth.uid() IS NULL OR owner_id = auth.uid());\n"
    )
    snap = _pr_snap(tmp_path, "leak", leak)
    res = CliRunner().invoke(main, ["pr", snap, snap, "--lint-fail-on", "error"])
    assert res.exit_code == 1  # SEC004 is a predicate rule
    assert "SEC004" in res.stdout


def test_pr_offline_head_skips_catalog_rules_and_caveats(tmp_path):
    # An offline (DDL-built) head can't model indexes / roles / function bodies
    # / FKs, so its catalog-dependent rules (here PERF003, which wants an index
    # on the tenant column) must be SKIPPED — neither fired on their empty
    # inputs (a false positive that would spuriously fail every clean offline
    # PR at the default warning floor) nor silently no-op'd and read as
    # coverage (a false clear). The report must NAME the skip so a clean
    # verdict is never mistaken for full coverage.
    snap = _pr_snap(tmp_path, "clean", _PR_CLEAN)  # RLS table, no index
    res = CliRunner().invoke(main, ["pr", snap, snap])  # default warning floor
    assert res.exit_code == 0  # PERF003 skipped → no spurious warning gate
    assert "PERF003" not in res.stdout
    assert "not evaluated on this head" in res.stdout  # the coverage caveat
    assert "catalog-dependent rule(s)" in res.stdout
    assert "offline from DDL" in res.stdout  # the offline-specific reason


def test_snapshot_offline_stamps_source_marker_and_reemit_preserves(tmp_path):
    # `snapshot --sql-file` stamps the offline provenance marker so downstream
    # lint / pr treat catalog rules as inert; re-emitting that snapshot
    # (`--snapshot IN`) must PRESERVE the marker — it's still catalog-incomplete.
    _pr_snap(tmp_path, "off", _PR_CLEAN)
    off_json = json.loads((tmp_path / "off.json").read_text(encoding="utf-8"))
    assert off_json["source"] == "sql"
    reemit = tmp_path / "reemit.json"
    r = CliRunner().invoke(
        main, ["snapshot", "--snapshot", str(tmp_path / "off.json"), "-o", str(reemit)]
    )
    assert r.exit_code == 0, r.output
    assert json.loads(reemit.read_text(encoding="utf-8"))["source"] == "sql"


def test_pr_unmarked_snapshot_runs_catalog_rules(tmp_path):
    # A snapshot WITHOUT the offline marker (a live-DB capture is catalog-
    # complete) must still run catalog-dependent rules — the marker is what
    # gates the skip, so its absence means full coverage, not a silent skip.
    # Guards against over-skipping: the provenance fix must not weaken a real
    # (DB-sourced) snapshot's rule coverage.
    from pgrls.schema_sources import schema_from_sql

    snap = schema_from_sql(_PR_CLEAN).to_snapshot()  # no "source" marker
    assert "source" not in snap
    p = tmp_path / "unmarked.json"
    p.write_text(json.dumps(snap), encoding="utf-8")
    res = CliRunner().invoke(main, ["pr", str(p), str(p)])
    assert "PERF003" in res.stdout  # the catalog rule DID run (index missing)
    assert "not evaluated on this head" not in res.stdout  # nothing skipped
    assert res.exit_code == 1  # PERF003 (warning) trips the default floor


def test_pr_file_url_head_strips_prefix_for_provenance_gating(tmp_path):
    # `pr` accepts a `file://` snapshot path (`_resolve_diff_source` strips it).
    # The provenance/version read (`_snapshot_meta`) MUST strip it the same way,
    # else the offline / version-skew coverage gating silently vanishes on a
    # `file://` head — a false clear the plain-path invocation would never show.
    from pgrls.schema_sources import schema_from_sql

    offline = _pr_snap(tmp_path, "off", _PR_CLEAN)  # source:"sql"
    off_url = CliRunner().invoke(
        main, ["pr", "file://" + offline, "file://" + offline]
    )
    assert off_url.exit_code == 0  # parity with the plain-path offline head
    assert "PERF003" not in off_url.stdout  # catalog rule still skipped
    assert "offline from DDL" in off_url.stdout  # offline caveat still emitted

    # Version-skew head (old-format, no marker) via `file://` — the genuine
    # false-clear direction the review found: version-gating must still fire.
    skew = schema_from_sql(_PR_CLEAN).to_snapshot()
    skew["version"] = 8
    p = tmp_path / "skew.json"
    p.write_text(json.dumps(skew), encoding="utf-8")
    skew_url = CliRunner().invoke(
        main, ["pr", "file://" + str(p), "file://" + str(p)]
    )
    assert "not evaluated on this head" in skew_url.stdout  # caveat present
    assert "older pgrls" in skew_url.stdout  # correct version-skew reason
    assert "offline from DDL" not in skew_url.stdout


# --- offline model fidelity vs live introspection ---------------------------
# Each of these pins a divergence found by differentially comparing
# `schema_from_sql` against `introspect` on the same DDL loaded into a real
# Postgres. Before these fixes the DB-free path (`lint --sql-file`, `pgrls pr`,
# MCP, LSP, `snapshot`) modelled a different schema than the one that ships.


def _only(sql: str):
    from pgrls.schema_sources import schema_from_sql

    schema = schema_from_sql(sql, schemas=("public",))
    assert len(schema.tables) == 1, [t.qualified_name for t in schema.tables]
    return schema.tables[0]


def test_offline_inline_not_null_is_captured():
    # Every offline column used to come back nullable, which handed SEC030
    # (nullable tenant discriminator) a false positive on every DB-free run.
    t = _only("CREATE TABLE t (id int, tenant text NOT NULL);")
    assert {c.name: c.is_nullable for c in t.column_details} == {
        "id": True,
        "tenant": False,
    }


def test_offline_primary_key_implies_not_null():
    # Both spellings: inline and as a table-level constraint.
    inline = _only("CREATE TABLE t (id int PRIMARY KEY, x text);")
    assert {c.name: c.is_nullable for c in inline.column_details}["id"] is False
    table_level = _only("CREATE TABLE t (id int, x text, PRIMARY KEY (id));")
    assert {
        c.name: c.is_nullable for c in table_level.column_details
    }["id"] is False
    altered = _only("CREATE TABLE t (id int, x text); ALTER TABLE t ADD PRIMARY KEY (id);")
    assert {c.name: c.is_nullable for c in altered.column_details}["id"] is False


def test_offline_pg18_not_null_constraints():
    # pglast 8 parses PG18's table-level / named NOT NULL. A validated one
    # makes the column NOT NULL; a NOT VALID one leaves existing NULLs, so the
    # column stays nullable, as introspection reads it.
    import pglast

    if not pglast.__version__.startswith("v8"):
        pytest.skip("PG18 NOT NULL constraint syntax needs pglast 8")
    sql = {
        "CREATE TABLE t (id int, tenant text, NOT NULL tenant);": False,
        "CREATE TABLE t (id int, tenant text);"
        " ALTER TABLE t ADD CONSTRAINT tnn NOT NULL tenant;": False,
        "CREATE TABLE t (id int, tenant text);"
        " ALTER TABLE t ADD CONSTRAINT tnn NOT NULL tenant NOT VALID;": True,
        # A name reused after the NOT VALID NOT NULL is gone is not it.
        "CREATE TABLE t (id int, tenant int);"
        " ALTER TABLE t ADD CONSTRAINT nn NOT NULL tenant NOT VALID;"
        " ALTER TABLE t ALTER COLUMN tenant DROP NOT NULL;"
        " ALTER TABLE t ADD CONSTRAINT nn CHECK (tenant > 0) NOT VALID;"
        " ALTER TABLE t VALIDATE CONSTRAINT nn;": True,
        # Validating it — SEC030's remedy — makes the column NOT NULL.
        "CREATE TABLE t (id int, tenant text);"
        " ALTER TABLE t ADD CONSTRAINT tnn NOT NULL tenant NOT VALID;"
        " ALTER TABLE t VALIDATE CONSTRAINT tnn;": False,
        "CREATE TABLE t (id int, tenant text);"
        " ALTER TABLE t ADD CONSTRAINT tnn NOT NULL tenant NOT VALID;"
        " ALTER TABLE t RENAME CONSTRAINT tnn TO tn2; ALTER TABLE t VALIDATE CONSTRAINT tn2;": False,
        # In CREATE TABLE there are no rows yet: Postgres stores it validated.
        "CREATE TABLE t (id int, tenant text, CONSTRAINT tnn NOT NULL tenant NOT VALID);": False,
    }
    for stmt, nullable in sql.items():
        t = _only(stmt)
        assert {c.name: c.is_nullable for c in t.column_details}["tenant"] is nullable, stmt


def test_offline_no_inherit_not_null_is_not_inherited():
    # PG18: an INHERITS child does not get a parent's NOT NULL … NO INHERIT
    # (measured), so the child's column is nullable.
    import pglast

    from pgrls.schema_sources import schema_from_sql

    if not pglast.__version__.startswith("v8"):
        pytest.skip("NOT NULL … NO INHERIT is PG18 syntax (pglast 8)")
    for parent in (
        "CREATE TABLE p (id int, tenant int NOT NULL NO INHERIT);",
        "CREATE TABLE p (id int, tenant int, NOT NULL tenant NO INHERIT);",
    ):
        schema = schema_from_sql(parent + " CREATE TABLE c (x int) INHERITS (p);",
                                 schemas=("public",))
        nullable = {t.name: {c.name: c.is_nullable for c in t.column_details}["tenant"]
                    for t in schema.tables}
        assert nullable == {"p": False, "c": True}, parent


def test_offline_parent_rename_redirects_only_earlier_children():
    # A child created after the rename names the table that now has the old
    # name, not the renamed one (measured on PG18).
    from pgrls.schema_sources import schema_from_sql

    schema = schema_from_sql(
        "CREATE TABLE p (a int, k int) PARTITION BY LIST (k);"
        " CREATE TABLE o (a int, k int) PARTITION BY LIST (k);"
        " CREATE TABLE early PARTITION OF p FOR VALUES IN (0);"
        " ALTER TABLE p RENAME TO tmp; ALTER TABLE o RENAME TO p; ALTER TABLE tmp RENAME TO o;"
        " CREATE TABLE late PARTITION OF p FOR VALUES IN (1);",
        schemas=("public",))
    parent = {t.name: t.partition_of for t in schema.tables}
    assert parent["early"] == ("public", "o") and parent["late"] == ("public", "p")


def test_offline_parent_constraint_rename_reaches_a_same_named_child_constraint():
    # PG18 renames a child's own constraint of the parent's name too — even
    # one joined by ALTER TABLE … INHERIT, which offline does not follow.
    import pglast

    from pgrls.schema_sources import schema_from_sql

    if not pglast.__version__.startswith("v8"):
        pytest.skip("named NOT NULL constraints are PG18 syntax")
    schema = schema_from_sql(
        "CREATE TABLE p (id int CONSTRAINT k NOT NULL);"
        " CREATE TABLE c (id int NOT NULL, tenant_id uuid CONSTRAINT k NOT NULL);"
        " ALTER TABLE c INHERIT p; ALTER TABLE p RENAME CONSTRAINT k TO z;"
        " ALTER TABLE c DROP CONSTRAINT z;",
        schemas=("public",))
    child = next(t for t in schema.tables if t.name == "c")
    assert {c.name: c.is_nullable for c in child.column_details}["tenant_id"] is True


def test_offline_drop_constraint_of_a_not_null():
    # PG18 stores NOT NULL as a named constraint, and DROP CONSTRAINT drops
    # it; an unnamed one is `<table>_<column>_not_null`.
    auto = _only(
        "CREATE TABLE t (id int, tenant text NOT NULL);"
        " ALTER TABLE t DROP CONSTRAINT t_tenant_not_null;"
    )
    assert {c.name: c.is_nullable for c in auto.column_details}["tenant"] is True
    # Postgres shortens the longer name to fit 63 bytes (measured on PG18).
    long_col = "tenant_" + "x" * 56
    long_table = "orders_" + "y" * 50
    for table, col, conname in (
        ("orders", long_col, f"orders_{long_col[:47]}_not_null"),
        (long_table, "tenant_id", f"{long_table[:44]}_tenant_id_not_null"),
    ):
        t = _only(f"CREATE TABLE {table} (id int, {col} text NOT NULL);"
                  f" ALTER TABLE {table} DROP CONSTRAINT {conname};")
        assert {c.name: c.is_nullable for c in t.column_details}[col] is True, conname
    for sql in (
        # A clash adds a digit; a renamed constraint keeps its column; an
        # unnamed one keeps the table name it was created under.
        "CREATE TABLE t (id int, tenant text NOT NULL);"
        " ALTER TABLE t DROP CONSTRAINT t_tenant_not_null1;",
        "CREATE TABLE t (id int, tenant text NOT NULL);"
        " ALTER TABLE t RENAME CONSTRAINT t_tenant_not_null TO tn;"
        " ALTER TABLE t DROP CONSTRAINT tn;",
        "CREATE TABLE old (id int, tenant text NOT NULL); ALTER TABLE old RENAME TO t;"
        " ALTER TABLE t DROP CONSTRAINT old_tenant_not_null;",
        # An auto-name several columns could have: all of them.
        "CREATE TABLE t (tenant text NOT NULL, tenant_b int NOT NULL);"
        " ALTER TABLE t RENAME CONSTRAINT t_tenant_not_null TO keep;"
        " ALTER TABLE t DROP CONSTRAINT keep;",
    ):
        t = _only(sql)
        assert {c.name: c.is_nullable for c in t.column_details}["tenant"] is True, sql
    # An inherited NOT NULL keeps the parent's name; a detached child can
    # drop it by that name (measured on PG18).
    from pgrls.schema_sources import schema_from_sql

    for detach in ("ALTER TABLE c NO INHERIT p;", ""):
        schema = schema_from_sql(
            "CREATE TABLE p (a int NOT NULL, b int); CREATE TABLE c () INHERITS (p);"
            f" {detach} ALTER TABLE c DROP CONSTRAINT p_a_not_null;",
            schemas=("public",))
        child = next(t for t in schema.tables if t.name == "c")
        assert {c.name: c.is_nullable for c in child.column_details}["a"] is True
    # `SET NOT NULL` validates a NOT VALID one in place, keeping its name; a
    # parent's RENAME CONSTRAINT renames its children's copies (measured).
    import pglast

    if pglast.__version__.startswith("v8"):
        for sql, table in (
            ("CREATE TABLE t (id int, a int);"
             " ALTER TABLE t ADD CONSTRAINT nn NOT NULL a NOT VALID;"
             " ALTER TABLE t ALTER COLUMN a SET NOT NULL; ALTER TABLE t DROP CONSTRAINT nn;", "t"),
            ("CREATE TABLE p (id int, a int NOT NULL); CREATE TABLE c () INHERITS (p);"
             " ALTER TABLE p RENAME CONSTRAINT p_a_not_null TO keep;"
             " ALTER TABLE c NO INHERIT p; ALTER TABLE c DROP CONSTRAINT keep;", "c"),
            # A child that left before the rename keeps the old name.
            ("CREATE TABLE p (id int, a int CONSTRAINT req NOT NULL, k int)"
             " PARTITION BY LIST (k); CREATE TABLE c PARTITION OF p FOR VALUES IN (1);"
             " ALTER TABLE p DETACH PARTITION c; ALTER TABLE p RENAME CONSTRAINT req TO p_req;"
             " ALTER TABLE c DROP CONSTRAINT req;", "c"),
            # The parent's rename reaches children after the parent is renamed.
            ("CREATE TABLE p (id int, a int CONSTRAINT req NOT NULL, k int)"
             " PARTITION BY LIST (k); CREATE TABLE c PARTITION OF p FOR VALUES IN (1);"
             " ALTER TABLE p RENAME TO events;"
             " ALTER TABLE events RENAME CONSTRAINT req TO events_req;"
             " ALTER TABLE events DETACH PARTITION c; ALTER TABLE c DROP CONSTRAINT events_req;",
             "c"),
        ):
            schema = schema_from_sql(sql, schemas=("public",))
            t = next(x for x in schema.tables if x.name == table)
            assert {c.name: c.is_nullable for c in t.column_details}["a"] is True, sql
    # A primary key's columns stay NOT NULL when it is dropped.
    pk = _only("CREATE TABLE t (id int, CONSTRAINT t_pk PRIMARY KEY (id));"
               " ALTER TABLE t DROP CONSTRAINT t_pk;")
    assert {c.name: c.is_nullable for c in pk.column_details}["id"] is False
    other = _only(
        "CREATE TABLE t (id int, tenant text NOT NULL, CONSTRAINT ck CHECK (id > 0));"
        " ALTER TABLE t DROP CONSTRAINT ck;"
    )
    assert {c.name: c.is_nullable for c in other.column_details}["tenant"] is False
    import pglast

    if not pglast.__version__.startswith("v8"):
        return  # named NOT NULL constraints are PG18 syntax
    for sql in (
        "CREATE TABLE t (id int, tenant text CONSTRAINT nn NOT NULL);",
        "CREATE TABLE t (id int, tenant text, CONSTRAINT nn NOT NULL tenant);",
        "CREATE TABLE t (id int, tenant text); ALTER TABLE t ADD CONSTRAINT nn NOT NULL tenant;",
    ):
        t = _only(sql + " ALTER TABLE t DROP CONSTRAINT nn;")
        assert {c.name: c.is_nullable for c in t.column_details}["tenant"] is True, sql


def test_offline_alter_column_set_and_drop_not_null():
    setted = _only(
        "CREATE TABLE t (id int, tenant text);"
        " ALTER TABLE t ALTER COLUMN tenant SET NOT NULL;"
    )
    assert {c.name: c.is_nullable for c in setted.column_details}["tenant"] is False
    dropped = _only(
        "CREATE TABLE t (id int, tenant text NOT NULL);"
        " ALTER TABLE t ALTER COLUMN tenant DROP NOT NULL;"
    )
    assert {c.name: c.is_nullable for c in dropped.column_details}["tenant"] is True


def test_offline_alter_table_drop_column_is_applied():
    # A migration that drops a column left it in the model, so column-keyed
    # rules fired on a column that no longer exists.
    t = _only("CREATE TABLE t (id int, secret text); ALTER TABLE t DROP COLUMN secret;")
    assert [c.name for c in t.column_details] == ["id"]


def test_offline_alter_table_rename_is_applied():
    # The finding used to be reported against the pre-rename name — a
    # `pgrls pr` annotation naming a table that does not exist.
    t = _only("CREATE TABLE staging (id int); ALTER TABLE staging RENAME TO users;")
    assert t.qualified_name == "public.users"


def test_offline_rename_carries_later_alters():
    t = _only(
        "CREATE TABLE staging (id int);"
        " ALTER TABLE staging RENAME TO users;"
        " ALTER TABLE users ENABLE ROW LEVEL SECURITY;"
    )
    assert t.qualified_name == "public.users"
    assert t.rls_enabled is True


def test_offline_rename_onto_a_later_created_name_is_applied():
    # The model holds every CREATE of the file before the renames replay, so
    # a later `CREATE TABLE IF NOT EXISTS users` (skipped live) must not stop
    # the rename onto `users`: the RLS state stayed on `users_tmp`.
    t = _only(
        "CREATE TABLE IF NOT EXISTS users_tmp (id int);"
        " ALTER TABLE users_tmp ENABLE ROW LEVEL SECURITY;"
        " ALTER TABLE users_tmp RENAME TO users;"
        " CREATE TABLE IF NOT EXISTS users (id int);"
    )
    assert t.qualified_name == "public.users"
    assert t.rls_enabled is True


@pytest.mark.parametrize("path, later", [
    ("public, pg_temp", ""),
    ("public, extensions", " CREATE SCHEMA IF NOT EXISTS extensions;"),
])
def test_a_name_found_on_the_path_is_not_refused_for_a_later_entry(path, later):
    # Postgres stops at the first schema holding the name, so a later entry
    # pgrls cannot follow is never reached.
    t = _only(
        f"SET search_path = {path}; CREATE TABLE t (id int);"
        f" ALTER TABLE t ENABLE ROW LEVEL SECURITY;{later}"
    )
    assert t.qualified_name == "public.t" and t.rls_enabled is True


def test_a_path_naming_pg_temp_after_a_schema_finds_the_schema_first():
    # `public, pg_temp`: Postgres searches public before the temp table, so
    # the policy lands on public.accounts, not on the temp table that hid it.
    t = _only(
        "SET search_path = public, pg_temp; CREATE TABLE accounts (id int);"
        " CREATE TEMP TABLE accounts (id int);"
        " ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;"
    )
    assert t.qualified_name == "public.accounts" and t.rls_enabled is True


def test_a_temp_table_on_a_connected_databases_path_is_refused():
    # The database may set `public, pg_temp`, which finds public.a first.
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError, match=r"sets search_path \(a \\connect"):
        schema_from_sql(
            "CREATE DATABASE d;\nALTER DATABASE d SET search_path = public, pg_temp;\n"
            "\\connect d\nCREATE TABLE public.a (id int);\n"
            "CREATE TEMP TABLE a (id int);\nALTER TABLE a DISABLE ROW LEVEL SECURITY;\n"
        )


def test_a_view_moved_out_of_the_path_no_longer_answers_a_name():
    from pgrls.schema_sources import schema_from_sql
    schema = schema_from_sql(
        "CREATE SCHEMA app; CREATE SCHEMA stage; CREATE TABLE public.docs (id int);"
        " CREATE VIEW app.docs AS SELECT 1 AS a; ALTER VIEW app.docs SET SCHEMA stage;"
        " SET search_path = app, public; ALTER TABLE docs ENABLE ROW LEVEL SECURITY;"
    )
    assert {t.qualified_name: t.rls_enabled for t in schema.tables}["public.docs"] is True


@pytest.mark.parametrize("drop", [
    "DROP TABLE app.base CASCADE;",            # takes the view on it
    "DROP OWNED BY r;",
    "CREATE TABLE app.p (a int) PARTITION BY LIST (a); DROP TABLE app.p;",
])
def test_a_name_a_drop_may_have_freed_is_refused(drop):
    # The view app.docs may be gone, so `docs` may be public.docs.
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError,
                       match="more than one schema on its search_path|DROP OWNED that may"):
        schema_from_sql(
            "CREATE SCHEMA app; CREATE TABLE public.docs (id int);"
            " CREATE TABLE app.base (a int); CREATE VIEW app.docs AS SELECT a FROM app.base;"
            f" {drop} SET search_path = app, public;"
            " ALTER TABLE docs ENABLE ROW LEVEL SECURITY;"
        )


def test_a_connect_inside_a_restrict_is_refused():
    # psql refuses it there, so the session never reconnects.
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError, match="inside a"):
        schema_from_sql("\\restrict abc\nSET search_path = app, public;\n"
                        "\\connect db\nCREATE TABLE t (id int);\n\\unrestrict abc\n")


def test_an_unqualified_view_moved_or_a_table_renamed_by_alter_index_is_followed():
    from pgrls.schema_sources import schema_from_sql
    for move in ("SET search_path = app; ALTER VIEW docs SET SCHEMA stage;",
                 "ALTER INDEX app.docs RENAME TO gone;"):
        kind = "VIEW app.docs AS SELECT 1 AS a" if "VIEW" in move else "TABLE app.docs (a int)"
        schema = schema_from_sql(
            f"CREATE SCHEMA app; CREATE SCHEMA stage; CREATE TABLE public.docs (id int);"
            f" CREATE {kind}; {move} SET search_path = app, public;"
            " ALTER TABLE docs ENABLE ROW LEVEL SECURITY;"
        )
        assert {t.qualified_name: t.rls_enabled for t in schema.tables}["public.docs"] is True, move


def test_a_name_two_path_schemas_hold_is_refused():
    # DROP COLUMN … CASCADE may have taken the view app.t (so `t` is
    # public.t); pgrls does not follow every such removal.
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError, match="more than one schema on its search_path"):
        schema_from_sql(
            "CREATE SCHEMA app; CREATE TABLE public.t (id int); CREATE TABLE app.base (c int);"
            " CREATE VIEW app.t AS SELECT c FROM app.base;"
            " ALTER TABLE app.base DROP COLUMN c CASCADE; SET search_path = app, public;"
            " ALTER TABLE t DISABLE ROW LEVEL SECURITY;"
        )


@pytest.mark.parametrize("line", [
    "\\restrict abc\n\\echo hello\n\\unrestrict abc",   # psql refuses it there
    "\\unrestrict zzz",                                      # not restricted
    "\\restrict",                                            # no key
    "\\pset format bogus", "\\pset nosuchoption", "\\timing maybe",
    "\\set ECHO bogus", "\\set VERBOSITY loud", "\\set ECHO",
])
def test_a_harmless_psql_command_psql_rejects_is_refused(line):
    # Under ON_ERROR_STOP psql stops at it, so the rest does not run.
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError, match="psql"):
        schema_from_sql(f"\\set ON_ERROR_STOP on\n{line}\nCREATE TABLE t (id int);\n")


@pytest.mark.parametrize("sql, expected", [
    # A view on a temporary table is temporary: dropping it leaves app.v.
    ("CREATE SCHEMA app; CREATE TABLE app.v (id int); CREATE TEMP TABLE tmp (id int);"
     " SET search_path = app, public; CREATE VIEW v AS SELECT * FROM tmp; DROP VIEW v;"
     " ALTER TABLE v ENABLE ROW LEVEL SECURITY;", "app.v"),
    # A DROP SCHEMA succeeds only once what it held is gone.
    ("CREATE SCHEMA app; CREATE TABLE app.p (d int) PARTITION BY RANGE (d);"
     " CREATE TABLE app.p1 PARTITION OF app.p FOR VALUES FROM (1) TO (2);"
     " DROP TABLE app.p; DROP SCHEMA app; SET search_path = app, public;"
     " CREATE TABLE t (id int); ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "public.t"),
    # An unqualified ALTER INDEX may name an index: the table keeps its name.
    ("CREATE SCHEMA app; CREATE TABLE public.x (id int); CREATE TABLE app.b (id int);"
     " CREATE INDEX x ON app.b (id); SET search_path = app, public;"
     " ALTER INDEX x RENAME TO x_idx; ALTER TABLE x ENABLE ROW LEVEL SECURITY;", "public.x"),
    # REASSIGN OWNED passes app to s1, which DROP OWNED then drops; or to
    # postgres, so it stays. A role rename, or a no-op CREATE SCHEMA IF NOT
    # EXISTS, keeps who owns it.
    ("CREATE SCHEMA app AUTHORIZATION r1; REASSIGN OWNED BY r1 TO s1; DROP OWNED BY s1;"
     " SET search_path = app, public; CREATE TABLE t (id int);"
     " ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "public.t"),
    ("CREATE SCHEMA app AUTHORIZATION r1; REASSIGN OWNED BY r1 TO postgres; DROP OWNED BY r1;"
     " SET search_path = app, public; CREATE TABLE t (id int);"
     " ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "app.t"),
    ("CREATE SCHEMA app AUTHORIZATION r1; ALTER ROLE r1 RENAME TO q; DROP OWNED BY q;"
     " SET search_path = app, public; CREATE TABLE t (id int);"
     " ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "public.t"),
    # ALTER SCHEMA … OWNER TO gives one the SQL did not create an owner;
    # a SET ROLE makes CURRENT_USER that role.
    ("ALTER SCHEMA app OWNER TO r1; CREATE TABLE app.x (id int); DROP OWNED BY r1;"
     " SET search_path = app, public; CREATE TABLE t (id int);"
     " ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "public.t"),
    ("CREATE SCHEMA app AUTHORIZATION r1; SET ROLE r1; REASSIGN OWNED BY CURRENT_USER TO s1;"
     " RESET ROLE; DROP OWNED BY s1; SET search_path = app, public; CREATE TABLE t (id int);"
     " ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "public.t"),
    # A CREATE after a DROP OWNED that may have dropped app makes it anew.
    ("CREATE SCHEMA app AUTHORIZATION u1; DROP OWNED BY CURRENT_USER;"
     " CREATE SCHEMA app AUTHORIZATION r1; DROP OWNED BY r1; SET search_path = app, public;"
     " CREATE TABLE t (id int); ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "public.t"),
    ("CREATE SCHEMA app AUTHORIZATION r1; CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION s1;"
     " DROP OWNED BY r1; SET search_path = app, public; CREATE TABLE t (id int);"
     " ALTER TABLE t ENABLE ROW LEVEL SECURITY;", "public.t"),
])
def test_relations_postgres_removes_or_keeps_are_followed(sql, expected):
    from pgrls.schema_sources import schema_from_sql
    assert {t.qualified_name: t.rls_enabled for t in schema_from_sql(sql).tables}[expected] is True


@pytest.mark.parametrize("sql", [
    # DROP OWNED may drop app, owned by the connecting role.
    "CREATE SCHEMA app; SET search_path = app, public; DROP OWNED BY r; CREATE TABLE t (id int);",
    # app.x may be gone with its parent, and then `mid` decides.
    "CREATE SCHEMA app; CREATE TABLE public.x (id int); CREATE TABLE app.parent (id int);"
    " CREATE TABLE app.x () INHERITS (app.parent); DROP TABLE app.parent CASCADE;"
    " SET search_path = app, mid, public; ALTER TABLE x DISABLE ROW LEVEL SECURITY;"
    " CREATE SCHEMA IF NOT EXISTS mid;",
    "\\restrict ''\nCREATE TABLE t (id int);\n\\unrestrict ''\n",
    # REASSIGN OWNED BY CURRENT_USER under a SET ROLE: app may not pass.
    "CREATE SCHEMA app; SET ROLE r2; REASSIGN OWNED BY CURRENT_USER TO s1; RESET ROLE;"
    " DROP OWNED BY s1; SET search_path = app; CREATE TABLE t (id int);",
    # A database that sets `role`: CURRENT_USER is that role or the session
    # user by turns, so REASSIGN OWNED BY it may or may not pass app on.
    "CREATE DATABASE d;\nALTER DATABASE d SET role = 'r1';\n\\connect d\nCREATE SCHEMA app;\n"
    "SET ROLE NONE;\nREASSIGN OWNED BY CURRENT_USER TO s1;\nDROP OWNED BY r1;\n"
    "SET search_path = app, public;\nCREATE TABLE u (id int);\n",
    # A schema there before the SQL, whose owner it does not know.
    "CREATE TABLE app.x (id int); DROP OWNED BY r1; SET search_path = app, public;"
    " CREATE TABLE t (id int);",
    # A role that may have no USAGE on app, which Postgres then skips.
    "CREATE SCHEMA audit; SET SESSION AUTHORIZATION app_user;"
    " SET search_path = audit, public; CREATE TABLE items (id int);",
    # A schema made again grants no one USAGE (a reset `public` too).
    "CREATE SCHEMA app; GRANT USAGE ON SCHEMA app TO r1; DROP SCHEMA app CASCADE;"
    " CREATE SCHEMA app; SET ROLE r1; SET search_path = app, public; CREATE TABLE t (id int);",
    "DROP SCHEMA public CASCADE; CREATE SCHEMA public; SET ROLE r1; CREATE TABLE t (id int);",
    # app.t and ext.t: r1 may lack USAGE on ext (through a group), so either.
    "CREATE SCHEMA app AUTHORIZATION r1; CREATE SCHEMA ext; CREATE TABLE app.t (id int);"
    " CREATE TABLE ext.t (id int); GRANT USAGE ON SCHEMA ext TO grp; SET ROLE r1;"
    " SET search_path = app, ext; ALTER TABLE t ENABLE ROW LEVEL SECURITY;",
    # An owner may revoke its own USAGE; a renamed role takes its grants.
    "CREATE SCHEMA app AUTHORIZATION r1; SET ROLE r1; REVOKE USAGE ON SCHEMA app FROM r1;"
    " SET search_path = app, public; CREATE TABLE t (id int);",
    "CREATE SCHEMA app; GRANT USAGE ON SCHEMA app TO ua; ALTER ROLE ua RENAME TO ub;"
    " SET ROLE ua; SET search_path = app, public; CREATE TABLE t (id int);",
    # DROP OWNED revokes r1's USAGE on app.
    "CREATE SCHEMA app AUTHORIZATION r2; GRANT USAGE ON SCHEMA app TO r1; DROP OWNED BY r1;"
    " SET search_path = app, public; SET ROLE r1; CREATE TABLE t (id int);",
    # An INSERT may fire a trigger that drops the temporary t.
    "CREATE TABLE public.t (id int); CREATE TEMP TABLE t (id int); CREATE TABLE public.log (id int);"
    " INSERT INTO public.log VALUES (1); GRANT SELECT ON t TO anon;",
])
def test_what_pgrls_cannot_tell_is_refused(sql):
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError):
        schema_from_sql(sql)


def test_a_table_made_again_is_a_partition_only_as_its_create_says():
    # DETACH, an INSERT (which may run code), then CREATE … IF NOT EXISTS:
    # either way events_2024 is a table of its own.
    schema = __import__("pgrls.schema_sources", fromlist=["x"]).schema_from_sql(
        "CREATE TABLE public.events (id int, at date) PARTITION BY RANGE (at);"
        " CREATE TABLE public.events_2024 PARTITION OF public.events"
        " FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');"
        " INSERT INTO public.events VALUES (1, '2024-03-01');"
        " ALTER TABLE public.events DETACH PARTITION public.events_2024;"
        " CREATE TABLE IF NOT EXISTS public.events_2024 (id int, at date);")
    assert {t.name: t.partition_of for t in schema.tables}["events_2024"] is None


def test_an_if_not_exists_that_may_skip_keeps_a_table_standalone():
    from pgrls.schema_sources import schema_from_sql
    # c may be the standalone table still (Postgres skips the IF NOT EXISTS).
    schema = schema_from_sql(
        "CREATE TABLE public.p (id int) PARTITION BY RANGE (id); CREATE TABLE public.c (id int);"
        " DROP TABLE IF EXISTS public.zzz;"
        " CREATE TABLE IF NOT EXISTS public.c PARTITION OF public.p FOR VALUES FROM (0) TO (10);")
    assert {t.name: t.partition_of for t in schema.tables}["c"] is None
    # A re-create that would close a cycle of partitions is no partition.
    schema = schema_from_sql(
        "CREATE TABLE a (id int) PARTITION BY RANGE (id);"
        " CREATE TABLE b PARTITION OF a FOR VALUES FROM (0) TO (100) PARTITION BY RANGE (id);"
        " ALTER TABLE a DETACH PARTITION b; DROP TABLE IF EXISTS a;"
        " CREATE TABLE IF NOT EXISTS a PARTITION OF b FOR VALUES FROM (0) TO (10);")
    assert len(schema.tables) == 2


@pytest.mark.parametrize("sql", [
    # A DETACH before an IF NOT EXISTS that may skip still applies.
    "CREATE TABLE public.p (id int) PARTITION BY RANGE (id); CREATE TABLE public.c (id int);"
    " DROP TABLE public.c; CREATE TABLE public.c PARTITION OF public.p FOR VALUES FROM (0) TO (10);"
    " ALTER TABLE public.p DETACH PARTITION public.c; DROP VIEW IF EXISTS x;"
    " CREATE TABLE IF NOT EXISTS public.c PARTITION OF public.p FOR VALUES FROM (0) TO (10);",
    # A table made again from a query is a table of its own.
    "CREATE TABLE public.p (id int) PARTITION BY LIST (id);"
    " CREATE TABLE public.c PARTITION OF public.p FOR VALUES IN (1); DROP TABLE public.c;"
    " CREATE TABLE public.c AS SELECT 1 AS id;",
])
def test_a_table_that_ends_standalone_is_no_partition(sql):
    from pgrls.schema_sources import schema_from_sql
    assert {t.name: t.partition_of for t in schema_from_sql(sql).tables}["c"] is None


def test_a_renamed_table_keeps_its_links_when_its_old_name_is_made_again():
    from pgrls.schema_sources import schema_from_sql
    schema = schema_from_sql(
        "CREATE TABLE public.p (id int) PARTITION BY RANGE (id); CREATE TABLE public.b (id int);"
        " ALTER TABLE public.b RENAME TO a;"
        " CREATE TABLE public.b PARTITION OF public.p FOR VALUES FROM (1) TO (2);")
    assert {t.name: t.partition_of for t in schema.tables}["a"] is None


def test_a_usable_schema_and_a_lone_path_entry_resolve():
    # app_user owns app, or was granted USAGE: Postgres searches it.
    for grant in ("CREATE SCHEMA app AUTHORIZATION app_user;",
                  "CREATE SCHEMA app; GRANT USAGE ON SCHEMA app TO app_user;",
                  # Revoking only the grant option keeps USAGE.
                  "CREATE SCHEMA app; GRANT USAGE ON SCHEMA app TO app_user WITH GRANT OPTION;"
                  " REVOKE GRANT OPTION FOR USAGE ON SCHEMA app FROM app_user;",
                  # A schema made again, or given to a new owner, is the owner's.
                  "CREATE SCHEMA app AUTHORIZATION app_user; REVOKE USAGE ON SCHEMA app FROM app_user;"
                  " DROP SCHEMA app; CREATE SCHEMA app AUTHORIZATION app_user;",
                  "CREATE SCHEMA app; REVOKE ALL ON SCHEMA app FROM app_user;"
                  " ALTER SCHEMA app OWNER TO app_user;"):
        t = _only(f"{grant} CREATE TABLE app.items (id int); SET ROLE app_user;"
                  " SET search_path = app, public; ALTER TABLE items ENABLE ROW LEVEL SECURITY;")
        assert t.qualified_name == "app.items" and t.rls_enabled is True, grant
    # A path of one schema has one place a name can be (else it errors).
    t = _only("SET search_path TO app; ALTER TABLE users ENABLE ROW LEVEL SECURITY;")
    assert t.qualified_name == "app.users"


def test_offline_create_table_if_not_exists_does_not_duplicate_columns():
    # The second CREATE re-walked tableElts and appended the columns again.
    t = _only(
        "CREATE TABLE t (id int PRIMARY KEY, tenant text);"
        " CREATE TABLE IF NOT EXISTS t (id int);"
    )
    assert [c.name for c in t.column_details] == ["id", "tenant"]


def test_offline_partition_child_records_parent_and_columns():
    from pgrls.schema_sources import schema_from_sql

    schema = schema_from_sql(
        "CREATE TABLE evt (id int, tenant text) PARTITION BY LIST (tenant);"
        " ALTER TABLE evt ENABLE ROW LEVEL SECURITY;"
        " CREATE TABLE evt_a PARTITION OF evt FOR VALUES IN ('a');",
        schemas=("public",),
    )
    child = next(t for t in schema.tables if t.name == "evt_a")
    # Without partition_of the child looked like a standalone RLS-off table and
    # SEC001 false-positived on it, where live correctly cedes to SEC041.
    assert child.partition_of == ("public", "evt")
    assert [c.name for c in child.column_details] == ["id", "tenant"]


def test_offline_inherits_child_records_parents_and_columns():
    from pgrls.schema_sources import schema_from_sql

    schema = schema_from_sql(
        "CREATE TABLE parent (id int PRIMARY KEY, tenant text);"
        " CREATE TABLE child () INHERITS (parent);",
        schemas=("public",),
    )
    child = next(t for t in schema.tables if t.name == "child")
    assert child.inherits == (("public", "parent"),)
    assert child.partition_of is None
    assert [c.name for c in child.column_details] == ["id", "tenant"]
    # Inherited nullability comes along too.
    assert {c.name: c.is_nullable for c in child.column_details}["id"] is False


# --- offline model: DROP ordering + data-derived tables (MF4) ---------------


@pytest.mark.parametrize(
    ("label", "sql", "expected"),
    [
        # A rebuild migration. `CREATE TABLE` resolves in pass 1 and drops in
        # pass 2, so an EARLIER drop used to remove the table the LATER create
        # had just established — the model reported no table at all, and
        # nothing lints a table that isn't there.
        ("rebuild", "DROP TABLE IF EXISTS public.t; CREATE TABLE public.t (id int);", ["public.t"]),
        ("create-drop-create", "CREATE TABLE public.t (id int); DROP TABLE public.t; CREATE TABLE public.t (id int);", ["public.t"]),
        # …while a genuine drop must still drop.
        ("genuine drop", "CREATE TABLE public.t (id int); DROP TABLE public.t;", []),
        ("ctas after a drop", "CREATE TABLE public.t (id int); DROP TABLE public.t; CREATE TABLE public.t AS SELECT 1 AS id;", ["public.t"]),
        ("create-create-drop", "CREATE TABLE public.t (id int); CREATE TABLE IF NOT EXISTS public.t (id int); DROP TABLE public.t;", []),
        ("drop one of two", "CREATE TABLE public.a (id int); CREATE TABLE public.b (id int); DROP TABLE public.a;", ["public.b"]),
    ],
)
def test_offline_drop_table_is_order_aware(label, sql, expected) -> None:
    from pgrls.schema_sources import schema_from_sql

    got = sorted(t.qualified_name for t in schema_from_sql(sql).tables)
    assert got == sorted(expected), label


def test_offline_model_registers_ctas_and_select_into() -> None:
    # Both create a REAL table with no RLS — exactly what SEC001 catches — but
    # neither is a CreateStmt, so both were invisible offline.
    from pgrls.schema_sources import schema_from_sql

    schema = schema_from_sql(
        "CREATE TABLE public.src (id int);"
        "CREATE TABLE public.copy AS SELECT * FROM public.src;"
        "SELECT * INTO public.copy2 FROM public.src;"
    )
    names = sorted(t.qualified_name for t in schema.tables)
    assert names == ["public.copy", "public.copy2", "public.src"]
    # Columns come from the SELECT and cannot be resolved without a catalog, so
    # the relation is registered WITHOUT them — column-keyed rules stay silent
    # rather than guess a shape.
    copy = next(t for t in schema.tables if t.name == "copy")
    assert copy.column_details == ()


def test_offline_model_does_not_treat_a_matview_as_a_table() -> None:
    # CREATE MATERIALIZED VIEW is also a CreateTableAsStmt; it is a different
    # relkind with its own rules (VIEW003 / SEC054) and must not be registered
    # as a table.
    from pgrls.schema_sources import schema_from_sql

    schema = schema_from_sql(
        "CREATE TABLE public.s (id int);"
        "CREATE MATERIALIZED VIEW public.mv AS SELECT * FROM public.s;"
    )
    assert [t.qualified_name for t in schema.tables] == ["public.s"]


def test_offline_alter_policy_rename_is_followed(tmp_path) -> None:
    """`ALTER POLICY p … RENAME TO q; ALTER POLICY q … USING (true)`: before
    the model followed policy renames the loosening targeted a name it did
    not know and was silently discarded — the offline lint kept seeing the
    scoped predicate under the old name."""
    from click.testing import CliRunner

    from pgrls.cli import main

    sql = tmp_path / "s.sql"
    sql.write_text(
        "CREATE TABLE t (id int primary key, tenant_id text NOT NULL);\n"
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON t FOR SELECT TO PUBLIC "
        "USING (tenant_id = current_setting('app.t', true));\n"
        "ALTER POLICY p ON t RENAME TO q;\n"
        "ALTER POLICY q ON t USING (true);\n"
    )
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(sql), "--rule", "SEC008"])
    assert "SEC008" in res.output and "public.t.q" in res.output, res.output


# A schema-only pg_dump (17.11) of a table, a view, a matview and a
# sequence, trimmed — the psql meta-commands it opens and closes with, and an
# `ALTER … OWNER TO` for every relation — plus an `ALTER TABLE` on the view,
# which Postgres accepts and older dumps write.
_PG_DUMP = """\
--
-- PostgreSQL database dump
--

\\restrict olnOXz8SM3l4TC2vQ3Eo3ko9YcqR12IfgchMvua3keYdHKgZdSM2a4sC3CchbT9

SET statement_timeout = 0;
SELECT pg_catalog.set_config('search_path', '', false);
CREATE TABLE public.docs (id integer NOT NULL, tenant_id integer NOT NULL, body text);
ALTER TABLE public.docs OWNER TO postgres;
CREATE SEQUENCE public.docs_id_seq AS integer START WITH 1 INCREMENT BY 1 CACHE 1;
ALTER SEQUENCE public.docs_id_seq OWNER TO postgres;
ALTER SEQUENCE public.docs_id_seq OWNED BY public.docs.id;
CREATE MATERIALIZED VIEW public.mv AS SELECT count(*) AS n FROM public.docs WITH NO DATA;
ALTER MATERIALIZED VIEW public.mv OWNER TO postgres;
CREATE VIEW public.v_docs WITH (security_invoker='true') AS SELECT id, body FROM public.docs;
ALTER VIEW public.v_docs OWNER TO postgres;
ALTER TABLE public.v_docs OWNER TO postgres;
ALTER TABLE ONLY public.docs ADD CONSTRAINT docs_pkey PRIMARY KEY (id);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.docs FOR SELECT TO anon USING ((tenant_id = 1));
GRANT SELECT ON TABLE public.docs TO anon;

--
-- PostgreSQL database dump complete
--

\\unrestrict olnOXz8SM3l4TC2vQ3Eo3ko9YcqR12IfgchMvua3keYdHKgZdSM2a4sC3CchbT9

"""


def test_pg_dump_output_lints_without_phantom_tables(tmp_path):
    sql = tmp_path / "dump.sql"
    sql.write_text(_PG_DUMP)
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(sql), "--format", "json"])
    assert res.exit_code in (0, 1), res.output
    locations = {v["location"] for v in json.loads(res.stdout)["violations"]}
    # Only the real table: no finding on the sequence, view or matview.
    assert locations and all(loc.startswith("public.docs") for loc in locations), locations


def test_psql_meta_commands_are_blanked_only_outside_literals():
    from pgrls.schema_sources import _without_psql_meta_commands, schema_from_sql

    sql = (
        "\\restrict key\n"
        "CREATE TABLE t (a text DEFAULT 'x\n\\still a string');\n"
        "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $b$\n\\in a body\nSELECT 1 $b$;\n"
        "\\unrestrict key\n  \\echo done\n"
    )
    out = _without_psql_meta_commands(sql)
    assert len(out) == len(sql)
    assert "key" not in out and "done" not in out
    assert "\\still a string" in out and "\\in a body" in out
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]


def test_alter_table_on_an_unseen_name_needs_a_modelled_change():
    from pgrls.schema_sources import schema_from_sql

    # An RLS toggle on a table defined elsewhere still records; an OWNER TO
    # alone says nothing about the relation.
    names = [t.name for t in schema_from_sql(
        "ALTER TABLE a ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE b OWNER TO postgres;\n"
        "CREATE SEQUENCE c;\nALTER TABLE c OWNER TO postgres;\n"
        "ALTER SEQUENCE d OWNER TO postgres;\n"
    ).tables]
    assert names == ["a"]


def test_pg_dump_attaches_partitions_with_alter_table():
    from pgrls.schema_sources import schema_from_sql

    # pg_dump writes a partition as a plain CREATE TABLE plus ATTACH; the
    # child is no standalone RLS-off table (a false SEC001).
    schema = schema_from_sql(
        "CREATE TABLE public.ev (id int, t int) PARTITION BY RANGE (t);\n"
        "CREATE TABLE public.ev_2025 (id int, t int);\n"
        "CREATE TABLE public.ev_old (id int, t int);\n"
        "ALTER TABLE ONLY public.ev ATTACH PARTITION public.ev_2025 FOR VALUES FROM (1) TO (2);\n"
        "ALTER TABLE public.ev ATTACH PARTITION public.ev_old FOR VALUES FROM (0) TO (1);\n"
        "ALTER TABLE public.ev DETACH PARTITION public.ev_old;\n"
        "ALTER TABLE public.ev ENABLE ROW LEVEL SECURITY;\n")
    parents = {t.name: t.partition_of for t in schema.tables}
    assert parents == {"ev": None, "ev_2025": ("public", "ev"), "ev_old": None}


def test_a_create_if_not_exists_of_a_table_there_does_not_undo_a_detach():
    from pgrls.schema_sources import schema_from_sql

    # An idempotent migration run twice: the IF NOT EXISTS skips.
    base = ("CREATE TABLE public.p (k int) PARTITION BY LIST (k);\n"
            "CREATE TABLE IF NOT EXISTS public.c PARTITION OF public.p FOR VALUES IN (1);\n")
    for after in ("CREATE TABLE IF NOT EXISTS public.c (k int);\n",
                  "CREATE TABLE IF NOT EXISTS public.p (k int) PARTITION BY LIST (k);\n"):
        sql = base + "ALTER TABLE public.p DETACH PARTITION public.c;\n" + after
        parents = {t.name: t.partition_of for t in schema_from_sql(sql).tables}
        assert parents["c"] is None, after
    # A table gone with its schema, or by DROP OWNED, is created anew.
    for gone in ("DROP SCHEMA s CASCADE;\nCREATE SCHEMA s;\n", "DROP OWNED BY mig;\n"):
        sql = ("CREATE SCHEMA s;\nCREATE TABLE public.p (k int) PARTITION BY LIST (k);\n"
               "CREATE TABLE s.c (k int);\n"
               "ALTER TABLE public.p ATTACH PARTITION s.c FOR VALUES IN (1);\n" + gone
               + "CREATE TABLE IF NOT EXISTS s.c (k int);\n")
        parents = {t.name: t.partition_of for t in schema_from_sql(sql).tables}
        assert parents["c"] is None, gone
    # ... and so is one a DROP of an ancestor, a type or an extension may have
    # taken, or a CREATE TABLE ... AS of the name.
    for gone in ("DROP TABLE public.top;\n", "DROP TYPE ty CASCADE;\n", "DROP EXTENSION hstore;\n",
                 "ALTER INDEX public.c RENAME TO d;\n", "DROP ACCESS METHOD heap2 CASCADE;\n",
                 "DROP FUNCTION f(int) CASCADE;\n",
                 # Code may drop it too.
                 "DO $$ BEGIN DROP TABLE public.c; END $$;\n", "CALL dr();\n", "SELECT dr();\n"):
        sql = ("CREATE TABLE public.top (k int) PARTITION BY LIST (k);\n"
               "CREATE TABLE public.p PARTITION OF public.top FOR VALUES IN (1) PARTITION BY LIST (k);\n"
               "CREATE TABLE public.c (k int);\n"
               "ALTER TABLE public.p ATTACH PARTITION public.c FOR VALUES IN (1);\n" + gone
               + "CREATE TABLE IF NOT EXISTS public.c (k int);\n")
        parents = {t.name: t.partition_of for t in schema_from_sql(sql).tables}
        assert parents["c"] is None, gone
    sql = ("CREATE TABLE public.p (k int) PARTITION BY LIST (k);\nCREATE TABLE public.c (k int);\n"
           "ALTER TABLE public.p ATTACH PARTITION public.c FOR VALUES IN (1);\n"
           "CREATE TABLE public.c AS SELECT 1 AS k;\n")
    parents = {t.name: t.partition_of for t in schema_from_sql(sql).tables}
    assert parents["c"] is None
    # ... nor an ATTACH.
    sql = ("CREATE TABLE public.p (k int) PARTITION BY LIST (k);\nCREATE TABLE public.c (k int);\n"
           "ALTER TABLE public.p ATTACH PARTITION public.c FOR VALUES IN (1);\n"
           "CREATE TABLE IF NOT EXISTS public.c (k int);\n")
    parents = {t.name: t.partition_of for t in schema_from_sql(sql).tables}
    assert parents["c"] == ("public", "p")


def test_an_attach_reaches_only_the_child_as_it_stood():
    from pgrls.schema_sources import schema_from_sql

    # Dropped and created again, the child is a table of its own; attached
    # before it exists, the ATTACH fails.
    for sql in (
        "CREATE TABLE p (id int) PARTITION BY RANGE (id);\nCREATE TABLE c (id int);\n"
        "ALTER TABLE ONLY p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);\n"
        "DROP TABLE c;\nCREATE TABLE c (id int);\n",
        "CREATE TABLE p (id int) PARTITION BY RANGE (id);\n"
        "ALTER TABLE ONLY p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);\n"
        "CREATE TABLE c (id int);\n",
        # ... and so is one attached to a parent that does not exist yet.
        "CREATE TABLE c (id int);\n"
        "ALTER TABLE ONLY p ATTACH PARTITION c FOR VALUES FROM (0) TO (10);\n"
        "CREATE TABLE p (id int) PARTITION BY RANGE (id);\n",
    ):
        parents = {t.name: t.partition_of for t in schema_from_sql(sql).tables}
        assert parents["c"] is None, sql


def test_a_partition_follows_its_parent_renamed():
    from pgrls.schema_sources import schema_from_sql

    attach = ("CREATE TABLE a.p (id int) PARTITION BY RANGE (id);\nCREATE TABLE a.c (id int);\n"
              "ALTER TABLE ONLY a.p ATTACH PARTITION a.c FOR VALUES FROM (0) TO (10);\n")
    schema = schema_from_sql(attach + "ALTER TABLE a.p RENAME TO q;\n", schemas=("a",))
    assert {t.qualified_name: t.partition_of for t in schema.tables}["a.c"] == ("a", "q")


def test_a_table_moved_to_another_schema_is_refused():
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql

    # Policies name it by its old schema, and a later CREATE of the old name
    # would merge with it; a view may move.
    with pytest.raises(SchemaSourceError, match="SET SCHEMA"):
        schema_from_sql("CREATE TABLE a.t (id int);\nALTER TABLE a.t SET SCHEMA b;\n")
    schema_from_sql("CREATE VIEW a.v AS SELECT 1;\nALTER VIEW a.v SET SCHEMA b;\n")


def test_an_attach_that_would_close_a_cycle_is_left_out():
    from pgrls.schema_sources import schema_from_sql

    # The replay merges the two CREATEs of b.y, keeping its link to b.x, so
    # the ATTACH of b.x to b.y would close a cycle Postgres never has.
    sql = ("CREATE TABLE b.x (id int) PARTITION BY LIST (id);\n"
           "CREATE TABLE b.y PARTITION OF b.x FOR VALUES IN (1) PARTITION BY LIST (id);\n"
           "DROP TABLE b.x;\nCREATE TABLE b.y (id int) PARTITION BY LIST (id);\n"
           "CREATE TABLE b.x (id int) PARTITION BY LIST (id);\n"
           "ALTER TABLE b.y ATTACH PARTITION b.x FOR VALUES IN (1);\n"
           "CREATE TABLE a.c PARTITION OF b.x FOR VALUES IN (2);\n")
    for schemas in (("a",), ("a", "b")):
        tables = {t.qualified_name: t for t in schema_from_sql(sql, schemas=schemas).tables}
        assert tables["a.c"].partition_of == ("b", "x")


def test_an_unqualified_name_lands_in_public_whatever_the_scope():
    from pgrls.schema_sources import schema_from_sql

    # psql puts it there; moved into `app`, the partition below would have a
    # parent `app.q` in scope and its SEC001 (live: the chain leaves the
    # scanned schemas) would be lost.
    sql = ("CREATE TABLE q (id int) PARTITION BY LIST (id);\n"
           "ALTER TABLE q ENABLE ROW LEVEL SECURITY;\n"
           "CREATE TABLE app.qc (id int);\n"
           "ALTER TABLE ONLY q ATTACH PARTITION app.qc FOR VALUES IN (1);\n")
    tables = {t.qualified_name: t for t in schema_from_sql(sql, schemas=("app",)).tables}
    assert set(tables) == {"app.qc"} and tables["app.qc"].partition_of == ("public", "q")
    names = {t.qualified_name for t in schema_from_sql(sql, schemas=("app", "public")).tables}
    assert names == {"app.qc", "public.q"}


def test_an_unqualified_name_resolves_on_the_search_path_the_sql_sets():
    from pgrls.schema_sources import schema_from_sql

    def tables(sql):
        return {t.qualified_name: t for t in schema_from_sql(sql, schemas=("app", "public")).tables}

    # Created where the path puts it, not merged into `public.profiles`.
    got = tables("CREATE TABLE public.profiles (id int);\n"
                 "ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n"
                 "CREATE SCHEMA app;\nSET search_path TO app;\n"
                 "CREATE TABLE profiles (id int, ssn text);\nGRANT SELECT ON profiles TO PUBLIC;\n")
    assert not got["app.profiles"].rls_enabled and got["app.profiles"].grants
    assert got["public.profiles"].rls_enabled and not got["public.profiles"].grants
    # A reference finds the table where the path has it, a later schema too,
    # as the tables stand then: one created later, or dropped, is not found.
    got = tables("CREATE TABLE public.t (id int);\nCREATE SCHEMA app;\n"
                 "SET search_path TO app, public;\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
                 "ALTER TABLE t RENAME TO u;\nALTER TABLE u FORCE ROW LEVEL SECURITY;\n"
                 "CREATE TABLE app.t (id int);\n")
    assert got["public.u"].rls_enabled and got["public.u"].force_rls
    assert not got["app.t"].rls_enabled
    got = tables("CREATE TABLE public.t (id int);\nCREATE SCHEMA app;\nCREATE TABLE app.t (id int);\n"
                 "DROP TABLE app.t;\nSET search_path TO app, public;\n"
                 "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n")
    assert set(got) == {"public.t"} and got["public.t"].rls_enabled


@pytest.mark.parametrize(("sql", "where"), [
    # A local one lasts to the end of its transaction, and outside one, not
    # at all.
    ("BEGIN;\nSET LOCAL search_path TO app;\nCOMMIT;\nCREATE TABLE x (id int);\n", "public"),
    ("BEGIN;\nSET LOCAL search_path TO app;\nCREATE TABLE x (id int);\nCOMMIT;\n", "app"),
    ("SET LOCAL search_path TO app;\nCREATE TABLE x (id int);\n", "public"),
    ("BEGIN;\nCOMMIT AND CHAIN;\nSET LOCAL search_path TO app;\nCREATE TABLE x (id int);\n"
     "COMMIT;\n", "app"),
    # A rolled-back one is undone, as is what it created.
    ("BEGIN;\nSET search_path TO app;\nROLLBACK;\nCREATE TABLE x (id int);\n", "public"),
    ("BEGIN;\nSAVEPOINT s;\nSET search_path TO app;\nROLLBACK TO SAVEPOINT s;\n"
     "CREATE TABLE x (id int);\nCOMMIT;\n", "public"),
    ("BEGIN;\nCREATE TABLE app.y (id int);\nROLLBACK;\nCREATE TABLE x (id int);\n", "public"),
    ("BEGIN;\nCREATE TABLE app.y (id int);\nCREATE TABLE x (id int);\n", None),
    ("SET search_path TO app;\nDISCARD ALL;\nCREATE TABLE x (id int);\n", "public"),
    ("SET search_path TO app;\nRESET search_path;\nCREATE TABLE x (id int);\n", "public"),
    # `$user` is the role the SQL sets, when it has a schema; a schema the
    # path names before it exists, and a quoted list item, as Postgres reads
    # them; a name cut to 63 bytes.
    ('SET search_path TO "$user", app;\nCREATE TABLE x (id int);\n', "app"),
    ("CREATE SCHEMA AUTHORIZATION alice;\nSET ROLE alice;\nCREATE TABLE x (id int);\n", "alice"),
    ("SET search_path TO later, app;\nCREATE TABLE x (id int);\nCREATE SCHEMA later;\n", "app"),
    ("CREATE SCHEMA gone;\nDROP SCHEMA gone;\nSET search_path TO gone, app;\n"
     "CREATE TABLE x (id int);\n", "app"),
    ("CREATE SCHEMA \"app, b\";\nSET search_path = 'app, b';\nCREATE TABLE x (id int);\n",
     "app, b"),
    ("CREATE SCHEMA " + "a" * 70 + ";\nSET search_path TO '" + "a" * 70 + "';\n"
     "CREATE TABLE x (id int);\n", "a" * 63),
    ("SET SCHEMA 'app';\nCREATE TABLE x (id int);\n", "app"),
    ("SELECT set_config('search_path', 'APP, public', false);\nCREATE TABLE x (id int);\n", "app"),
    # pg_dump's: an unqualified CREATE then has nowhere to go.
    # A search_path string splits on ASCII whitespace: a no-break space is
    # part of a name.
    ("CREATE SCHEMA \"\u00a0app\";\n"
     "SELECT set_config('search_path', '\u00a0app, public', false);\nCREATE TABLE x (id int);\n",
     "\u00a0app"),
    # set_config() of the role is SET ROLE.
    ("CREATE SCHEMA AUTHORIZATION alice;\nSELECT set_config('role', 'alice', false);\n"
     "CREATE TABLE x (id int);\n", "alice"),
    # ... `none` exactly is no role; `NONE` is one so named.
    ('CREATE SCHEMA AUTHORIZATION "NONE";\nSELECT set_config(\'role\', \'NONE\', false);\n'
     "CREATE TABLE x (id int);\n", "NONE"),
    # A schema's elements go in it; a temporary table is no table, and one
    # gone no longer hides the name.
    ("CREATE SCHEMA app CREATE TABLE x (id int);\n", "app"),
    ("CREATE TEMP TABLE x (id int);\n", None),
    # `public` is there before the SQL creates it IF NOT EXISTS.
    ("CREATE TABLE x (id int);\nCREATE SCHEMA IF NOT EXISTS public;\n", "public"),
    # A dead SET LOCAL after COMMIT AND CHAIN and a ROLLBACK.
    ("BEGIN;\nCOMMIT AND CHAIN;\nSET LOCAL search_path TO app;\nROLLBACK;\n"
     "CREATE TABLE x (id int);\n", "public"),
    # RESET ALL leaves the role, and RESET ROLE goes back to the session user.
    ("CREATE SCHEMA AUTHORIZATION alice;\nSET ROLE alice;\nRESET ALL;\n"
     "CREATE TABLE x (id int);\n", "alice"),
    ("CREATE SCHEMA AUTHORIZATION alice;\nSET SESSION AUTHORIZATION alice;\nRESET ROLE;\n"
     "CREATE TABLE x (id int);\n", "alice"),
    # pg_dump's form of a set_config() in an expression, which runs when used.
    ("CREATE TABLE public.audit (who text DEFAULT set_config('app.x'::text, 'y'::text, true));\n"
     "CREATE VIEW public.v AS SELECT set_config('search_path'::text, 'app'::text, true) AS s;\n"
     "CREATE TABLE x (id int);\n", "public"),
])
def test_the_search_path_follows_the_session(sql, where):
    from pgrls.schema_sources import schema_from_sql

    sql = "CREATE SCHEMA IF NOT EXISTS app;\n" + sql if "CREATE SCHEMA app " not in sql else sql
    got = [t.schema for t in schema_from_sql(sql).tables if t.name == "x"]
    assert got == ([where] if where else []), sql


def test_a_name_with_no_schema_to_go_to_is_refused():
    # A dump's empty search_path left in force: Postgres errors on the
    # unqualified CREATE, which was silently dropped.
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError, match="no schema on search_path"):
        schema_from_sql("SELECT pg_catalog.set_config('search_path', '', false);\n"
                        "CREATE TABLE x (id int);\n")


@pytest.mark.parametrize("looked_up", [
    # pg_dump leaves a catalog relation unqualified under its empty path.
    "CREATE POLICY p ON public.t FOR SELECT USING (EXISTS (SELECT 1 FROM pg_roles r "
    "WHERE r.rolname = current_user AND r.rolsuper));\n",
    "DROP TABLE IF EXISTS foo;\nDROP POLICY IF EXISTS p ON foo;\n"
    "ALTER TABLE IF EXISTS foo ENABLE ROW LEVEL SECURITY;\n",
    "GRANT SELECT ON pg_authid TO postgres;\n",
])
def test_a_name_looked_up_with_no_schema_on_the_path_is_not_refused(looked_up):
    from pgrls.schema_sources import schema_from_sql
    schema = schema_from_sql(
        "CREATE TABLE public.t (id int, owner text);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
        "SELECT pg_catalog.set_config('search_path', '', false);\n" + looked_up)
    assert [t.name for t in schema.tables] == ["t"]


def _migrations_snapshot(tmp_path, files):
    import json
    from click.testing import CliRunner
    from pgrls.cli import main
    mig = tmp_path / "migrations"
    mig.mkdir()
    for name, text in files.items():
        (mig / name).write_text(text)
    out = tmp_path / "s.json"
    res = CliRunner().invoke(main, ["snapshot", "--migrations", str(mig), "-o", str(out)])
    return res, (json.loads(out.read_text()) if res.exit_code == 0 else None)


def test_a_migration_file_ending_inside_a_transaction_is_refused(tmp_path):
    # psql rolls it back, `psql -1` and `lint --migrations` commit it; it no
    # longer voids the files after it either.
    res, _ = _migrations_snapshot(tmp_path, {
        "001_a.sql": "CREATE TABLE a1 (id int);\nBEGIN;\nCREATE TABLE e (id int);\n",
        "002_b.sql": "CREATE TABLE g (id int);\n",
    })
    assert res.exit_code != 0
    assert "ends inside a transaction" in res.output


def test_migration_files_ending_their_transactions_are_read_apart(tmp_path):
    # A bare BEGIN at the end changes nothing; a last statement with no `;`
    # ends with its file.
    res, snap = _migrations_snapshot(tmp_path, {
        "001_a.sql": "CREATE TABLE a1 (id int);\nBEGIN;\n",
        "002_b.sql": "BEGIN;\nCREATE TABLE h (id int);\nROLLBACK;\nCREATE TABLE g (id int)",
        "003_c.sql": "CREATE TABLE k (id int);\n",
    })
    assert res.exit_code == 0, res.output
    assert {t["name"] for t in snap["tables"]} == {"a1", "g", "k"}


def test_a_lookup_looks_on_past_pg_catalog():
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    (t,) = schema_from_sql("SET search_path = pg_catalog, public;\n"
                           "CREATE POLICY p ON t FOR SELECT USING (true);\n"
                           "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n").tables
    assert (t.schema, t.name, t.rls_enabled, len(t.policies)) == ("public", "t", True, 1)
    # A CREATE there is Postgres's "permission denied to create".
    with pytest.raises(SchemaSourceError, match="pg_catalog first"):
        schema_from_sql("SET search_path = pg_catalog, public;\nCREATE TABLE u (id int);\n")


def test_a_rename_of_a_name_found_nowhere_makes_no_temporary_table():
    from pgrls.schema_sources import schema_from_sql
    (u,) = schema_from_sql(
        "CREATE TABLE public.u (id int);\nALTER TABLE public.u ENABLE ROW LEVEL SECURITY;\n"
        "SELECT pg_catalog.set_config('search_path', '', false);\n"
        "ALTER TABLE IF EXISTS t RENAME TO u;\n"
        "SET search_path = public;\nALTER TABLE u DISABLE ROW LEVEL SECURITY;\n").tables
    assert not u.rls_enabled


def test_a_role_setting_a_migration_makes_is_not_followed_in_later_files(tmp_path):
    # The next file's session starts with it: pgrls cannot tell where the
    # unqualified table goes (Postgres puts it in app).
    res, _ = _migrations_snapshot(tmp_path, {
        "001_a.sql": "CREATE SCHEMA app;\nALTER ROLE postgres SET search_path = app, public;\n",
        "002_b.sql": "CREATE TABLE t (id int);\n",
    })
    assert res.exit_code != 0
    assert "search_path" in res.output


def test_each_migration_file_is_a_session_of_its_own(tmp_path):
    # A baseline dump's empty search_path does not reach the migration after
    # it (the Supabase CLI resets each file's session).
    import json
    from click.testing import CliRunner
    from pgrls.cli import main
    mig = tmp_path / "migrations"
    mig.mkdir()
    (mig / "20240101000000_remote_schema.sql").write_text(
        "SELECT pg_catalog.set_config('search_path', '', false);\n"
        "CREATE TABLE public.base (id int);\n")
    (mig / "20240201000000_invoices.sql").write_text("CREATE TABLE invoices (id int);\n")
    out = tmp_path / "s.json"
    res = CliRunner().invoke(main, ["snapshot", "--migrations", str(mig), "-o", str(out)])
    assert res.exit_code == 0, res.output
    names = {(t["schema"], t["name"]) for t in json.loads(out.read_text())["tables"]}
    assert ("public", "invoices") in names


@pytest.mark.parametrize("gone", [
    "CREATE TEMP TABLE x (id int);\nDISCARD TEMP;\n",
    "CREATE TEMP TABLE x (id int);\nDISCARD ALL;\n",
    "BEGIN;\nCREATE TEMP TABLE x (id int) ON COMMIT DROP;\nCOMMIT;\n",
    "CREATE TEMP TABLE x (id int) ON COMMIT DROP;\n",
    # ... as it stands at COMMIT: renamed, dropped, or never made.
    "BEGIN;\nCREATE TEMP TABLE s (id int) ON COMMIT DROP;\nALTER TABLE s RENAME TO x;\nCOMMIT;\n",
])
def test_a_temporary_table_gone_no_longer_hides_the_name(gone):
    from pgrls.schema_sources import schema_from_sql

    (x,) = schema_from_sql("CREATE TABLE public.x (id int);\n" + gone
                           + "ALTER TABLE x ENABLE ROW LEVEL SECURITY;\n").tables
    assert x.rls_enabled, gone


@pytest.mark.parametrize("kept", [
    "BEGIN;\nCREATE TEMP TABLE x (id int) ON COMMIT DROP;\nDROP TABLE x;\n"
    "CREATE TEMP TABLE x (id int);\nCOMMIT;\n",
    "CREATE TEMP TABLE x (id int);\nBEGIN;\n"
    "CREATE TEMP TABLE IF NOT EXISTS x (id int) ON COMMIT DROP;\nCOMMIT;\n",
])
def test_a_temporary_table_still_there_still_hides_the_name(kept):
    from pgrls.schema_sources import schema_from_sql

    (x,) = schema_from_sql("CREATE TABLE public.x (id int);\n" + kept
                           + "ALTER TABLE x ENABLE ROW LEVEL SECURITY;\n").tables
    assert not x.rls_enabled, kept


@pytest.mark.parametrize(("sql", "why"), [
    # Postgres creates in it only if it exists.
    ("SET search_path TO nosuch, public;\nCREATE TABLE x (id int);\n", "neither creates"),
    # set_config() anywhere but a plain SELECT of literals may not run, or
    # run where pgrls does not look.
    ("SELECT set_config('search_path', 'app', false) WHERE false;\n", "set_config"),
    ("SELECT set_config('search_path', 'app', 'true');\n", "set_config"),
    ("CREATE TABLE j AS SELECT set_config('search_path', 'app', false);\n", "set_config"),
    ("SELECT set_config('search_path', current_user, false);\n", "set_config"),
    # A cast that may change the literal (`::varchar(11)` cuts it) is no
    # literal, and set_config() in a statement that runs it now, not only
    # a plain SELECT, is refused.
    ("SELECT set_config('search_path_'::varchar(11), 'app', false);\n", "set_config"),
    ("SELECT set_config('search_path', 'appx, public'::varchar(3), false);\n", "set_config"),
    ("DECLARE c CURSOR WITH HOLD FOR SELECT set_config('search_path', 'app', false);\n",
     "set_config"),
    ("CREATE TABLE public.s (id int);\nINSERT INTO public.s VALUES (1);\n"
     "ALTER TABLE public.s ALTER COLUMN id TYPE text "
     "USING set_config('search_path', 'app', false);\n", "set_config"),
    ("PREPARE p AS SELECT set_config('search_path', 'app', false);\nEXECUTE p;\n",
     "set_config"),
    # A partition bound runs as the table is made.
    ("CREATE TABLE public.p (k int) PARTITION BY LIST (k);\n"
     "CREATE TABLE public.p1 PARTITION OF public.p FOR VALUES IN "
     "(length(set_config('search_path', 'app', false)));\n", "set_config"),
    # ... inside a CREATE SCHEMA too, and EXECUTE's parameters run WITH NO
    # DATA.
    ("CREATE TABLE public.p (k int) PARTITION BY LIST (k);\n"
     "CREATE SCHEMA side CREATE TABLE p1 PARTITION OF public.p FOR VALUES IN "
     "(length(set_config('search_path', 'app', false)));\n", "set_config"),
    ("PREPARE ps(text) AS SELECT $1 AS a;\nCREATE TABLE public.x AS EXECUTE "
     "ps(set_config('search_path', 'app', false)) WITH NO DATA;\n", "set_config"),
    # A cast to a type named `text` the SQL creates (or renames one to) may
    # change the literal.
    ("CREATE DOMAIN public.d AS varchar(3);\nALTER DOMAIN public.d RENAME TO text;\n",
     "built-in"),
    ("CREATE SCHEMA text;\nCREATE DOMAIN text.text AS varchar(3);\n"
     "SELECT set_config('search_path', 'appx'::text.text, false);\n", "built-in"),
    # The database a `\\connect` reaches may set it.
    ("CREATE DATABASE d;\nALTER DATABASE d SET search_path TO app;\n\\connect d\n"
     "CREATE TABLE x (id int);\n", "connects to a database"),
    ("SET search_path TO pg_temp, public;\nCREATE TABLE x (id int);\n", "pg_temp"),
    ("SET search_path TO app;\nCREATE TABLE x (id int);\nCREATE SCHEMA IF NOT EXISTS app;\n",
     "IF NOT EXISTS"),
    ("CREATE SCHEMA app;\nALTER SCHEMA app RENAME TO app2;\n", "renames a schema"),
    # psql may connect as the role a schema is made for.
    ("CREATE SCHEMA AUTHORIZATION postgres;\nCREATE TABLE x (id int);\n", "for a role"),
    ("CREATE SCHEMA app;\nALTER SCHEMA app OWNER TO app;\nCREATE TABLE x (id int);\n",
     "for a role"),
    ("CREATE SCHEMA app AUTHORIZATION CURRENT_USER;\nCREATE TABLE x (id int);\n", "for a role"),
    ("CREATE SCHEMA AUTHORIZATION CURRENT_USER;\n", "connects as"),
    ("CREATE SCHEMA AUTHORIZATION SESSION_USER CREATE TABLE x (id int);\n", "connects as"),
    ("BEGIN;\nCREATE TABLE x (id int);\nPREPARE TRANSACTION 'x';\n", "PREPARE TRANSACTION"),
    # A name two schemas on the path hold: the first may be gone (here by
    # code) or moved by something pgrls does not follow.
    ("CREATE TABLE app.c (k int);\nCREATE TABLE public.c (k int);\nSET search_path = app, public;\n"
     "DO $$ BEGIN DROP TABLE app.c; END $$;\nALTER TABLE c DISABLE ROW LEVEL SECURITY;\n",
     "more than one schema"),
    ("CREATE TABLE public.c (k int);\nCREATE TEMP TABLE c (k int);\n"
     "DO $$ BEGIN DROP TABLE IF EXISTS pg_temp.c; END $$;\nALTER TABLE c DISABLE ROW LEVEL SECURITY;\n",
     "runs code"),
    # A transaction still open at a \\connect is rolled back there.
    ("BEGIN;\nCREATE DATABASE d;\n\\connect d\nCREATE TABLE x (id int);\n", "transaction"),
    ("CREATE DATABASE d;\nBEGIN;\n\\connect d\nALTER DATABASE d SET search_path TO app;\n"
     "ROLLBACK;\n\\connect d\nCREATE TABLE x (id int);\n", "transaction"),
    # The role a \\connect'ed session runs as decides `$user`.
    ("CREATE DATABASE d;\nALTER DATABASE d SET role TO 'alice';\n\\connect d\n"
     "CREATE SCHEMA alice;\nCREATE TABLE x (id int);\n", "sets the role"),
    # psql splits a meta-command on ASCII whitespace: `\\c\u00a0d` is no `\\c`.
    ("SET search_path = app, public;\n\\c\u00a0d\nCREATE TABLE x (id int);\n", "psql command"),
    # ... and only psql 17 splits on a vertical tab, so does Postgres's list.
    ("SET search_path = app, public;\n\\c\vd\nCREATE TABLE x (id int);\n", "psql command"),
    ("SELECT set_config('search_path', 'app,\vpublic', false);\nCREATE TABLE x (id int);\n",
     "vertical tab"),
])
def test_a_search_path_pgrls_cannot_follow_is_refused(sql, why):
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql

    with pytest.raises(SchemaSourceError, match=why):
        schema_from_sql(sql)


def test_a_policy_reads_a_table_where_the_search_path_found_it():
    from pgrls.schema_sources import schema_from_sql

    # SEC025 reads an unqualified name in the policy's own schema.
    schema = schema_from_sql(
        "CREATE SCHEMA app;\nCREATE TABLE app.members (uid int);\n"
        "CREATE TABLE public.docs (id int);\n"
        "SET search_path TO app, public;\nALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs USING (EXISTS (SELECT 1 FROM members m));\n")
    (docs,) = [t for t in schema.tables if t.name == "docs"]
    assert "app.members" in docs.policies[0].using_sql


def test_a_deep_view_does_not_overflow_the_walk():
    from pgrls.lsp.diagnostics import diagnose
    from pgrls.schema_sources import schema_from_sql

    # Valid SQL a few thousand nodes deep: the settings check walks it.
    sql = ("CREATE TABLE public.t (a int);\nCREATE VIEW public.v AS "
           + " UNION ALL ".join(f"SELECT {i} AS a" for i in range(3000)) + ";\n"
           "CREATE VIEW public.w AS SELECT " + " + ".join(["a"] * 3000) + " FROM public.t;\n")
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]
    assert any(d.code == "SEC001" for d in diagnose(sql))


def test_an_attach_postgres_refuses_is_not_modelled():
    from pgrls.schema_sources import schema_from_sql

    # An inheritance child, a table already attached, a parent not partitioned.
    for attach in ("CREATE TABLE c (id int) INHERITS (base);\n"
                   "ALTER TABLE ONLY p ATTACH PARTITION c FOR VALUES IN (1);\n",
                   "CREATE TABLE c PARTITION OF q FOR VALUES IN (1);\n"
                   "ALTER TABLE ONLY p ATTACH PARTITION c FOR VALUES IN (1);\n",
                   "CREATE TABLE c (id int);\n"
                   "ALTER TABLE ONLY base ATTACH PARTITION c FOR VALUES IN (1);\n"):
        sql = ("CREATE TABLE base (id int);\n"
               "CREATE TABLE p (id int) PARTITION BY LIST (id);\n"
               "CREATE TABLE q (id int) PARTITION BY LIST (id);\n" + attach)
        parents = {t.name: t.partition_of for t in schema_from_sql(sql).tables}
        assert parents["c"] in (None, ("public", "q")), attach


def test_offline_lint_reads_the_configured_schemas(tmp_path):
    from pgrls.cli import main

    # `[database] schemas` scopes an offline run as it does a live one: the
    # parent in `a` is linted, not left out as beyond the scope.
    (tmp_path / "pgrls.toml").write_text('[database]\nschemas = ["public", "a"]\n')
    sql = tmp_path / "s.sql"
    sql.write_text("CREATE TABLE a.p (id int) PARTITION BY LIST (id);\n"
                   "ALTER TABLE a.p ENABLE ROW LEVEL SECURITY;\n"
                   "CREATE TABLE public.c PARTITION OF a.p FOR VALUES IN (1);\n")
    res = CliRunner().invoke(main, ["lint", "--config", str(tmp_path / "pgrls.toml"),
                                    "--sql-file", str(sql), "--format", "json"])
    locations = {v["location"] for v in json.loads(res.stdout)["violations"]}
    assert "a.p" in locations, res.output
    # ... without moving an unqualified name out of psql's `public`.
    (tmp_path / "pgrls.toml").write_text('[database]\nschemas = ["app", "public"]\n')
    sql.write_text("CREATE TABLE t (id int);\n")
    res = CliRunner().invoke(main, ["lint", "--config", str(tmp_path / "pgrls.toml"),
                                    "--sql-file", str(sql), "--format", "json"])
    locations = {v["location"] for v in json.loads(res.stdout)["violations"]}
    assert "public.t" in locations and "app.t" not in locations, res.output


def test_a_partition_of_a_parent_outside_the_schemas_keeps_its_link():
    from pgrls.schema_sources import schema_from_sql

    # Live lint of `public` does not see `s.p`: `public.c` keeps its link
    # and its ancestor walk stops there; the offline model leaves `s.p` out,
    # whichever form the SQL uses.
    for sql in (
        "CREATE SCHEMA s;\nCREATE TABLE s.p (id int) PARTITION BY RANGE (id);\n"
        "ALTER TABLE s.p ENABLE ROW LEVEL SECURITY;\nCREATE TABLE public.c (id int);\n"
        "ALTER TABLE ONLY s.p ATTACH PARTITION public.c FOR VALUES FROM (0) TO (10);\n",
        "CREATE SCHEMA s;\nCREATE TABLE s.p (id int) PARTITION BY RANGE (id);\n"
        "ALTER TABLE s.p ENABLE ROW LEVEL SECURITY;\n"
        "CREATE TABLE public.c PARTITION OF s.p FOR VALUES FROM (0) TO (10);\n",
    ):
        tables = {t.qualified_name: t for t in schema_from_sql(sql, schemas=("public",)).tables}
        assert tables["public.c"].partition_of == ("s", "p") and "s.p" not in tables
        both = {t.qualified_name: t
                for t in schema_from_sql(sql, schemas=("public", "s")).tables}
        assert both["public.c"].partition_of == ("s", "p")


def test_a_typed_literal_is_no_escape_string():
    from pgrls.schema_sources import _without_psql_meta_commands

    # `date'x\'` ends at its second quote (only `E'…'` takes escapes), so
    # the backslash line inside the next string is left alone.
    sql = "COMMENT ON TABLE t IS date'x\\' || '\n\\keep me\n';"
    assert _without_psql_meta_commands(sql) == sql


def test_pg_dumpall_output_is_refused(tmp_path):
    # Read as one schema, one database's table would merge with a same-named
    # table in another, and its SEC001 would vanish.
    sql = tmp_path / "all.sql"
    sql.write_text(
        "\\connect a\nCREATE TABLE public.t (id int);\nGRANT SELECT ON public.t TO PUBLIC;\n"
        "\\connect b\nCREATE TABLE public.t (id int);\n"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n")
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(sql)])
    assert res.exit_code == 2 and "more than one database" in res.output, res.output
    # `pg_dump --create` connects once: that file lints.
    sql.write_text("\\connect a\nCREATE TABLE public.t (id int);\n")
    assert CliRunner().invoke(main, ["lint", "--sql-file", str(sql)]).exit_code == 1


@pytest.mark.parametrize(("sql", "why"), [
    # COPY data: blanking `\\.` would read the rows as SQL — said before a
    # `\\N` NULL or an apostrophe in them gets in the way.
    ("CREATE TABLE t (b text);\nCOPY t (b) FROM stdin;\n\\.\n", "COPY data"),
    ("CREATE TABLE t (a text, b text);\nCOPY t (a, b) FROM stdin;\n\\N\tx\nit's\ty\n\\.\n",
     "COPY data"),
    # Another file, a branch not taken, generated SQL: not the SQL that runs.
    ("\\i other.sql\nCREATE TABLE t (id int);\n", "psql command"),
    ("\\if :prod\nALTER TABLE t DISABLE ROW LEVEL SECURITY;\n\\endif\n", "psql command"),
    ("SELECT 'ALTER TABLE t DISABLE ROW LEVEL SECURITY'\n\\gexec\n", "psql command"),
    # A connect after objects switches database.
    ("CREATE TABLE a (id int);\n\\connect other\nCREATE TABLE b (id int);\n", "connects to another"),
    ("SELECT 1 AS id INTO t;\n\\connect other\nCREATE TABLE b (id int);\n", "connects to another"),
    # One line, more than one command: `\\\\` ends a command and the rest runs
    # as SQL; a second backslash starts another; a backtick runs a shell.
    ("\\echo hi \\\\ ALTER TABLE t DISABLE ROW LEVEL SECURITY;\n", "psql command"),
    ("\\echo hi \\i other.sql\n", "psql command"),
    ("\\pset title `id`\n", "psql command"),
    ("\\;ALTER TABLE t DISABLE ROW LEVEL SECURITY;\n", "psql command"),
    ("\\! psql -c 'select 1'\n", "psql command"),
    # psql interpolates its variables into the SQL after them, including
    # its own settings (`:ON_ERROR_STOP`) and those it sets itself.
    ("\\set n 2\nSELECT (ARRAY[1,2,3])[1:n];\n", "psql command"),
    ("\\set ON_ERROR_STOP :x\n", "psql command"),
    ("\\set ECHO a\n\\connect :ECHO\nCREATE TABLE t (id int);\n", "psql command"),
    ("\\connect :DBNAME\nCREATE TABLE t (id int);\n", "psql command"),
    ('\\connect "dbname=x options=-c"\nCREATE TABLE t (id int);\n', "psql command"),
    # psql ends a bare name at a backslash and runs the rest of the line.
    ("\\connect app\\\\CREATE/**/TABLE/**/public.leak(id/**/int);\nCREATE TABLE t (id int);\n",
     "psql command"),
    ("\\connect \\\\CREATE/**/TABLE/**/public.leak(id/**/int);\n", "psql command"),
    ("\\echo x\nCREATE TABLE t (id int);\nSELECT (ARRAY[1])[1:ROW_COUNT] FROM t;\n", "its own variable"),
    ("\\echo x\nSELECT :'USER', 1 FROM (SELECT 1) s(\"USER\");\n", "psql command|its own variable|parse"),
    # psql splits lines by the client encoding.
    ("\\encoding SJIS\nCREATE TABLE t (id int);\n", "psql command"),
    # A conninfo string can set what the server reads strings by, or reach
    # another server: only pg_dump's own forms are skipped.
    ("\\connect \"dbname=d options='-c standard_conforming_strings=off'\"\n", "psql command"),
    ("\\connect -reuse-previous=on \"dbname=d client_encoding=SJIS\"\n", "psql command"),
    ("\\connect dbname=d\n", "psql command"),
    ("\\connect d app otherhost\n", "psql command"),
    # psql reads a line to its LF: the rest after a CR is the command's.
    ("CREATE TABLE t (id int);\n\\echo hi\rALTER TABLE t ENABLE ROW LEVEL SECURITY;\n",
     "psql command"),
    # `:USER` lexes as a keyword, and psql replaces it all the same.
    ("\\echo x\nSELECT (ARRAY[1, 2])[1:USER];\n", "its own variable"),
    # psql ends the name at `$`; the server lexes `USER$x` as one name.
    ("\\echo x\nSELECT (ARRAY[1, 2])[1:USER$x];\n", "its own variable"),
    ("\\encoding LATIN1\nCREATE TABLE t (id int);\n", "psql command"),
    # Only database-level statements may come before the LAST connect: psql
    # rolls an open transaction back when it reconnects, and it reads a
    # `begin` in a CREATE FUNCTION as opening a body, so the COMMIT after
    # it runs in the next session.
    ("CREATE DATABASE d;\n\\connect d\nCREATE TABLE t (id int);\nBEGIN;\n"
     "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n\\connect d\n", "connects to another"),
    ("\\connect d\nCREATE TABLE t (id int);\nBEGIN;\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
     "CREATE FUNCTION begin() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\nCOMMIT;\n"
     "\\connect d\nCREATE TABLE u (id int);\n", "connects to another"),
    # A CTE that writes can set the next database's settings in its catalog.
    ("CREATE DATABASE d;\nWITH x AS (INSERT INTO pg_catalog.pg_db_role_setting "
     "SELECT oid, 0, '{transform_null_equals=on}' FROM pg_database WHERE datname = 'd' "
     "RETURNING 1) SELECT count(*) FROM x;\n\\connect d\nCREATE TABLE t (id int);\n",
     "connects to another"),
    # psql reads COPY rows from the file, up to `\\.`.
    ("CREATE TABLE t (x text);\nCOPY t FROM stdin;\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\n",
     "stdin"),
    # psql reads what follows in the new database's encoding ...
    ("CREATE DATABASE d ENCODING 'LATIN1';\n\\connect d\nCREATE TABLE \"donn\u00e9es\" (id int);\n",
     "encoding other than UTF8"),
    # ... and set back to UTF8, Postgres still converts the text to the
    # database's encoding and folds unquoted names by its locale.
    ("CREATE DATABASE d ENCODING 'LATIN1';\n\\connect d\nSET client_encoding = 'UTF8';\n"
     "CREATE TABLE public.t (id int);\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY /* \u0100 */;\n",
     "encoding other than UTF8"),
    # ... even ASCII text (a `U&` escape it cannot hold), and SQL_ASCII,
    # single-byte, cuts names by byte and folds them by its locale.
    ("CREATE DATABASE d ENCODING 'LATIN1';\n\\connect d\nCREATE TABLE t (id int, c text);\n",
     "encoding other than UTF8"),
    ("CREATE DATABASE d ENCODING 'SQL_ASCII';\n\\connect d\nCREATE TABLE t (id int);\n",
     "encoding other than UTF8"),
    # The template's objects are copied into the database.
    ("CREATE DATABASE d TEMPLATE base;\n\\connect d\nCREATE TABLE t (id int);\n", "template"),
    # pglast stops reading at a NUL; psql drops only the rest of its line.
    ("CREATE TABLE a (id int);\n-- \x00\nCREATE TABLE b (id int);\n", "NUL"),
])
def test_psql_commands_pgrls_cannot_model_are_refused(sql, why):
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql

    with pytest.raises(SchemaSourceError, match=why.replace("\\", "\\\\")):
        schema_from_sql(sql)


@pytest.mark.parametrize("sql", [
    # Postgres ends a `--` comment at a lone CR, so the string that follows
    # holds the `\\echo` line.
    "SELECT 1; -- c\rSELECT '\n\\echo x'; CREATE TABLE hidden (id int); --\n';\n",
    # A dollar-quote tag can be any non-ASCII character, and so can an
    # identifier's (`·$a$` is one identifier).
    "SELECT $\U0001f600$\n\\echo x $\U0001f600$; CREATE TABLE hidden (id int); "
    "SELECT $\U0001f600$\n$\U0001f600$;\n",
    "SELECT 1 AS \u00b7$a$, '\n$a$\n\\echo x'; CREATE TABLE hidden (id int); --\n';\n",
])
def test_a_psql_line_inside_a_string_is_not_skipped(sql):
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql

    try:
        tables = [t.name for t in schema_from_sql(sql).tables]
    except SchemaSourceError:
        return
    assert tables == ["hidden"]


def test_a_sql_file_keeps_a_lone_cr(tmp_path):
    # Read with universal newlines, `\\echo hi\rALTER …` became two lines
    # and the ALTER, which psql never runs, was linted.
    from pgrls.cli import main

    sql = tmp_path / "cr.sql"
    sql.write_bytes(b"CREATE TABLE t (id int);\n\\echo hi\rALTER TABLE t ENABLE ROW LEVEL SECURITY;\n")
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(sql)])
    assert res.exit_code == 2 and "psql command" in res.output, res.output
    sql.write_bytes(b"CREATE TABLE t (id int);\r\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\r\n")
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(sql), "--format", "json"])
    assert res.exit_code in (0, 1), res.output


def test_a_sql_file_that_is_not_utf8_is_a_tool_error(tmp_path):
    from pgrls.cli import main

    data = 'CREATE TABLE "\u00e9" (id int);\n'.encode("latin-1")
    sql = tmp_path / "latin1.sql"
    sql.write_bytes(data)
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(sql)])
    assert res.exit_code == 2 and "cannot read" in res.output, res.output
    res = CliRunner().invoke(main, ["lint", "--sql-file", "-"], input=data)
    assert res.exit_code == 2 and "cannot read" in res.output, res.output


def test_a_skipped_line_must_lie_between_tokens():
    # Whatever the line splitter decides, a blanked line Postgres's lexer
    # reads as inside a string is refused.
    from pgrls.schema_sources import SchemaSourceError, _check_blanked_lines

    sql = "SELECT '\n          \n';\n"
    with pytest.raises(SchemaSourceError, match="inside a string"):
        _check_blanked_lines(sql, [(9, "\\echo x")])
    _check_blanked_lines("SELECT 1;\n          \n", [(10, "\\echo x")])


@pytest.mark.parametrize(("sql", "refused"), [
    ("SET client_encoding = 'SJIS';\n", True),
    ("SET NAMES 'Big-5';\n", True),
    ("SET client_encoding = 'win932';\n", True),
    ("SET standard_conforming_strings = off;\n", True),
    ("SET standard_conforming_strings = 0;\n", True),
    ("SET standard_conforming_strings = fa;\n", True),
    # A database's or role's setting applies once psql reconnects.
    ("ALTER DATABASE d SET standard_conforming_strings = off;\n", True),
    ("ALTER ROLE r IN DATABASE d SET client_encoding = 'SJIS';\n", True),
    ("SELECT set_config('standard_conforming_strings', 'off', false);\n", True),
    ("SELECT set_config('client_encoding', current_setting('x'), false);\n", True),
    ("SELECT set_config(current_setting('x'), 'off', false);\n", "set_config"),
    ("SELECT pg_catalog.set_config('search_path', '', false);\n", False),
    # Under any encoding but UTF-8 / SQL_ASCII a non-ASCII character is read
    # as others (`é` as `Ã©` under LATIN1).
    ("SET client_encoding = 'LATIN1';\nCREATE TABLE \"\u00e9\" (id int);\n", True),
    ("SET client_encoding = 'SQL_ASCII';\nCREATE TABLE \"\u00e9\" (id int);\n", False),
    # Postgres stores `x = NULL` as `x IS NULL`.
    ("SET transform_null_equals = on;\n", True),
    ("ALTER DATABASE d SET transform_null_equals = true;\n", True),
    ("SET transform_null_equals = off;\n", False),
    # A quoted name is still the setting: Postgres ignores its case.
    ('SET "Transform_Null_Equals" = on;\n', True),
    ('ALTER DATABASE d SET "Standard_Conforming_Strings" = off;\n', True),
    ('SET "Client_Encoding" = \'SJIS\';\n', True),
    # A rule on pg_settings sets what it names.
    ("UPDATE pg_settings SET setting = 'off' WHERE name = 'standard_conforming_strings';\n",
     "pg_settings"),
    # ... and so does an UPDATE through a view over it.
    ("CREATE VIEW s AS SELECT * FROM pg_catalog.pg_settings;\n"
     "UPDATE s SET setting = 'on' WHERE name = 'transform_null_equals';\n", "pg_settings"),
    ("SELECT name, setting FROM pg_settings;\n", False),
    # A table of the same name in another schema is not it.
    ("CREATE TABLE app.pg_settings (name text, setting text);\n"
     "UPDATE app.pg_settings SET setting = 'on';\n", False),
    # A function's SET clause applies while it runs; its body runs when called.
    ("CREATE FUNCTION f() RETURNS int LANGUAGE sql SET standard_conforming_strings = off "
     "AS 'select 1';\n", False),
    ("CREATE FUNCTION g(k text, v text) RETURNS void LANGUAGE sql "
     "BEGIN ATOMIC SELECT set_config(k, v, true); END;\n", False),
    # A dump's view over it is read, beside an UPDATE of something else.
    ("CREATE VIEW s AS SELECT name, setting FROM pg_catalog.pg_settings;\n"
     "CREATE TABLE d (id int, n int);\nCREATE FUNCTION f() RETURNS void LANGUAGE sql "
     "BEGIN ATOMIC UPDATE d SET n = n + 1; END;\n", False),
    # A view of the view, and a renamed one, still reach it.
    ("CREATE VIEW s AS SELECT * FROM pg_settings;\nCREATE VIEW s2 AS SELECT * FROM s;\n"
     "UPDATE s2 SET setting = 'on' WHERE name = 'transform_null_equals';\n", "pg_settings"),
    ("CREATE VIEW s AS SELECT * FROM pg_settings;\nALTER VIEW s RENAME TO z;\n", "pg_settings"),
    ("CREATE SCHEMA s CREATE VIEW v AS SELECT * FROM pg_catalog.pg_settings;\n"
     "UPDATE s.v SET setting = 'on' WHERE name = 'transform_null_equals';\n", "pg_settings"),
    ("SET client_encoding = 'UTF8';\n", False),
    ("SET client_encoding = 'LATIN1';\n", False),
    ("SET standard_conforming_strings = on;\n", False),
    ("SET standard_conforming_strings = tru;\n", False),
    ("SET standard_conforming_strings TO DEFAULT;\n", False),
])
def test_a_setting_that_changes_how_strings_read_is_refused(sql, refused):
    # Under SJIS a multibyte character can end in a backslash byte, and with
    # standard_conforming_strings off `\\'` escapes: Postgres would end
    # strings where pgrls does not.
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql

    sql += "CREATE TABLE public.t (id int);\n"
    if refused:
        why = refused if isinstance(refused, str) else "reads its text differently"
        with pytest.raises(SchemaSourceError, match=why):
            schema_from_sql(sql)
    else:
        assert "t" in [t.name for t in schema_from_sql(sql).tables]


@pytest.mark.parametrize("sql", [
    # A COPY and a `\\.` line inside a string, a function body or a comment
    # are no COPY data: only a line pg_dump writes, outside them, is.
    "CREATE FUNCTION h() RETURNS text LANGUAGE sql AS $$ SELECT 'COPY t FROM stdin;\n1\n\\.\n' $$;\n",
    "CREATE TABLE u (id int);\nCOMMENT ON TABLE u IS 'Load with psql:\nCOPY u FROM stdin;\n1\n\\.\n';\n",
    "/* COPY t FROM stdin;\n\\.\n*/\nCREATE TABLE u (id int);\n",
])
def test_copy_text_outside_a_dump_with_data_is_read(sql):
    from pgrls.schema_sources import schema_from_sql

    assert "t" in [t.name for t in schema_from_sql("CREATE TABLE t (id int);\n" + sql).tables]


def test_the_copy_data_check_is_linear():
    import time

    from pgrls.schema_sources import schema_from_sql

    rows = "".join(f"INSERT INTO t VALUES ('ad copy number {i} from the stdin desk');\n"
                   for i in range(8000))
    sql = "CREATE TABLE t (a text);\n" + rows + "INSERT INTO t VALUES ('x\n\\.\ny');\n"
    start = time.monotonic()
    schema_from_sql(sql)
    assert time.monotonic() - start < 10


def test_harmless_psql_commands_are_skipped():
    from pgrls.schema_sources import schema_from_sql

    # pg_dump --create lifts its `\\restrict` around the `\\connect`.
    sql = ("\\echo start\n\\restrict k\nCREATE DATABASE d;\n\\unrestrict k\n\\connect d\n"
           "\\pset pager off\n\\restrict k\nCREATE TABLE t (id int);\n\\unrestrict k\n")
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]
    # pg_dump double-quotes a name that needs it, and psql skips a BOM.
    for name in ("MyApp", "user", "my.app", 'a""b'):
        sql = (f'CREATE DATABASE "{name}";\n\\connect "{name}"\n'
               'CREATE TABLE t (id int);\n')
        assert [t.name for t in schema_from_sql(sql).tables] == ["t"], name
    assert [t.name for t in schema_from_sql("\ufeffCREATE TABLE t (id int);\n").tables] == ["t"]
    # ... and its conninfo form for any other name, conninfo-escaped inside
    # psql's double quotes.
    for name, written in (("my:app", "my:app"), ('a"b', 'a""b'), ("it's", "it\\'s"), ("a`b", "a`b"),
                          ("back\\slash", "back\\\\slash")):
        quoted = name.replace('"', '""')
        sql = (f'CREATE DATABASE "{quoted}";\n'
               f'\\connect -reuse-previous=on "dbname=\'{written}\'"\n'
               'CREATE TABLE t (id int);\n')
        assert [t.name for t in schema_from_sql(sql).tables] == ["t"], name
    # pg_dump --create --clean of a template database clears its flag first.
    sql = ("UPDATE pg_catalog.pg_database SET datistemplate = false WHERE datname = 'd';\n"
           "DROP DATABASE IF EXISTS d;\nCREATE DATABASE d WITH TEMPLATE = template0;\n"
           "\\connect d\nCREATE TABLE t (id int);\n")
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]
    # A database's security label, and pg_restore --transaction-size's
    # committed transactions, before the `\\connect`.
    sql = ("BEGIN;\nCOMMIT;\nCREATE DATABASE d;\nBEGIN;\nCOMMIT;\n\\connect d\n"
           "SECURITY LABEL FOR selinux ON DATABASE d IS 'x';\n"
           "ALTER DATABASE d SET work_mem = '8MB';\n\\connect d\nCREATE TABLE t (id int);\n")
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]
    # A script's settings of psql's own error and output handling.
    sql = "\\set ON_ERROR_STOP on\n\\set QUIET\nCREATE TABLE t (id int);\n"
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]
    # pg_dump --create's form for a name that needs quoting, after an
    # `\\encoding` of the server's.
    sql = ('CREATE DATABASE "my-app";\n\\encoding SQL_ASCII\n'
           '\\connect -reuse-previous=on "dbname=\'my-app\'"\nCREATE TABLE t (id int);\n')
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]
    # A UTF8 database reads the text as pgrls does.
    sql = ("CREATE DATABASE d ENCODING 'UTF8';\n\\connect d\n"
           'CREATE TABLE "\u00e9" (id int);\n')
    assert [t.name for t in schema_from_sql(sql).tables] == ["\u00e9"]
    # pg_dump --create connects again after the database's own settings.
    sql = ("CREATE DATABASE d;\n\\connect d\nALTER DATABASE d SET work_mem = '4MB';\n"
           "ALTER ROLE app IN DATABASE d SET work_mem = '4MB';\n\\connect d\n"
           "CREATE TABLE t (id int);\n")
    assert [t.name for t in schema_from_sql(sql).tables] == ["t"]



def test_each_sql_file_may_open_with_a_byte_order_mark(tmp_path):
    from pgrls.cli import main

    # psql skips the BOM of each file it reads.
    (tmp_path / "001.sql").write_text("CREATE TABLE public.a (id int);\n")
    (tmp_path / "002.sql").write_bytes(b"\xef\xbb\xbfCREATE TABLE public.b (id int);\n")
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(tmp_path / "001.sql"),
                                    "--sql-file", str(tmp_path / "002.sql"), "--format", "json"])
    locations = {v["location"] for v in json.loads(res.stdout)["violations"]}
    assert {"public.a", "public.b"} <= locations, res.output


def test_offline_policy_keeps_the_parentheses_its_predicate_needs():
    # The DB-free source renders each predicate from its AST; pglast's
    # deparser drops the parentheses `(a OR b) BETWEEN …` needs, which would
    # hand the rules a different predicate than the SQL wrote.
    from pgrls.ast_utils import parse_expr
    from pgrls.schema_sources import schema_from_sql

    source = "(tenant_id = 1 OR is_public) BETWEEN true AND true"
    schema = schema_from_sql(
        "CREATE TABLE t (tenant_id int, is_public bool);"
        f" CREATE POLICY p ON t USING ({source});", schemas=("public",))
    assert parse_expr(schema.tables[0].policies[0].using_sql) == parse_expr(source)


def test_an_unprintable_clause_keeps_the_schema_its_tables_resolve_to(monkeypatch):
    # The resolver qualifies a table the policy reads on the search path, so
    # the clause as written no longer parses back to the tree; the schema is
    # written into it rather than the clause dropped.
    import pgrls.ast_utils
    from pgrls.ast_utils import parse_expr
    from pgrls.schema_sources import schema_from_sql

    def broken(node):
        raise TypeError("printer failed")

    monkeypatch.setattr(pgrls.ast_utils, "_render", broken)
    schema = schema_from_sql(
        "CREATE SCHEMA app; CREATE TABLE app.m (uid int); CREATE TABLE public.t (owner int);"
        " SET search_path = public, app;"
        " CREATE POLICY p ON t USING (owner OPERATOR(pg_catalog.=) ANY (SELECT uid FROM m) OR true);",
        schemas=("public", "app"))
    (policy,) = [p for t in schema.tables for p in t.policies]
    assert parse_expr(policy.using_sql) == parse_expr(
        'owner OPERATOR(pg_catalog.=) ANY (SELECT uid FROM app.m) OR true')


def test_offline_policy_pglast_cannot_print_keeps_the_clause_it_wrote(monkeypatch):
    # pglast 7's printer raises on `x OPERATOR(s.op) ANY (…)`, which pg_dump
    # writes; the clause was then dropped, so the rules (and `pgrls pr`) saw
    # a policy with no USING at all. The clause as written is used instead.
    import pgrls.ast_utils
    from pgrls.ast_utils import parse_expr
    from pgrls.schema_sources import schema_from_sql

    def broken(node):
        raise TypeError("printer failed")

    monkeypatch.setattr(pgrls.ast_utils, "_render", broken)
    using = "(auth.uid() IS NULL) OR (tenant_id OPERATOR(pg_catalog.=) ANY (ARRAY[1]))"
    check = "tenant_id = ANY (ARRAY['é'])"
    schema = schema_from_sql(
        "/* ü */ CREATE TABLE t (tenant_id int); -- é\n"
        f"CREATE POLICY \"using\" ON t FOR ALL TO \"with\" USING ({using} -- c\n)"
        " WITH CHECK (true);\n"
        f"ALTER POLICY \"using\" ON t WITH CHECK (/* x */ {check})",
        schemas=("public",))
    policy = schema.tables[0].policies[0]
    assert policy.using_sql == using
    assert parse_expr(policy.with_check_sql) == parse_expr(check)
    assert policy.using_ast is not None

    # The other clause of each statement, and comments, which a snapshot
    # refuses in a predicate; a string still continues across a line break.
    schema = schema_from_sql(
        "CREATE TABLE t (tenant_id int, s text);\n"
        f"CREATE POLICY p ON t FOR ALL USING (true) WITH CHECK ({check} /* x */);\n"
        "ALTER POLICY p ON t USING (s = 'a'\n'b' -- c\nOR tenant_id = 1);",
        schemas=("public",))
    policy = schema.tables[0].policies[0]
    assert "/*" not in policy.with_check_sql and "--" not in policy.using_sql
    assert parse_expr(policy.with_check_sql) == parse_expr(check)
    assert parse_expr(policy.using_sql) == parse_expr("s = 'ab' OR tenant_id = 1")


def test_offline_constraint_before_a_rebuild_does_not_reach_the_new_table():
    # An ADD PRIMARY KEY / NOT NULL constraint that ran before DROP TABLE and
    # a re-CREATE constrained the old table only (measured on PG18).
    t = _only(
        "CREATE TABLE docs (id int, tenant_id uuid);"
        " ALTER TABLE docs ADD PRIMARY KEY (id, tenant_id);"
        " DROP TABLE docs; CREATE TABLE docs (id int, tenant_id uuid);"
    )
    assert {c.name: c.is_nullable for c in t.column_details}["tenant_id"] is True


@pytest.mark.parametrize("sql", [
    # The RLS flags, policies and grants of a table dropped and made again
    # are gone with it.
    "CREATE TABLE public.t (id int);\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n"
    "CREATE POLICY p ON public.t USING (id = 1);\nGRANT SELECT ON public.t TO anon;\n"
    "DROP TABLE public.t;\nCREATE TABLE public.t (id int);\n",
    "CREATE SCHEMA x;\nCREATE TABLE x.t (id int);\nALTER TABLE x.t ENABLE ROW LEVEL SECURITY;\n"
    "DROP SCHEMA x CASCADE;\nCREATE SCHEMA x;\nCREATE TABLE x.t (id int);\n",
])
def test_a_table_made_again_after_a_drop_starts_afresh(sql):
    from pgrls.schema_sources import schema_from_sql
    (t,) = schema_from_sql(sql, schemas=("public", "x")).tables
    assert (t.rls_enabled, t.policies, t.grants) == (False, (), ())


def test_a_schema_dropped_takes_its_tables():
    from pgrls.schema_sources import schema_from_sql
    assert schema_from_sql("CREATE SCHEMA x;\nCREATE TABLE x.t (id int);\n"
                           "DROP SCHEMA x CASCADE;\n", schemas=("x",)).tables == ()


def test_an_empty_search_path_set_names_no_schema():
    from pgrls.schema_sources import schema_from_sql
    (t,) = schema_from_sql("CREATE TABLE public.t (id int);\nSET search_path = '';\n"
                           "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n").tables
    assert not t.rls_enabled  # Postgres: relation "t" does not exist


def test_a_policy_reading_a_name_with_no_schema_to_find_it_in_is_refused():
    from pgrls.schema_sources import SchemaSourceError, schema_from_sql
    with pytest.raises(SchemaSourceError, match="no schema on search_path to find it"):
        schema_from_sql("CREATE TABLE public.t (id int);\nCREATE TABLE public.u (id int);\n"
                        "SET search_path = '';\n"
                        "CREATE POLICY p ON public.t USING (EXISTS (SELECT 1 FROM u));\n")


@pytest.mark.parametrize("ending", [
    "BEGIN;\nCOMMIT AND CHAIN;\nALTER TABLE public.t DISABLE ROW LEVEL SECURITY;\n",
    "BEGIN;\nROLLBACK AND CHAIN;\nALTER TABLE public.t DISABLE ROW LEVEL SECURITY;\n",
])
def test_a_migration_file_left_in_a_chained_transaction_is_refused(tmp_path, ending):
    res, _ = _migrations_snapshot(tmp_path, {
        "001_a.sql": "CREATE TABLE public.t (id int);\nALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n",
        "002_b.sql": ending,
    })
    assert res.exit_code != 0 and "ends inside a transaction" in res.output


def test_a_migration_file_preparing_a_transaction_is_refused_not_a_crash(tmp_path):
    res, _ = _migrations_snapshot(tmp_path, {
        "001_a.sql": "BEGIN;\nCREATE TABLE public.t (id int);\nPREPARE TRANSACTION 'x';\n"})
    assert res.exit_code == 2 and "PREPARE TRANSACTION" in res.output


def test_alter_system_search_path_is_not_followed_in_later_files(tmp_path):
    res, _ = _migrations_snapshot(tmp_path, {
        "001_a.sql": "CREATE SCHEMA app;\nALTER SYSTEM SET search_path = app, public;\n"
                     "SELECT pg_reload_conf();\n",
        "002_b.sql": "CREATE TABLE t (id int);\n",
    })
    assert res.exit_code != 0 and "search_path" in res.output

_AUTH_UID = ("CREATE SCHEMA auth;\n"
             "CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;\n"
             "CREATE TABLE public.docs (id int, owner_id uuid);\n"
             "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n")


def _policy_using(sql):
    from pgrls.schema_sources import schema_from_sql
    (docs,) = [t for t in schema_from_sql(sql).tables if t.name == "docs"]
    return docs.policies[0].using_sql


def test_an_unqualified_policy_call_names_the_function_the_path_finds(tmp_path):
    # As `pg_get_expr` writes it live: `auth.uid()`, which SEC004 / SEC038 /
    # PERF001 / SEC030 key on.
    import json
    from click.testing import CliRunner
    from pgrls.cli import main
    sql = (_AUTH_UID + "SET search_path = public, auth;\n"
           "CREATE POLICY p ON docs FOR SELECT TO anon USING (uid() IS NULL OR owner_id = uid());\n")
    assert _policy_using(sql) == "auth.uid() IS NULL OR owner_id = auth.uid()"
    path = tmp_path / "s.sql"
    path.write_text(sql)
    res = CliRunner().invoke(main, ["lint", "--sql-file", str(path), "--format", "json"])
    found = {v["rule_id"] for v in json.loads(res.stdout)["violations"]}
    assert {"SEC004", "SEC038", "PERF001", "SEC030"} <= found, res.output


@pytest.mark.parametrize("sql", [
    # A built-in of the name is searched first.
    "CREATE FUNCTION auth.now() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\n"
    "SET search_path = public, auth;\n"
    "CREATE POLICY p ON docs USING (now() IS NOT NULL);\n",
    # Two schemas on the path hold one (the arguments decide which).
    "CREATE SCHEMA app;\nCREATE FUNCTION app.uid() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$;\n"
    "SET search_path = app, auth;\nCREATE POLICY p ON public.docs USING (owner_id = uid());\n",
    # Not on the path, made after the policy, or dropped before it.
    "CREATE POLICY p ON docs USING (owner_id = uid());\n",
    "SET search_path = public, auth;\nDROP FUNCTION auth.uid();\n"
    "CREATE POLICY p ON docs USING (owner_id = uid());\n",
    # An extension or a DO block may make one pgrls does not see.
    "CREATE EXTENSION IF NOT EXISTS pgcrypto;\nSET search_path = public, auth;\n"
    "CREATE POLICY p ON docs USING (owner_id = uid());\n",
    "DO $$ BEGIN END $$;\nSET search_path = public, auth;\n"
    "CREATE POLICY p ON docs USING (owner_id = uid());\n",
    # A function it runs may make one (with EXECUTE), as may a range type.
    "CREATE FUNCTION public.setup() RETURNS void LANGUAGE sql AS $$ SELECT $$;\n"
    "SELECT public.setup();\nSET search_path = public, auth;\n"
    "CREATE POLICY p ON docs USING (owner_id = uid());\n",
    "SELECT pg_catalog.query_to_xml('SELECT 1', true, false, '');\nSET search_path = public, auth;\n"
    "CREATE POLICY p ON docs USING (owner_id = uid());\n",
    "CREATE MATERIALIZED VIEW mv AS SELECT 1 WITH NO DATA;\nREFRESH MATERIALIZED VIEW mv;\n"
    "SET search_path = public, auth;\nCREATE POLICY p ON docs USING (owner_id = uid());\n",
    "CREATE TYPE public.r AS RANGE (subtype = int, multirange_type_name = public.uid);\n"
    "SET search_path = public, auth;\nCREATE POLICY p ON docs USING (owner_id = uid());\n",
])
def test_an_unqualified_policy_call_stays_as_written_where_unsure(sql):
    assert "auth" not in _policy_using(_AUTH_UID + sql)


def test_a_built_in_run_leaves_the_policy_calls_followed():
    # pg_dump's `SELECT pg_catalog.set_config(…)` runs no user code.
    sql = (_AUTH_UID + "SELECT pg_catalog.set_config('search_path', 'public, auth', false);\n"
           "CREATE POLICY p ON docs USING (owner_id = uid());\n")
    assert _policy_using(sql) == "owner_id = auth.uid()"


def test_a_policy_call_on_the_default_path_stays_unqualified():
    # `pg_get_expr` leaves `public.uid()` unqualified on the default path.
    sql = ("CREATE FUNCTION public.uid() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$;\n"
           "CREATE TABLE public.docs (id int, owner_id uuid);\n"
           "CREATE POLICY p ON docs USING (owner_id = uid());\n")
    assert _policy_using(sql) == "owner_id = uid()"


def test_what_the_sql_did_to_a_table_renamed_away_before_a_drop_stays():
    from pgrls.schema_sources import schema_from_sql
    tables = {t.name: t for t in schema_from_sql(
        "CREATE TABLE accounts (id int);\nALTER TABLE accounts ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON accounts TO anon USING (true);\nGRANT SELECT ON accounts TO anon;\n"
        "ALTER TABLE accounts RENAME TO accounts_legacy;\nDROP TABLE IF EXISTS accounts;\n"
        "CREATE TABLE accounts (id int);\n").tables}
    legacy = tables["accounts_legacy"]
    assert legacy.rls_enabled and len(legacy.policies) == 1 and legacy.grants


def test_a_partition_detached_before_its_parents_drop_stands_alone():
    from pgrls.schema_sources import schema_from_sql
    tables = {t.name: t for t in schema_from_sql(
        "CREATE TABLE p (id int) PARTITION BY RANGE (id);\n"
        "CREATE TABLE c PARTITION OF p FOR VALUES FROM (0) TO (10);\n"
        "ALTER TABLE p DETACH PARTITION c;\nDROP TABLE p;\n"
        "CREATE TABLE p (id int) PARTITION BY RANGE (id);\n").tables}
    assert tables["c"].partition_of is None


def test_a_table_made_again_after_a_drop_has_its_new_columns():
    from pgrls.schema_sources import schema_from_sql
    (p,) = schema_from_sql("CREATE TABLE p (x int);\nDROP TABLE p;\n"
                           "CREATE TABLE p (y int, tenant_id int);\n").tables
    assert list(p.columns) == ["y", "tenant_id"]
