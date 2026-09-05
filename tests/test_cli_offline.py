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
