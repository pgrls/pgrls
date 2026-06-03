"""Unit + CLI tests for `pgrls perf` (runtime seq-scan analysis).

The pure analysis (`build_perf_report`) and the renderers are exercised
with hand-built schemas and stats — no database. The CLI command is run
with `psycopg.connect`, `introspect`, and `collect_table_stats` mocked, so
the plumbing (thresholds, formats, --output, --fail-on-findings) is pinned
without a live server. The live SQL and the PERF003 cross-reference are
covered end-to-end in test_perf_e2e.py.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import psycopg
from click.testing import CliRunner

from pgrls.cli import main
from pgrls.model import Policy, Schema, Table
from pgrls.perf import (
    ARTIFACT_VERSION,
    CONFIRMED,
    DEFAULT_PERF_ARTIFACT_PATH,
    INDEX_UNUSED,
    PERF_FORMATS,
    PerfFinding,
    PerfReport,
    PerfThresholds,
    StatementStat,
    TableStats,
    _relations_in,
    build_perf_report,
    collect_statements,
    load_perf_artifact,
    render,
    top_statements_for,
    under_seq_scan_pressure,
    write_perf_artifact,
)


def _table(name: str, *, rls: bool, schema: str = "public") -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=rls,
        policies=(
            Policy(
                name=f"{name}_p",
                command="ALL",
                permissive=True,
                roles=("authenticated",),
                using_sql="true",
                with_check_sql=None,
            ),
        ),
    )


def _stats(
    schema: str,
    name: str,
    *,
    seq_scan: int,
    seq_tup_read: int,
    idx_scan: int = 0,
    n_live_tup: int,
) -> TableStats:
    return TableStats(
        schema=schema,
        table=name,
        seq_scan=seq_scan,
        seq_tup_read=seq_tup_read,
        idx_scan=idx_scan,
        n_live_tup=n_live_tup,
    )


# ---------- TableStats arithmetic ----------


def test_seq_scan_pct_and_avg() -> None:
    ts = _stats("public", "t", seq_scan=300, seq_tup_read=3_000_000, idx_scan=100, n_live_tup=10_000)
    assert ts.total_scans == 400
    assert ts.seq_scan_pct == 75.0
    assert ts.avg_seq_rows == 10_000.0


def test_seq_scan_pct_zero_when_never_scanned() -> None:
    ts = _stats("public", "t", seq_scan=0, seq_tup_read=0, idx_scan=0, n_live_tup=5)
    assert ts.seq_scan_pct == 0.0
    assert ts.avg_seq_rows == 0.0


def test_seq_scan_pct_all_sequential() -> None:
    ts = _stats("public", "t", seq_scan=10, seq_tup_read=50, idx_scan=0, n_live_tup=5)
    assert ts.seq_scan_pct == 100.0


# ---------- build_perf_report: classification ----------


def _big(name: str) -> TableStats:
    # Comfortably over every default threshold.
    return _stats("public", name, seq_scan=500, seq_tup_read=5_000_000, idx_scan=1, n_live_tup=500_000)


def test_confirmed_when_statically_flagged() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    report = build_perf_report(
        schema,
        {("public", "posts"): _big("posts")},
        statically_flagged={("public", "posts")},
    )
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.classification == CONFIRMED
    assert f.severity == "warning"


def test_index_unused_when_not_flagged() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    report = build_perf_report(
        schema,
        {("public", "posts"): _big("posts")},
        statically_flagged=set(),
    )
    assert report.findings[0].classification == INDEX_UNUSED
    assert report.findings[0].severity == "info"


# ---------- build_perf_report: gating ----------


def test_non_rls_table_never_a_finding() -> None:
    schema = Schema(tables=(_table("public_data", rls=False),))
    report = build_perf_report(
        schema,
        {("public", "public_data"): _big("public_data")},
        statically_flagged=set(),
    )
    assert report.findings == ()
    # Not RLS-enabled → not even counted in the considered denominator.
    assert report.rls_tables_considered == 0


def test_rls_table_without_stats_is_skipped() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    report = build_perf_report(schema, {}, statically_flagged=set())
    assert report.findings == ()
    assert report.rls_tables_considered == 0


def test_small_table_below_min_rows_skipped() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _stats("public", "posts", seq_scan=500, seq_tup_read=5000, idx_scan=0, n_live_tup=100)}
    report = build_perf_report(schema, stats, statically_flagged=set())
    assert report.findings == ()
    # It HAD stats and is RLS — counted as considered, just under threshold.
    assert report.rls_tables_considered == 1


def test_few_seq_scans_below_threshold_skipped() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _stats("public", "posts", seq_scan=5, seq_tup_read=5_000_000, idx_scan=0, n_live_tup=500_000)}
    report = build_perf_report(schema, stats, statically_flagged=set())
    assert report.findings == ()


def test_mostly_indexed_below_seq_pct_skipped() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    # 100 seq scans but 100000 index scans → ~0.1% sequential.
    stats = {("public", "posts"): _stats("public", "posts", seq_scan=100, seq_tup_read=5_000_000, idx_scan=100_000, n_live_tup=500_000)}
    report = build_perf_report(schema, stats, statically_flagged=set())
    assert report.findings == ()
    assert report.rls_tables_considered == 1


def test_custom_thresholds_lower_the_bar() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _stats("public", "posts", seq_scan=5, seq_tup_read=500, idx_scan=0, n_live_tup=100)}
    # Default thresholds skip it; a permissive threshold set surfaces it.
    assert build_perf_report(schema, stats, statically_flagged=set()).findings == ()
    loose = PerfThresholds(min_live_tup=10, min_seq_scans=1, min_seq_pct=10.0)
    report = build_perf_report(schema, stats, statically_flagged=set(), thresholds=loose)
    assert len(report.findings) == 1


# ---------- build_perf_report: ranking ----------


def test_findings_ranked_by_seq_tup_read_desc() -> None:
    schema = Schema(
        tables=(_table("small", rls=True), _table("big", rls=True), _table("mid", rls=True))
    )
    stats = {
        ("public", "small"): _stats("public", "small", seq_scan=100, seq_tup_read=1_000_000, idx_scan=0, n_live_tup=500_000),
        ("public", "big"): _stats("public", "big", seq_scan=100, seq_tup_read=9_000_000, idx_scan=0, n_live_tup=500_000),
        ("public", "mid"): _stats("public", "mid", seq_scan=100, seq_tup_read=4_000_000, idx_scan=0, n_live_tup=500_000),
    }
    report = build_perf_report(schema, stats, statically_flagged=set())
    assert [f.stats.table for f in report.findings] == ["big", "mid", "small"]
    assert report.rls_tables_considered == 3


def test_summary_counts() -> None:
    schema = Schema(tables=(_table("a", rls=True), _table("b", rls=True)))
    stats = {("public", "a"): _big("a"), ("public", "b"): _big("b")}
    report = build_perf_report(schema, stats, statically_flagged={("public", "a")})
    s = report.summary
    assert s == {"rls_tables": 2, "findings": 2, "confirmed": 1, "index_unused": 1}


# ---------- renderers ----------


def _report_one() -> PerfReport:
    ts = _stats("public", "posts", seq_scan=500, seq_tup_read=5_000_000, idx_scan=1, n_live_tup=500_000)
    return PerfReport(findings=(PerfFinding(ts, CONFIRMED, "warning"),), rls_tables_considered=3)


def test_render_empty_no_rls_tables() -> None:
    report = PerfReport(findings=(), rls_tables_considered=0)
    assert "No RLS-enabled tables with statistics" in render(report, "text")


def test_render_empty_with_rls_tables_below_threshold() -> None:
    report = PerfReport(findings=(), rls_tables_considered=4)
    assert "No seq-scan pressure" in render(report, "text")


def test_render_text_has_table_and_caveat() -> None:
    out = render(_report_one(), "text")
    assert "public.posts" in out
    assert "confirmed (no index)" in out
    assert "pg_stat_user_tables counts all sequential scans" in out
    # thousands separators in the numeric columns.
    assert "5,000,000" in out


def test_render_json_shape() -> None:
    payload = json.loads(render(_report_one(), "json"))
    assert payload["summary"]["confirmed"] == 1
    assert payload["thresholds"]["min_live_tup"] == PerfThresholds().min_live_tup
    row = payload["findings"][0]
    assert row["table"] == "public.posts"
    assert row["classification"] == CONFIRMED
    assert row["seq_tup_read"] == 5_000_000


def test_render_markdown_table() -> None:
    md = render(_report_one(), "markdown")
    assert md.startswith("# Runtime RLS seq-scan report")
    assert "| `public.posts` |" in md
    assert md.endswith("\n")


def _report_one_named(name: str) -> PerfReport:
    ts = _stats(
        "public", name, seq_scan=500, seq_tup_read=5_000_000,
        idx_scan=1, n_live_tup=500_000,
    )
    return PerfReport(
        findings=(PerfFinding(ts, CONFIRMED, "warning"),),
        rls_tables_considered=1,
    )


def _perf_md_finding_rows(out: str) -> list[str]:
    """Markdown data rows for the findings table (before the optional
    statements section), excluding heading / caveat / header / sep."""
    rows: list[str] = []
    for ln in out.splitlines():
        if not ln.startswith("| `"):
            continue  # only finding rows start with a backticked table cell
        rows.append(ln)
    return rows


def test_render_markdown_pipe_in_name_does_not_corrupt_table() -> None:
    # A `|` in a quoted Postgres identifier must be escaped inside the
    # backtick code span so it doesn't add a phantom GFM column.
    # Regression for audit finding #17.
    out = render(_report_one_named("we|rd"), "markdown")
    rows = _perf_md_finding_rows(out)
    assert len(rows) == 1
    row = rows[0]
    assert "public.we\\|rd" in row
    # 6 columns → 7 unescaped pipe delimiters.
    assert row.replace("\\|", "").count("|") == 7


def test_render_markdown_newline_in_name_does_not_split_row() -> None:
    # Regression for #17: a `\n` would end the GFM row early.
    out = render(_report_one_named("we\nrd"), "markdown")
    rows = _perf_md_finding_rows(out)
    assert len(rows) == 1
    assert "public.we\\nrd" in rows[0]


def test_render_text_newline_in_name_does_not_split_row() -> None:
    # Regression for audit finding #23: a `\n` in a name must not
    # split the fixed-width text row.
    out = render(_report_one_named("we\nrd"), "text")
    data_lines = [ln for ln in out.splitlines() if "public.we" in ln]
    assert len(data_lines) == 1
    assert "public.we\\nrd" in data_lines[0]


def test_render_html_escapes_and_is_standalone() -> None:
    ts = _stats("public", "tab<x>", seq_scan=500, seq_tup_read=5_000_000, idx_scan=1, n_live_tup=500_000)
    report = PerfReport(findings=(PerfFinding(ts, INDEX_UNUSED, "info"),), rls_tables_considered=1)
    out = render(report, "html")
    assert out.startswith("<!DOCTYPE html>")
    assert "tab&lt;x&gt;" in out  # identifier escaped
    assert "<tab<x>" not in out


def test_all_formats_agree_on_table_set() -> None:
    schema = Schema(tables=(_table("a", rls=True), _table("b", rls=True)))
    stats = {("public", "a"): _big("a"), ("public", "b"): _big("b")}
    report = build_perf_report(schema, stats, statically_flagged={("public", "a")})
    text = render(report, "text")
    payload = json.loads(render(report, "json"))
    md = render(report, "markdown")
    html_out = render(report, "html")
    json_tables = {r["table"] for r in payload["findings"]}
    assert json_tables == {"public.a", "public.b"}
    for t in json_tables:
        assert t in text and f"`{t}`" in md and t in html_out


def test_perf_formats_are_the_four_expected() -> None:
    assert set(PERF_FORMATS) == {"text", "json", "markdown", "html"}


# ---------- CLI command (mocked introspection + stats) ----------


def _run_perf(args, *, schema: Schema, stats: dict, flagged=frozenset()):
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=schema
    ), patch("pgrls.cli.collect_table_stats", return_value=stats), patch(
        "pgrls.cli._perf003_flagged_tables", return_value=set(flagged)
    ):
        return CliRunner().invoke(
            main, ["perf", "--database-url", "postgresql://x", *args]
        )


def test_cli_perf_reports_json() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    res = _run_perf(
        ["--format", "json"],
        schema=schema,
        stats={("public", "posts"): _big("posts")},
        flagged={("public", "posts")},
    )
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["findings"][0]["table"] == "public.posts"
    assert payload["findings"][0]["classification"] == CONFIRMED


def test_cli_perf_output_file_matches_stdout(tmp_path) -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _big("posts")}
    stdout = _run_perf(["--format", "markdown"], schema=schema, stats=stats)
    out = tmp_path / "perf.md"
    res = _run_perf(
        ["--format", "markdown", "--output", str(out)], schema=schema, stats=stats
    )
    assert res.exit_code == 0, res.output
    assert out.read_text(encoding="utf-8") == stdout.output


def test_cli_perf_fail_on_findings_gates() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    big = {("public", "posts"): _big("posts")}
    # Findings + the flag → exit 1.
    res = _run_perf(["--fail-on-findings"], schema=schema, stats=big)
    assert res.exit_code == 1, res.output
    assert "under seq-scan pressure" in res.output
    # No findings (small table) + the flag → exit 0.
    small = {("public", "posts"): _stats("public", "posts", seq_scan=1, seq_tup_read=1, idx_scan=0, n_live_tup=1)}
    res2 = _run_perf(["--fail-on-findings"], schema=schema, stats=small)
    assert res2.exit_code == 0, res2.output


def test_cli_perf_custom_thresholds() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _stats("public", "posts", seq_scan=5, seq_tup_read=500, idx_scan=0, n_live_tup=100)}
    # Defaults: no findings.
    res = _run_perf(["--format", "json"], schema=schema, stats=stats)
    assert json.loads(res.output)["summary"]["findings"] == 0
    # Loosened thresholds via flags: one finding.
    res2 = _run_perf(
        ["--format", "json", "--min-rows", "10", "--min-seq-scans", "1", "--min-seq-pct", "10"],
        schema=schema,
        stats=stats,
    )
    assert json.loads(res2.output)["summary"]["findings"] == 1


def test_cli_perf_requires_database_url(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    res = CliRunner().invoke(main, ["perf"])
    assert res.exit_code == 2
    assert "No database connection" in res.output


def test_cli_perf_rejects_unknown_format() -> None:
    schema = Schema(tables=())
    res = _run_perf(["--format", "yaml"], schema=schema, stats={})
    assert res.exit_code == 2


def test_cli_help_lists_perf() -> None:
    res = CliRunner().invoke(main, ["perf", "--help"])
    assert res.exit_code == 0
    for flag in (
        "--min-rows",
        "--min-seq-scans",
        "--min-seq-pct",
        "--fail-on-findings",
        "--snapshot",
    ):
        assert flag in res.output


# ---------- threshold predicate ----------


def test_under_seq_scan_pressure_gates() -> None:
    th = PerfThresholds()
    assert under_seq_scan_pressure(_big("posts"), th) is True
    # Each individual gate, just under, fails the whole predicate.
    assert under_seq_scan_pressure(
        _stats("public", "posts", seq_scan=500, seq_tup_read=9, idx_scan=1, n_live_tup=100),
        th,
    ) is False  # too few rows
    assert under_seq_scan_pressure(
        _stats("public", "posts", seq_scan=2, seq_tup_read=9, idx_scan=1, n_live_tup=500_000),
        th,
    ) is False  # too few scans
    assert under_seq_scan_pressure(
        _stats("public", "posts", seq_scan=60, seq_tup_read=9, idx_scan=100_000, n_live_tup=500_000),
        th,
    ) is False  # mostly index-scanned


# ---------- artifact round-trip + validation ----------

_AWARE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_perf_artifact_round_trip(tmp_path) -> None:
    stats = {
        ("public", "posts"): _big("posts"),
        ("public", "notes"): _stats("public", "notes", seq_scan=10, seq_tup_read=20, idx_scan=5, n_live_tup=30),
    }
    path = str(tmp_path / "perf.json")
    write_perf_artifact(path, stats, generated_at=_AWARE)
    loaded = load_perf_artifact(path)
    assert set(loaded) == {("public", "posts"), ("public", "notes")}
    assert loaded[("public", "posts")].seq_tup_read == 5_000_000
    # The on-disk shape carries the version + tz-aware timestamp.
    payload = json.loads((tmp_path / "perf.json").read_text(encoding="utf-8"))
    assert payload["pgrls_perf_version"] == ARTIFACT_VERSION
    assert payload["generated_at"].endswith("Z")


def test_perf_artifact_rejects_bad_version(tmp_path) -> None:
    path = tmp_path / "perf.json"
    path.write_text('{"pgrls_perf_version": 999, "tables": []}', encoding="utf-8")
    try:
        load_perf_artifact(str(path))
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "version" in str(exc)


def test_perf_artifact_rejects_malformed_row(tmp_path) -> None:
    path = tmp_path / "perf.json"
    path.write_text(
        f'{{"pgrls_perf_version": {ARTIFACT_VERSION}, '
        '"tables": [{"schema": "public"}]}',  # missing required keys
        encoding="utf-8",
    )
    try:
        load_perf_artifact(str(path))
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "malformed" in str(exc)


# ---------- lint --perf wiring (PERF005) ----------


def _lint_perf(args, *, schema: Schema):
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=schema
    ):
        return CliRunner().invoke(
            main, ["lint", "--database-url", "postgresql://x", *args]
        )


def test_cli_lint_perf_enables_perf005(tmp_path) -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    artifact = str(tmp_path / ".pgrls-perf.json")
    write_perf_artifact(
        artifact, {("public", "posts"): _big("posts")}, generated_at=_AWARE
    )
    # Without --perf, PERF005 is inert (no finding even though stats exist).
    res_off = _lint_perf(["--rule", "PERF005", "--format", "json"], schema=schema)
    assert res_off.exit_code == 0, res_off.output
    assert json.loads(res_off.output)["violations"] == []
    # With --perf, PERF005 fires.
    res_on = _lint_perf(
        ["--rule", "PERF005", "--perf", artifact, "--format", "json"],
        schema=schema,
    )
    ids = [v["rule_id"] for v in json.loads(res_on.output)["violations"]]
    assert ids == ["PERF005"], res_on.output


def test_cli_lint_perf_missing_artifact_errors(tmp_path) -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    res = _lint_perf(
        ["--perf", str(tmp_path / "nope.json"), "--rule", "PERF005"],
        schema=schema,
    )
    assert res.exit_code == 2
    assert "not found" in res.output


def test_cli_perf_snapshot_writes_loadable_artifact(tmp_path) -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _big("posts")}
    out = tmp_path / "snap.json"
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=schema
    ), patch("pgrls.cli.collect_table_stats", return_value=stats), patch(
        "pgrls.cli._perf003_flagged_tables", return_value=set()
    ):
        res = CliRunner().invoke(
            main,
            ["perf", "--database-url", "postgresql://x", "--snapshot", str(out)],
        )
    assert res.exit_code == 0, res.output
    loaded = load_perf_artifact(str(out))
    assert loaded[("public", "posts")].seq_scan == 500
    assert DEFAULT_PERF_ARTIFACT_PATH == ".pgrls-perf.json"


# ---------- pg_stat_statements enrichment (--statements / PR3) ----------


def _stmt(query, *, total_ms, mean_ms=1.0, calls=1, rows=0, tables=()):
    return StatementStat(
        query=query,
        calls=calls,
        total_exec_ms=total_ms,
        mean_exec_ms=mean_ms,
        rows=rows,
        tables=frozenset(tables),
    )


def test_statement_references_qualified_and_bare() -> None:
    s = _stmt("...", total_ms=1.0, tables={("public", "posts")})
    assert s.references("public", "posts") is True
    assert s.references("other", "posts") is False
    bare = _stmt("...", total_ms=1.0, tables={(None, "posts")})
    assert bare.references("public", "posts") is True  # unqualified matches any schema


def test_statement_short_query_flattens_and_caps() -> None:
    s = _stmt("SELECT\n  *\n  FROM   posts", total_ms=1.0)
    assert s.short_query() == "SELECT * FROM posts"
    long = _stmt("SELECT " + "x" * 200, total_ms=1.0)
    assert len(long.short_query(width=40)) == 40 and long.short_query(width=40).endswith("…")


def test_relations_in_parses_joins_and_tolerates_garbage() -> None:
    rels = _relations_in(
        "SELECT * FROM public.posts p JOIN notes n ON n.id = p.id WHERE p.tenant_id = $1"
    )
    assert ("public", "posts") in rels and (None, "notes") in rels
    assert _relations_in("this is not valid sql ;;;") == frozenset()


def test_top_statements_filters_to_pressured_and_ranks() -> None:
    ts = _stats("public", "posts", seq_scan=500, seq_tup_read=5_000_000, idx_scan=1, n_live_tup=500_000)
    report = PerfReport(findings=(PerfFinding(ts, CONFIRMED, "warning"),), rls_tables_considered=1)
    stmts = [
        _stmt("SELECT * FROM public.posts WHERE tenant_id=$1", total_ms=900, tables={("public", "posts")}),
        _stmt("SELECT * FROM public.posts", total_ms=2500, tables={("public", "posts")}),
        _stmt("SELECT * FROM unrelated", total_ms=9999, tables={(None, "unrelated")}),  # not pressured
    ]
    top = top_statements_for(report, stmts, limit=10)
    # Only posts-touching, ranked by total_exec_ms desc; 'unrelated' excluded.
    assert [round(s.total_exec_ms) for s in top] == [2500, 900]
    assert top_statements_for(report, stmts, limit=1)[0].total_exec_ms == 2500


class _FakeStmtCursor:
    def __init__(self, ext_present, rows, raise_on_query=False):
        self._ext_present, self._rows = ext_present, rows
        self._raise_on_query = raise_on_query

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._sql = sql
        # The view query (not the pg_extension check) raises when the
        # extension is registered but unreadable.
        if self._raise_on_query and "FROM pg_stat_statements" in sql:
            raise psycopg.OperationalError("permission denied")

    def fetchone(self):
        return (1,) if self._ext_present else None

    def fetchall(self):
        return self._rows


class _FakeStmtConn:
    def __init__(self, ext_present, rows, raise_on_query=False):
        self._cur = _FakeStmtCursor(ext_present, rows, raise_on_query)
        self.rolled_back = False

    def cursor(self, **kw):
        return self._cur

    def rollback(self):
        self.rolled_back = True


def test_collect_statements_none_when_extension_absent() -> None:
    assert collect_statements(_FakeStmtConn(False, [])) is None


def test_collect_statements_none_when_view_unreadable() -> None:
    # Extension registered but the view query errors (search_path / perms):
    # roll back and degrade to None rather than let the error escape.
    conn = _FakeStmtConn(True, [], raise_on_query=True)
    assert collect_statements(conn) is None
    assert conn.rolled_back is True


def test_collect_statements_parses_rows() -> None:
    rows = [
        {
            "query": "SELECT * FROM public.posts WHERE tenant_id = $1",
            "calls": 10,
            "total_exec_time": 123.4,
            "mean_exec_time": 12.34,
            "rows": 10,
        }
    ]
    out = collect_statements(_FakeStmtConn(True, rows))
    assert out is not None and len(out) == 1
    assert out[0].references("public", "posts") is True
    assert out[0].total_exec_ms == 123.4


def test_render_statements_section_tristate() -> None:
    ts = _stats("public", "posts", seq_scan=500, seq_tup_read=5_000_000, idx_scan=1, n_live_tup=500_000)
    base = PerfReport(findings=(PerfFinding(ts, CONFIRMED, "warning"),), rls_tables_considered=1)
    # None → no statements section in any format.
    for fmt in PERF_FORMATS:
        assert "Top statements" not in render(base, fmt)
    # populated
    s = _stmt("SELECT * FROM public.posts WHERE tenant_id=$1", total_ms=999, calls=42, tables={("public", "posts")})
    full = PerfReport(findings=base.findings, rls_tables_considered=1, statements=(s,))
    assert "Top statements" in render(full, "text")
    assert json.loads(render(full, "json"))["statements"][0]["calls"] == 42
    assert "Top statements touching" in render(full, "markdown")
    assert "<h2>Top statements" in render(full, "html")
    # empty (collected, none relevant) → section present with a 'none' note.
    empty = PerfReport(findings=base.findings, rls_tables_considered=1, statements=())
    assert "none reference" in render(empty, "text").lower()


def _run_perf_statements(*, schema, stats, stmts):
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock()
    cm.__exit__.return_value = False
    with patch("pgrls.cli.psycopg.connect", return_value=cm), patch(
        "pgrls.cli.introspect", return_value=schema
    ), patch("pgrls.cli.collect_table_stats", return_value=stats), patch(
        "pgrls.cli._perf003_flagged_tables", return_value=set()
    ), patch("pgrls.cli.collect_statements", return_value=stmts):
        return CliRunner().invoke(
            main,
            ["perf", "--database-url", "postgresql://x", "--statements", "--format", "json"],
        )


def test_cli_perf_statements_enriches_when_available() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _big("posts")}
    stmts = [_stmt("SELECT * FROM public.posts", total_ms=500, calls=7, tables={("public", "posts")})]
    res = _run_perf_statements(schema=schema, stats=stats, stmts=stmts)
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["statements"][0]["calls"] == 7


def test_cli_perf_statements_degrades_when_absent() -> None:
    schema = Schema(tables=(_table("posts", rls=True),))
    stats = {("public", "posts"): _big("posts")}
    # collect_statements returns None (extension absent) → note on stderr, no
    # statements section. (CliRunner mixes the stderr note into output, so
    # assert on substrings rather than json.loads the whole thing.)
    res = _run_perf_statements(schema=schema, stats=stats, stmts=None)
    assert res.exit_code == 0, res.output
    assert "pg_stat_statements is unavailable" in res.output
    assert '"statements"' not in res.output  # JSON report omits the key


def test_cli_perf_statements_no_section_without_findings() -> None:
    # --statements with stmts available but NO pressured tables: nothing to
    # attribute, so the section is omitted (keeps every format consistent —
    # text would otherwise diverge by early-returning before the section).
    schema = Schema(tables=(_table("posts", rls=True),))
    small = {("public", "posts"): _stats("public", "posts", seq_scan=1, seq_tup_read=1, idx_scan=0, n_live_tup=1)}
    stmts = [_stmt("SELECT * FROM public.posts", total_ms=500, calls=7, tables={("public", "posts")})]
    res = _run_perf_statements(schema=schema, stats=small, stmts=stmts)
    assert res.exit_code == 0, res.output
    assert '"statements"' not in res.output


def test_under_seq_scan_pressure_gates_on_raw_fraction() -> None:
    # Regression (round-5): the gate must compare the RAW seq-scan fraction,
    # not the 1-dp display value. 4996/10000 = 49.96% rounds to 50.0 and
    # would clear a min_seq_pct=50.0 gate it is actually below.
    thresholds = PerfThresholds(
        min_live_tup=1, min_seq_scans=1, min_seq_pct=50.0
    )
    just_below = _stats(
        "public", "t", seq_scan=4996, seq_tup_read=0, idx_scan=5004,
        n_live_tup=10000,
    )
    assert just_below.seq_scan_pct == 50.0  # rounded display value
    assert under_seq_scan_pressure(just_below, thresholds) is False  # raw 49.96
    at_threshold = _stats(
        "public", "t", seq_scan=5000, seq_tup_read=0, idx_scan=5000,
        n_live_tup=10000,
    )
    assert under_seq_scan_pressure(at_threshold, thresholds) is True
