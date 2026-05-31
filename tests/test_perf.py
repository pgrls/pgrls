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
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pgrls.cli import main
from pgrls.model import Policy, Schema, Table
from pgrls.perf import (
    CONFIRMED,
    INDEX_UNUSED,
    PERF_FORMATS,
    PerfFinding,
    PerfReport,
    PerfThresholds,
    TableStats,
    build_perf_report,
    render,
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
    for flag in ("--min-rows", "--min-seq-scans", "--min-seq-pct", "--fail-on-findings"):
        assert flag in res.output
