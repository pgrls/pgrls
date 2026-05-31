"""Runtime PERF — observed sequential scans on RLS-protected tables.

PERF003 and PERF004 reason *statically*: they read the schema and infer
"this RLS predicate column has no usable index, so the planner *will*
sequential-scan." That's a prediction. This module reads what the
database actually did — Postgres's cumulative per-table statistics in
``pg_stat_user_tables`` (``seq_scan``, ``seq_tup_read``, ``idx_scan``,
``n_live_tup``) — and surfaces RLS-enabled tables that are *observed* to
be sequentially scanned in production.

Two things make the observed view worth having on top of the static one:

* It **confirms** a static prediction. A table PERF003 flagged (no index
  for the predicate) that is *also* seq-scanning heavily is a
  high-confidence missing-index candidate, not a maybe.
* It **catches what static analysis can't**. A table PERF003 thought was
  fine (an index exists) that *still* seq-scans heavily means the planner
  isn't using that index — poor selectivity, stale statistics, or a
  predicate shape the index doesn't serve. No amount of schema reading
  finds that; only the runtime counters do.

**Honest scope.** ``pg_stat_user_tables`` counts *every* sequential scan
on a table, not only the ones an RLS policy predicate drove. A reporting
query that legitimately full-scans inflates the same counter. So this is
a *prioritisation* signal — "these RLS tables are doing real sequential
work, look here first" — not proof that RLS is the cause. Attributing a
scan to a specific statement needs ``pg_stat_statements`` (a later
release). ``n_live_tup`` is the planner's estimate from the last
ANALYZE/autovacuum, so run against a database whose statistics are warm
(reset, exercise the workload, ANALYZE, then measure).
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime

import psycopg
from psycopg.rows import dict_row

from pgrls._html_common import resolve_generated_at, to_iso_z
from pgrls.model import Schema

__all__ = [
    "CONFIRMED",
    "INDEX_UNUSED",
    "PERF_FORMATS",
    "PerfFinding",
    "PerfReport",
    "PerfThresholds",
    "TableStats",
    "build_perf_report",
    "collect_table_stats",
    "render",
]

# Classification of a runtime seq-scan finding, by what the static
# analysis said about the same table.
CONFIRMED = "confirmed"  # PERF003 flagged it (no usable index) AND it seq-scans
INDEX_UNUSED = "index-unused"  # PERF003 saw an index, but it seq-scans anyway


@dataclass(frozen=True)
class TableStats:
    """Point-in-time cumulative statistics for one table.

    Pulled from ``pg_stat_user_tables``. Counters are monotonic since the
    last ``pg_stat_reset()`` (or database start); ``n_live_tup`` is the
    planner's row estimate, not an exact count.
    """

    schema: str
    table: str
    seq_scan: int
    seq_tup_read: int
    idx_scan: int
    n_live_tup: int

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.table}"

    @property
    def total_scans(self) -> int:
        return self.seq_scan + self.idx_scan

    @property
    def seq_scan_pct(self) -> float:
        """Share of scans that were sequential (0.0 when never scanned)."""
        total = self.total_scans
        return 0.0 if total == 0 else round(100.0 * self.seq_scan / total, 1)

    @property
    def avg_seq_rows(self) -> float:
        """Mean rows read per sequential scan (0.0 when never seq-scanned)."""
        return 0.0 if self.seq_scan == 0 else round(
            self.seq_tup_read / self.seq_scan, 1
        )


_STATS_SQL = """
SELECT
    schemaname AS schema_name,
    relname AS table_name,
    seq_scan,
    seq_tup_read,
    COALESCE(idx_scan, 0) AS idx_scan,
    COALESCE(n_live_tup, 0) AS n_live_tup
FROM pg_catalog.pg_stat_user_tables
WHERE schemaname = ANY(%s)
"""


def collect_table_stats(
    conn: psycopg.Connection, schemas: list[str]
) -> dict[tuple[str, str], TableStats]:
    """Read ``pg_stat_user_tables`` counters for tables in ``schemas``.

    Returns a ``{(schema, table): TableStats}`` map. Counters that
    Postgres can report as NULL (``idx_scan``, ``n_live_tup`` before any
    activity) are coalesced to 0 so callers never see ``None``.
    """
    out: dict[tuple[str, str], TableStats] = {}
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(_STATS_SQL, (schemas,))
        for row in cur.fetchall():
            ts = TableStats(
                schema=row["schema_name"],
                table=row["table_name"],
                seq_scan=row["seq_scan"],
                seq_tup_read=row["seq_tup_read"],
                idx_scan=row["idx_scan"],
                n_live_tup=row["n_live_tup"],
            )
            out[(ts.schema, ts.table)] = ts
    return out


@dataclass(frozen=True)
class PerfThresholds:
    """When an observed seq-scan is signal, not noise.

    All three gates must pass for a table to become a finding. The
    defaults are deliberately conservative — a false positive (telling an
    operator to add an index that wouldn't help) erodes trust faster than
    a missed one.
    """

    # Below this estimated row count, a sequential scan is cheap and often
    # the plan the planner *should* pick; flagging it would be noise.
    min_live_tup: int = 10_000
    # A handful of sequential scans (startup, a migration, an ad-hoc
    # query) isn't a pattern. Require enough to be a steady-state cost.
    min_seq_scans: int = 50
    # The table must do most of its scanning sequentially; a table that is
    # overwhelmingly index-scanned with a few seq scans is healthy.
    min_seq_pct: float = 50.0


@dataclass(frozen=True)
class PerfFinding:
    """One RLS-enabled table observed to be sequentially scanned."""

    stats: TableStats
    classification: str  # CONFIRMED | INDEX_UNUSED
    severity: str  # "warning" (confirmed) | "info" (index-unused)

    @property
    def location(self) -> str:
        return self.stats.qualified_name


@dataclass(frozen=True)
class PerfReport:
    findings: tuple[PerfFinding, ...]
    # How many RLS-enabled tables had stats and were evaluated against the
    # thresholds (the denominator for "N of M RLS tables").
    rls_tables_considered: int
    thresholds: PerfThresholds = field(default_factory=PerfThresholds)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "rls_tables": self.rls_tables_considered,
            "findings": len(self.findings),
            "confirmed": sum(
                1 for f in self.findings if f.classification == CONFIRMED
            ),
            "index_unused": sum(
                1 for f in self.findings if f.classification == INDEX_UNUSED
            ),
        }


def build_perf_report(
    schema: Schema,
    stats: dict[tuple[str, str], TableStats],
    *,
    statically_flagged: set[tuple[str, str]],
    thresholds: PerfThresholds | None = None,
) -> PerfReport:
    """Cross-reference runtime stats against RLS-enabled tables.

    A finding is an RLS-enabled table whose stats clear every gate in
    ``thresholds``. Its classification depends on whether PERF003
    statically flagged it (``statically_flagged`` is the set of
    ``(schema, table)`` PERF003 reported, computed by the caller so this
    function stays free of the rule registry): a flagged table that
    seq-scans is ``CONFIRMED`` (warning — a missing index the planner
    wants), an unflagged one is ``INDEX_UNUSED`` (info — an index exists
    but isn't being used). Findings are ranked by ``seq_tup_read``
    (descending) — total rows read sequentially is the real cost.
    """
    # Partitioned tables are a known blind spot: a partitioned *parent*
    # carries the RLS flag but accumulates ~no direct scan counters (queries
    # are planned against the children), while the *children* hold the real
    # counters but don't inherit the parent's ``relrowsecurity`` — so they
    # read as non-RLS here and are skipped. The effect is a possible false
    # negative (a partitioned RLS table's scans go unsurfaced), never a false
    # positive. Per-partition stat aggregation is a planned enhancement.
    thresholds = thresholds or PerfThresholds()
    findings: list[PerfFinding] = []
    considered = 0
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        if not table.rls_enabled:
            continue
        ts = stats.get((table.schema, table.name))
        if ts is None:
            # No stats row (table never seen by the stats collector, or
            # outside the scanned schemas) — nothing observed to judge.
            continue
        considered += 1
        if ts.n_live_tup < thresholds.min_live_tup:
            continue
        if ts.seq_scan < thresholds.min_seq_scans:
            continue
        if ts.seq_scan_pct < thresholds.min_seq_pct:
            continue
        flagged = (table.schema, table.name) in statically_flagged
        findings.append(
            PerfFinding(
                stats=ts,
                classification=CONFIRMED if flagged else INDEX_UNUSED,
                severity="warning" if flagged else "info",
            )
        )
    findings.sort(key=lambda f: f.stats.seq_tup_read, reverse=True)
    return PerfReport(
        findings=tuple(findings),
        rls_tables_considered=considered,
        thresholds=thresholds,
    )


_VERDICT_LABEL = {
    CONFIRMED: "confirmed (no index)",
    INDEX_UNUSED: "index unused",
}

_CAVEAT = (
    "Note: pg_stat_user_tables counts all sequential scans on a table, "
    "not only RLS-driven ones — treat these as tables to investigate "
    "first, ranked by rows read sequentially."
)


def _summary_line(report: PerfReport) -> str:
    s = report.summary
    n = s["findings"]
    noun = "table" if n == 1 else "tables"
    return (
        f"{n} of {s['rls_tables']} RLS {('table' if s['rls_tables'] == 1 else 'tables')} "
        f"under seq-scan pressure ({noun}: {s['confirmed']} confirmed, "
        f"{s['index_unused']} index-unused)."
    )


def render_text(report: PerfReport) -> str:
    if not report.findings:
        if report.rls_tables_considered == 0:
            return (
                "No RLS-enabled tables with statistics in the scanned "
                "schemas."
            )
        return (
            f"No seq-scan pressure on {report.rls_tables_considered} "
            "RLS-enabled table(s) (above the configured thresholds)."
        )
    rows = [
        (
            f.stats.qualified_name,
            f"{f.stats.n_live_tup:,}",
            f"{f.stats.seq_scan:,}",
            f"{f.stats.seq_tup_read:,}",
            f"{f.stats.seq_scan_pct}%",
            _VERDICT_LABEL[f.classification],
        )
        for f in report.findings
    ]
    headers = ("TABLE", "ROWS", "SEQ SCANS", "SEQ ROWS READ", "SEQ %", "VERDICT")
    widths = [
        max(len(headers[i]), max(len(r[i]) for r in rows))
        for i in range(len(headers))
    ]
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    out = [line]
    for r in rows:
        out.append("  ".join(r[i].ljust(widths[i]) for i in range(len(r))))
    out.append("")
    out.append(_summary_line(report))
    out.append(_CAVEAT)
    return "\n".join(out)


def render_json(report: PerfReport) -> str:
    payload = {
        "summary": report.summary,
        "thresholds": {
            "min_live_tup": report.thresholds.min_live_tup,
            "min_seq_scans": report.thresholds.min_seq_scans,
            "min_seq_pct": report.thresholds.min_seq_pct,
        },
        "findings": [
            {
                "table": f.stats.qualified_name,
                "schema": f.stats.schema,
                "name": f.stats.table,
                "classification": f.classification,
                "severity": f.severity,
                "n_live_tup": f.stats.n_live_tup,
                "seq_scan": f.stats.seq_scan,
                "seq_tup_read": f.stats.seq_tup_read,
                "idx_scan": f.stats.idx_scan,
                "seq_scan_pct": f.stats.seq_scan_pct,
                "avg_seq_rows": f.stats.avg_seq_rows,
            }
            for f in report.findings
        ],
    }
    return json.dumps(payload, indent=2)


def render_markdown(report: PerfReport) -> str:
    out = [
        "# Runtime RLS seq-scan report",
        "",
        _summary_line(report),
        "",
        f"_{_CAVEAT}_",
        "",
        "| Table | Rows | Seq scans | Seq rows read | Seq % | Verdict |",
        "|---|--:|--:|--:|--:|---|",
    ]
    for f in report.findings:
        out.append(
            f"| `{f.stats.qualified_name}` | {f.stats.n_live_tup:,} | "
            f"{f.stats.seq_scan:,} | {f.stats.seq_tup_read:,} | "
            f"{f.stats.seq_scan_pct}% | {_VERDICT_LABEL[f.classification]} |"
        )
    return "\n".join(out) + "\n"


def render_html(
    report: PerfReport,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Standalone HTML seq-scan report.

    Every user-influenced cell is ``html.escape``-d (Postgres identifiers
    can legally contain markup characters). ``generated_at`` must be
    timezone-aware (see ``pgrls._html_common``).
    """
    generated_at = resolve_generated_at(generated_at, caller_name="render_html")
    now = to_iso_z(generated_at)

    if not report.findings:
        empty = (
            "No RLS-enabled tables with statistics in the scanned schemas."
            if report.rls_tables_considered == 0
            else (
                f"No seq-scan pressure on {report.rls_tables_considered} "
                "RLS-enabled table(s) above the configured thresholds."
            )
        )
        rows_html = (
            f'<tr><td colspan="6" class="empty">{html.escape(empty)}</td></tr>'
        )
    else:
        row_lines: list[str] = []
        for f in report.findings:
            state = f.classification
            row_lines.append(
                f'      <tr class="row-{state}">'
                f"<td><code>{html.escape(f.stats.qualified_name)}</code></td>"
                f'<td class="num">{f.stats.n_live_tup:,}</td>'
                f'<td class="num">{f.stats.seq_scan:,}</td>'
                f'<td class="num">{f.stats.seq_tup_read:,}</td>'
                f'<td class="num">{f.stats.seq_scan_pct}%</td>'
                f'<td><span class="pill status-{state}">'
                f"{html.escape(_VERDICT_LABEL[f.classification])}</span></td>"
                "</tr>"
            )
        rows_html = "\n".join(row_lines)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>pgrls runtime RLS seq-scan report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI",
         Roboto, "Helvetica Neue", Arial, sans-serif;
         margin: 2rem auto; max-width: 64rem; padding: 0 1rem;
         color: #1f2328; background: #ffffff; }}
  @media (prefers-color-scheme: dark) {{
    body {{ color: #e6edf3; background: #0d1117; }}
    table {{ border-color: #30363d; }}
    th {{ background: #161b22; }}
    tr:nth-child(even) td {{ background: #0d1117; }}
    tr:nth-child(odd) td {{ background: #161b22; }}
    code {{ background: #161b22; }}
  }}
  header {{ margin-bottom: 1.5rem; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem 0; }}
  .meta {{ color: #57606a; font-size: .85rem; }}
  .summary {{ margin: 1rem 0 .5rem; }}
  .caveat {{ color: #57606a; font-size: .85rem; margin: .25rem 0 1rem; }}
  .pill {{ display: inline-block; padding: .15rem .55rem;
           border-radius: 999px; font-size: .85rem;
           border: 1px solid currentColor; }}
  .status-confirmed    {{ color: #cf222e; }}
  .status-index-unused {{ color: #9a6700; }}
  table {{ width: 100%; border-collapse: collapse;
           border: 1px solid #d0d7de; }}
  thead th {{ text-align: left; padding: .5rem .75rem;
              background: #f6f8fa; border-bottom: 1px solid #d0d7de;
              font-weight: 600; }}
  tbody td {{ padding: .5rem .75rem; border-bottom: 1px solid #d0d7de; }}
  tbody tr:last-child td {{ border-bottom: 0; }}
  td.num {{ font-variant-numeric: tabular-nums; text-align: right; }}
  code {{ background: #f6f8fa; padding: .1rem .35rem;
          border-radius: 4px; font: .9em ui-monospace, Menlo, monospace; }}
  .empty {{ text-align: center; color: #57606a; padding: 1.5rem; }}
  footer {{ margin-top: 2rem; color: #57606a; font-size: .8rem; }}
</style>
</head>
<body>
  <header>
    <h1>Runtime RLS seq-scan report</h1>
    <p class="meta">Generated by <code>pgrls perf --format html</code> · {html.escape(now)}</p>
    <p class="summary">{html.escape(_summary_line(report))}</p>
    <p class="caveat">{html.escape(_CAVEAT)}</p>
  </header>
  <table>
    <thead>
      <tr>
        <th>Table</th>
        <th>Rows</th>
        <th>Seq scans</th>
        <th>Seq rows read</th>
        <th>Seq %</th>
        <th>Verdict</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
  <footer>pgrls — Postgres Row-Level Security linter · <a href="https://github.com/pgrls/pgrls">github.com/pgrls/pgrls</a></footer>
</body>
</html>
"""


_RENDERERS = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
}
PERF_FORMATS = tuple(_RENDERERS)


def render(report: PerfReport, output_format: str) -> str:
    return _RENDERERS[output_format](report)
