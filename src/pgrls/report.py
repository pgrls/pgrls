"""Per-table RLS posture report for `pgrls report`.

`pgrls lint` answers "what's *wrong*?"; `pgrls report` answers "what's
the RLS posture *overall*?" — a factual, rule-free snapshot of every
table's row-level-security state, for audits and onboarding. It runs no
rules and emits no findings; it summarizes `relrowsecurity`,
`relforcerowsecurity`, and policy counts as introspected.

Each table gets a coarse `status` derived from those facts (plus
declarative-partition ancestry — see ``covered-by-parent``), in
precedence order:

* ``covered-by-parent`` — RLS not enabled on this table, but it is a
  declarative-partition child of a table that *does* have RLS. Postgres
  does not propagate ``relrowsecurity`` to children, but queries routed
  through the parent apply the parent's policies, so the child is
  covered. (This is credited only when an RLS-enabled ancestor is among
  the *scanned* schemas; if the partition chain leaves the scanned set,
  coverage can't be confirmed and the child shows ``rls-off`` — note
  SEC001 instead fires a distinct "cannot verify" finding there, so the
  two aren't identical for that edge.) Direct queries against the child
  still bypass the parent's policies — a documented caveat.
* ``rls-off``      — RLS not enabled and no RLS-enabled ancestor (the
  table is wide open to anyone with table privileges; if it also has
  policies they are dormant).
* ``no-policies``  — RLS on but no *permissive* policy: Postgres
  default-denies, so the table is locked to non-owners. Covers both a
  table with zero policies and one with only RESTRICTIVE policies
  (which AND-combine and grant nothing on their own).
* ``not-forced``   — RLS on with a permissive policy, but not ``FORCE``d,
  so the table owner bypasses every policy.
* ``protected``    — RLS on, ``FORCE``d, and at least one *permissive*
  policy.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime

from pgrls._html_common import html_page, resolve_generated_at, to_iso_z
from pgrls._render_common import (
    make_dispatcher,
    markdown_table,
    pluralize,
    render_text_table,
)
from pgrls.model import Schema

_REPORT_CSS = """    tr:nth-child(even) td { background: #0d1117; }
    tr:nth-child(odd) td { background: #161b22; }
    code { background: #161b22; }
  }
  header { margin-bottom: 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem 0; }
  .meta { color: #57606a; font-size: .85rem; }
  .summary { margin: 1rem 0 .5rem; }
  .pills { display: flex; flex-wrap: wrap; gap: .5rem;
            margin: 0 0 1.5rem 0; }
  .pill { display: inline-block; padding: .15rem .55rem;
           border-radius: 999px; font-size: .85rem;
           border: 1px solid currentColor; }
  .status-protected         { color: #1a7f37; }
  .status-not-forced        { color: #9a6700; }
  .status-no-policies       { color: #57606a; }
  .status-covered-by-parent { color: #0969da; }
  .status-rls-off           { color: #cf222e; }
  .status-empty             { color: #57606a; }
  table { width: 100%; border-collapse: collapse;
           border: 1px solid #d0d7de; }
  thead th { text-align: left; padding: .5rem .75rem;
              background: #f6f8fa; border-bottom: 1px solid #d0d7de;
              font-weight: 600; }
  tbody td { padding: .5rem .75rem; border-bottom: 1px solid #d0d7de; }
  tbody tr:last-child td { border-bottom: 0; }
  td.num { font-variant-numeric: tabular-nums; }
  code { background: #f6f8fa; padding: .1rem .35rem;
          border-radius: 4px; font: .9em ui-monospace, Menlo, monospace; }"""

# Ordered best → worst, which is also the order the summary line lists
# non-zero counts. (The `status` property's precedence is independent of
# this tuple; this only drives summary display and the count keys.)
STATUSES = (
    "protected",
    "not-forced",
    "no-policies",
    "covered-by-parent",
    "rls-off",
)

_STATUS_LABELS = {
    "protected": "protected",
    "not-forced": "not forced",
    "no-policies": "no policies",
    "covered-by-parent": "covered by parent",
    "rls-off": "RLS off",
}


def _status_key(status: str) -> str:
    return f"status_{status.replace('-', '_')}"


@dataclass(frozen=True)
class TablePosture:
    qualified_name: str
    rls_enabled: bool
    force_rls: bool
    policy_count: int
    permissive_count: int
    restrictive_count: int
    # True when this table is a partition child whose ancestor chain
    # reaches a table with RLS enabled — it is covered via the parent
    # even though its own `relrowsecurity` is false.
    covered_by_ancestor: bool = False

    @property
    def status(self) -> str:
        if not self.rls_enabled:
            return "covered-by-parent" if self.covered_by_ancestor else "rls-off"
        # Visibility is granted only by PERMISSIVE policies; with none,
        # Postgres default-denies every row to non-owners — whether the
        # table has zero policies or only RESTRICTIVE ones (which
        # AND-combine and grant nothing on their own). Both are the same
        # "no permissive policy → deny-all" posture, so a restrictive-only
        # table is NOT reported as the green `protected`.
        if self.permissive_count == 0:
            return "no-policies"
        if not self.force_rls:
            return "not-forced"
        return "protected"


@dataclass(frozen=True)
class Report:
    tables: tuple[TablePosture, ...]

    @property
    def summary(self) -> dict[str, int]:
        counts = {s: 0 for s in STATUSES}
        for t in self.tables:
            counts[t.status] += 1
        return {
            "tables": len(self.tables),
            "rls_enabled": sum(1 for t in self.tables if t.rls_enabled),
            "forced": sum(1 for t in self.tables if t.force_rls),
            "with_policies": sum(
                1 for t in self.tables if t.policy_count > 0
            ),
            **{_status_key(s): counts[s] for s in STATUSES},
        }


def build_report(schema: Schema) -> Report:
    """Build the posture report from an introspected `schema`.

    Tables are sorted by qualified name so the output is deterministic.
    A partition child whose ancestor chain reaches an RLS-enabled table
    is marked `covered_by_ancestor` (same coverage logic SEC001 uses to
    skip such children).
    """
    postures = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        permissive = sum(1 for p in table.policies if p.permissive)
        restrictive = len(table.policies) - permissive
        covered = any(
            ancestor.rls_enabled for ancestor in schema.ancestors_of(table)
        )
        postures.append(
            TablePosture(
                qualified_name=table.qualified_name,
                rls_enabled=table.rls_enabled,
                force_rls=table.force_rls,
                policy_count=len(table.policies),
                permissive_count=permissive,
                restrictive_count=restrictive,
                covered_by_ancestor=covered,
            )
        )
    return Report(tables=tuple(postures))


def _summary_line(report: Report) -> str:
    """`N table(s): X protected, Y not forced, …` — non-zero statuses
    only, pluralized, in STATUSES order."""
    n = len(report.tables)
    noun = pluralize(n, "table")
    s = report.summary
    parts = [
        f"{s[_status_key(st)]} {_STATUS_LABELS[st]}"
        for st in STATUSES
        if s[_status_key(st)]
    ]
    detail = ", ".join(parts) if parts else "none"
    return f"{n} {noun}: {detail}."


def render_text(report: Report) -> str:
    """Human-readable aligned table + a summary line."""
    if not report.tables:
        return "No tables found in the scanned schemas."
    rows = [
        (
            t.qualified_name,
            t.status,
            "yes" if t.rls_enabled else "no",
            "yes" if t.force_rls else "no",
            str(t.policy_count),
        )
        for t in report.tables
    ]
    headers = ("TABLE", "STATUS", "RLS", "FORCE", "POLICIES")
    out = render_text_table(headers, rows)
    out.append("")
    out.append(_summary_line(report))
    return "\n".join(out)


def render_json(report: Report) -> str:
    """Stable machine-readable shape: {summary, tables[]}."""
    payload = {
        "summary": report.summary,
        "tables": [
            {
                "table": t.qualified_name,
                "status": t.status,
                "rls_enabled": t.rls_enabled,
                "force_rls": t.force_rls,
                "policies": t.policy_count,
                "permissive": t.permissive_count,
                "restrictive": t.restrictive_count,
            }
            for t in report.tables
        ],
    }
    return json.dumps(payload, indent=2)


def render_markdown(report: Report) -> str:
    """Markdown table + summary, paste-ready for an audit doc / PR."""
    return markdown_table(
        heading="# RLS posture",
        summary=_summary_line(report),
        header_row="| Table | Status | RLS | FORCE | Policies |",
        separator_row="|---|---|---|---|---|",
        body_rows=[
            f"| {t.qualified_name} | {t.status} | "
            f"{'yes' if t.rls_enabled else 'no'} | "
            f"{'yes' if t.force_rls else 'no'} | {t.policy_count} |"
            for t in report.tables
        ],
    )


def render_html(
    report: Report,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Standalone HTML audit page — no external dependencies.

    Designed for the "archive this for the auditor" reading context:
    one file, embedded CSS, prints cleanly, opens offline. Each
    table appears as one row in a sortable layout (sort is visual —
    rows are pre-sorted by status precedence then qualified name —
    so we avoid the JS dependency a click-to-sort would need).
    Status renders as a coloured pill matching the text formatter's
    word list (`protected` / `not forced` / `no policies` /
    `covered by parent` / `RLS off`).

    Every cell value is `html.escape`-d — Postgres identifiers can
    contain `<` / `>` / `&` / `"` legally inside quoted-identifier
    syntax, so a name like ``weird<name>&"`` must not break the
    layout or inject markup. `html.escape` keeps `'` as a literal
    (cheap, no XSS risk here — user-influenced values appear inside
    `<code>` text and inside `class="row-{status}"` where `status`
    is from the closed `STATUSES` enum, never inside single-quoted
    attributes that an apostrophe could escape).

    `generated_at` is optional and defaults to `datetime.now(utc)` —
    pass an explicit value for deterministic snapshot tests, or to
    reflect the time of an earlier introspection (e.g. when the
    HTML is rendered offline from a cached `Report`). It MUST be
    timezone-aware; a naive `datetime` (no `tzinfo`) raises
    `ValueError` rather than silently being coerced through the
    host's local timezone — that would produce wrong audit
    timestamps depending on which CI runner generated the report,
    exactly the failure mode the explicit `Z`-suffix protocol is
    meant to prevent. The renderer drops sub-second precision and
    serialises non-UTC zones to UTC.

    `render_html` is the only renderer with a kwarg because it's
    the only format that embeds a generation timestamp — the text /
    json / markdown formats are timestamp-free (a consumer that
    needs a snapshot time pairs them with their own metadata). No
    need to thread `generated_at` through the other `render_*`
    functions for parity.

    The shape is deliberately conservative: a single self-contained
    `<style>` block (no inline styles per element), semantic
    `<table>` / `<thead>` / `<tbody>`, and a `<header>` summary
    band. The output passes a strict HTML5 validator and renders
    identically across browsers and `wkhtmltopdf`-style PDF
    converters (so an auditor can print/PDF it without running
    pgrls themselves).
    """
    generated_at = resolve_generated_at(generated_at, caller_name="render_html")
    now = to_iso_z(generated_at)
    s = report.summary

    # Status-pill chips for the top band.
    status_chips: list[str] = []
    for st in STATUSES:
        n = s[_status_key(st)]
        if n:
            label = html.escape(_STATUS_LABELS[st])
            status_chips.append(
                f'<span class="pill status-{st}">'
                f'<strong>{n}</strong>&nbsp;{label}'
                f'</span>'
            )
    chips_html = "\n      ".join(status_chips) if status_chips else (
        '<span class="pill status-empty">no tables</span>'
    )

    # Table rows.
    if not report.tables:
        rows_html = (
            '<tr><td colspan="5" class="empty">'
            "No tables found in the scanned schemas."
            "</td></tr>"
        )
    else:
        row_lines: list[str] = []
        for t in report.tables:
            qn = html.escape(t.qualified_name)
            status = t.status
            status_label = html.escape(_STATUS_LABELS[status])
            row_lines.append(
                f'      <tr class="row-{status}">'
                f"<td><code>{qn}</code></td>"
                f'<td><span class="pill status-{status}">'
                f"{status_label}</span></td>"
                f'<td class="num">{"yes" if t.rls_enabled else "no"}</td>'
                f'<td class="num">{"yes" if t.force_rls else "no"}</td>'
                f'<td class="num">{t.policy_count}</td>'
                "</tr>"
            )
        rows_html = "\n".join(row_lines)

    total = s["tables"]
    noun = pluralize(total, "table")

    body = f"""  <table>
    <thead>
      <tr>
        <th>Table</th>
        <th>Status</th>
        <th>RLS</th>
        <th>FORCE</th>
        <th>Policies</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>"""

    header_extra = (
        f'    <p class="summary"><strong>{total}</strong> {noun} scanned.</p>\n'
        '    <div class="pills">\n'
        f"      {chips_html}\n"
        "    </div>"
    )

    return html_page(
        title="pgrls RLS posture report",
        heading="RLS posture report",
        command="pgrls report --format html",
        generated_at_iso=html.escape(now),
        extra_css=_REPORT_CSS,
        header_extra=header_extra,
        body=body,
    )


render, REPORT_FORMATS = make_dispatcher({
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
})
