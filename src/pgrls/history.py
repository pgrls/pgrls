"""Trend analysis across a directory of `pgrls lint --format json` snapshots.

`pgrls history <dir>` consumes a directory of JSON files written by
`pgrls lint --format json` and emits a chronological trend: per-snapshot
totals by severity, plus the *delta* between consecutive snapshots —
which findings are NEW, which were FIXED. Designed for the question a
team asks after running pgrls on a long-lived database: "are we
gaining ground, or is the findings count creeping up?"

### Snapshot identity

The snapshot's timestamp is the JSON file's mtime — same approach
`pgrls diff` uses for snapshot ordering. Filename is preserved in the
output so the operator can correlate a row back to a build / CI run.
Files that don't parse as the pgrls JSON shape (a stray README, an
unrelated `*.json`) are skipped with a stderr warning rather than
failing the command — a `pgrls history snapshots/` over a slightly
contaminated directory still produces a useful report.

### Finding identity

A finding is keyed by `(rule_id, location)`. Two snapshots' findings
compare equal when both tuples match. `location` is `None` for a
schema-wide finding (e.g. SEC016, role-attribute scope); the pair
`(rule_id, None)` is a stable identity in its own right, so a SEC016
finding that persists across snapshots is correctly classified
PERSISTENT rather than NEW + FIXED on every comparison.

A snapshot may contain duplicate `(rule_id, location)` pairs (the
rule fires multiple times against the same target — rare but
possible for some rule shapes). Counts collapse to set semantics
for the new/fixed delta — the multiset distinction isn't useful at
trend granularity. The per-snapshot total still reflects raw
findings count.

### Output

Three formats:

* **text** — fixed-width aligned table for terminal reading; one row
  per snapshot with totals + delta. A trailing summary line names
  the net change over the full series.
* **json** — `{snapshots: [...], summary: {...}}` — machine-readable
  for downstream visualization (e.g. plotting a trend line). Stable
  shape, indented.
* **markdown** — GitHub-flavored Markdown table, paste-ready for a
  weekly engineering update or a PR comment.

### Why mtime, not a `generated_at` field

The JSON formatter's stable contract today carries findings and
summary counts but no timestamp. Adding one would be additive and
backward-compatible (consumers ignore unknown keys), but it would
force every `--format json` consumer to think about clock skew
between the linter host and CI runner clocks — a worse failure mode
than the operator already knows their snapshot directory's mtime
provenance. If `pgrls history` later grows a richer time-series
(per-rule trends, regression alerts) and needs a built-in
timestamp, the `generated_at` field is the right next step; for the
v0.6.10 baseline, mtime is enough.
"""
from __future__ import annotations

import html
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pgrls._html_common import html_page, resolve_generated_at, to_iso_z
from pgrls._render_common import make_dispatcher, pluralize, render_text_table
from pgrls.formatters._common import gfm_inline_code, safe_location

_HISTORY_CSS = """    tr td { background: #0d1117; }
    tr:nth-child(even) td { background: #161b22; }
    code { background: #161b22; }
  }
  header { margin-bottom: 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem 0; }
  .meta { color: #57606a; font-size: .85rem; }
  .summary { margin: 1rem 0 1.5rem; font-size: 1rem; }
  .net-good { color: #1a7f37; font-weight: 600; }
  .net-bad  { color: #cf222e; font-weight: 600; }
  .net-flat { color: #57606a; font-weight: 600; }
  table { width: 100%; border-collapse: collapse;
           border: 1px solid #d0d7de; }
  thead th { text-align: left; padding: .5rem .75rem;
              background: #f6f8fa; border-bottom: 1px solid #d0d7de;
              font-weight: 600; white-space: nowrap; }
  thead th.num { text-align: right; }
  tbody td { padding: .5rem .75rem; border-bottom: 1px solid #d0d7de; }
  tbody tr:last-child td { border-bottom: 0; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.new { color: #cf222e; font-weight: 600; }
  td.fixed { color: #1a7f37; font-weight: 600; }
  code { background: #f6f8fa; padding: .1rem .35rem;
          border-radius: 4px; font: .9em ui-monospace, Menlo, monospace; }"""


@dataclass(frozen=True)
class FindingKey:
    """The (rule_id, location) tuple that identifies a finding across
    snapshots. `location` may be None for schema-wide findings."""
    rule_id: str
    location: str | None


@dataclass(frozen=True)
class Snapshot:
    """One JSON file's worth of pgrls findings, with mtime."""
    path: Path
    timestamp: datetime
    findings: frozenset[FindingKey]
    raw_total: int
    counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SnapshotRow:
    """One row in the rendered trend table — a snapshot plus the
    delta vs. the prior snapshot in chronological order."""
    snapshot: Snapshot
    new_count: int
    fixed_count: int


HistoryFormat = Literal["text", "json", "markdown", "html"]
# `HISTORY_FORMATS` and `render` are defined at the bottom of the module
# via `make_dispatcher`, sourced from the renderer map so the format list
# can't drift from the renderers it advertises.


def _read_snapshot(path: Path) -> Snapshot | None:
    """Parse one JSON snapshot file. Returns None for unparseable
    files (logged to stderr); the caller skips them."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"pgrls history: skipping {path.name}: {exc}",
            file=sys.stderr,
        )
        return None
    if not isinstance(payload, dict):
        print(
            f"pgrls history: skipping {path.name}: "
            "top-level JSON is not an object",
            file=sys.stderr,
        )
        return None
    violations = payload.get("violations")
    if not isinstance(violations, list):
        print(
            f"pgrls history: skipping {path.name}: "
            "missing or non-list 'violations' field",
            file=sys.stderr,
        )
        return None
    keys: set[FindingKey] = set()
    counts: dict[str, int] = {
        "error": 0, "warning": 0, "info": 0, "other": 0,
    }
    for v in violations:
        if not isinstance(v, dict):
            continue
        rule_id = v.get("rule_id")
        severity = v.get("severity")
        if not isinstance(rule_id, str):
            continue
        loc = v.get("location")
        loc_str = loc if (loc is None or isinstance(loc, str)) else None
        keys.add(FindingKey(rule_id=rule_id, location=loc_str))
        if isinstance(severity, str) and severity in ("error", "warning", "info"):
            counts[severity] += 1
        else:
            # Off-spec, missing, or non-string severity on an otherwise
            # well-formed finding (an external rule plugin may emit a
            # severity pgrls doesn't model). Bucket it under 'other' so
            # error+warning+info+other equals the well-formed finding
            # count (== raw_total when every entry parses) — without it
            # the three columns silently under-sum the total.
            counts["other"] += 1
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return Snapshot(
        path=path,
        timestamp=mtime,
        findings=frozenset(keys),
        raw_total=len(violations),
        counts=counts,
    )


def load_snapshots(directory: Path) -> list[Snapshot]:
    """Read every `*.json` file in `directory`, sort chronologically
    by mtime. Unparseable files are skipped with a stderr warning;
    the caller still gets a result for the readable ones."""
    if not directory.exists():
        raise FileNotFoundError(
            f"pgrls history: directory not found: {directory}"
        )
    if not directory.is_dir():
        raise NotADirectoryError(
            f"pgrls history: {directory} is not a directory"
        )
    snapshots: list[Snapshot] = []
    for path in sorted(directory.glob("*.json")):
        snap = _read_snapshot(path)
        if snap is not None:
            snapshots.append(snap)
    snapshots.sort(key=lambda s: s.timestamp)
    return snapshots


def build_rows(snapshots: Iterable[Snapshot]) -> list[SnapshotRow]:
    """Compute the (NEW, FIXED) delta between each snapshot and the
    one before it in chronological order. The first snapshot has
    `new_count = len(findings)` (every finding is "new" with no prior
    baseline) and `fixed_count = 0`."""
    rows: list[SnapshotRow] = []
    prior: frozenset[FindingKey] = frozenset()
    first = True
    for snap in snapshots:
        if first:
            new = len(snap.findings)
            fixed = 0
            first = False
        else:
            new = len(snap.findings - prior)
            fixed = len(prior - snap.findings)
        rows.append(SnapshotRow(snapshot=snap, new_count=new, fixed_count=fixed))
        prior = snap.findings
    return rows


def render_text(rows: list[SnapshotRow]) -> str:
    """Fixed-width aligned table for terminal reading.

    Columns: TIMESTAMP, FILE, TOTAL, ERROR, WARN, INFO, NEW, FIXED.
    Trailing summary line names the net change over the full series.
    """
    if not rows:
        return "No snapshots found.\n"
    # Only show the OTHER column when some snapshot actually has an
    # off-spec ('other') severity, so the common all-standard table is
    # not widened. When present it keeps ERROR+WARN+INFO+OTHER reconciled
    # to TOTAL — mirroring the JSON 'others' key — instead of the three
    # columns silently under-summing TOTAL.
    show_other = any(row.snapshot.counts.get("other", 0) for row in rows)
    headers = (
        "TIMESTAMP",
        "FILE",
        "TOTAL",
        "ERROR",
        "WARN",
        "INFO",
        *(("OTHER",) if show_other else ()),
        "NEW",
        "FIXED",
    )
    body = [
        (
            row.snapshot.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            # `safe_location` keeps the row single-line and the
            # fixed-width columns aligned: a snapshot filename can
            # legally carry a `\n` (POSIX allows any byte but `/`
            # and NUL), which would otherwise split the row. No-op
            # on a clean `a.json`; mirrors the lint/diff text
            # formatters.
            safe_location(row.snapshot.path.name),
            str(row.snapshot.raw_total),
            str(row.snapshot.counts.get("error", 0)),
            str(row.snapshot.counts.get("warning", 0)),
            str(row.snapshot.counts.get("info", 0)),
            *(
                (str(row.snapshot.counts.get("other", 0)),)
                if show_other
                else ()
            ),
            str(row.new_count) if row.new_count else "-",
            str(row.fixed_count) if row.fixed_count else "-",
        )
        for row in rows
    ]
    out = render_text_table(headers, body)
    out.append("")
    out.append(_summary_line(rows))
    return "\n".join(out) + "\n"


def render_json(rows: list[SnapshotRow]) -> str:
    """Machine-readable shape: `{snapshots: [...], summary: {...}}`.

    Each snapshot carries `timestamp`, `file`, `total`, severity
    counts, and the new/fixed delta. Stable across the same major-
    zero series; new keys are additive.
    """
    payload = {
        "snapshots": [
            {
                "timestamp": row.snapshot.timestamp.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "file": row.snapshot.path.name,
                "total": row.snapshot.raw_total,
                "errors": row.snapshot.counts.get("error", 0),
                "warnings": row.snapshot.counts.get("warning", 0),
                "infos": row.snapshot.counts.get("info", 0),
                # Off-spec / unmodeled severities, so errors + warnings
                # + infos + others reconciles to total.
                "others": row.snapshot.counts.get("other", 0),
                "new": row.new_count,
                "fixed": row.fixed_count,
            }
            for row in rows
        ],
        "summary": _summary_dict(rows),
    }
    # ensure_ascii=False so non-ASCII identifiers (quoted table/policy/
    # role names) stay readable instead of escaped to \uXXXX — matches
    # the lint/sarif/snapshot/explain JSON contract.
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_markdown(rows: list[SnapshotRow]) -> str:
    """GitHub-flavored Markdown table; paste-ready for a weekly
    engineering update or a PR comment."""
    if not rows:
        return "## pgrls history\n\nNo snapshots found.\n"
    # Only add the Other column when some snapshot has an off-spec
    # severity, so the common all-standard table is not widened (mirrors
    # render_text and the JSON 'others' key).
    show_other = any(row.snapshot.counts.get("other", 0) for row in rows)
    other_h = " Other |" if show_other else ""
    other_sep = "---:|" if show_other else ""
    out = [
        "## pgrls history",
        "",
        f"| Timestamp | File | Total | Error | Warn | Info |{other_h} New | Fixed |",
        f"|---|---|---:|---:|---:|---:|{other_sep}---:|---:|",
    ]
    for row in rows:
        # `safe_location` neutralizes newlines / zero-width chars (a
        # raw `\n` in a snapshot filename would end the GFM row
        # early), the `|` -> `\|` escape stops a pipe from splitting
        # the cell, and `gfm_inline_code` adds the backtick span
        # (widening the wrapper if the filename contains backticks).
        # All no-ops on a well-formed `a.json`, so existing output
        # is unchanged. Mirrors the lint/diff markdown location cell.
        fn = gfm_inline_code(
            safe_location(row.snapshot.path.name).replace("|", "\\|")
        )
        other_cell = (
            f" {row.snapshot.counts.get('other', 0)} |" if show_other else ""
        )
        out.append(
            "| {ts} | {fn} | {tot} | {err} | {warn} | {info} |{other} {new} | {fix} |".format(
                ts=row.snapshot.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                fn=fn,
                tot=row.snapshot.raw_total,
                err=row.snapshot.counts.get("error", 0),
                warn=row.snapshot.counts.get("warning", 0),
                info=row.snapshot.counts.get("info", 0),
                other=other_cell,
                new=row.new_count if row.new_count else "—",
                fix=row.fixed_count if row.fixed_count else "—",
            )
        )
    out.append("")
    out.append(f"**{_summary_line(rows)}**")
    return "\n".join(out) + "\n"


def _summary_dict(rows: list[SnapshotRow]) -> dict[str, int]:
    if not rows:
        return {
            "snapshots": 0,
            "first_total": 0,
            "last_total": 0,
            "net_change": 0,
            "total_new": 0,
            "total_fixed": 0,
        }
    first_total = rows[0].snapshot.raw_total
    last_total = rows[-1].snapshot.raw_total
    # NEW / FIXED across the full series — sum of per-snapshot
    # deltas (skipping the first snapshot's baseline "every finding
    # is new" count, which is bookkeeping noise, not new findings).
    total_new = sum(r.new_count for r in rows[1:])
    total_fixed = sum(r.fixed_count for r in rows[1:])
    return {
        "snapshots": len(rows),
        "first_total": first_total,
        "last_total": last_total,
        "net_change": last_total - first_total,
        "total_new": total_new,
        "total_fixed": total_fixed,
    }


def _summary_line(rows: list[SnapshotRow]) -> str:
    s = _summary_dict(rows)
    if s["snapshots"] == 0:
        return "No snapshots."
    if s["snapshots"] == 1:
        return (
            f"1 snapshot, {s['first_total']} "
            f"{pluralize(s['first_total'], 'finding')}."
        )
    delta = s["net_change"]
    direction = "+" if delta > 0 else ""
    return (
        f"{s['snapshots']} snapshots, net change {direction}{delta} "
        f"({s['first_total']} → {s['last_total']}); "
        f"{s['total_new']} new, {s['total_fixed']} fixed."
    )


def render_html(
    rows: list[SnapshotRow],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Standalone HTML trend page — no external dependencies.

    Mirrors `pgrls report --format html` for the same reading
    context: archive as the weekly engineering-review artefact,
    print to PDF for a quarterly compliance file, email to a
    stakeholder who doesn't run pgrls. Embedded CSS, no `<link>`
    / `<script>` — opens offline, renders identically in browsers
    and `wkhtmltopdf`-style PDF converters.

    Each snapshot renders as one row with severity totals + the
    NEW/FIXED delta vs. the prior snapshot. A summary band on top
    surfaces the net change over the series at a glance. The
    NEW / FIXED columns highlight by colour when non-zero
    (red for new, green for fixed) so the at-a-glance read of
    "are we gaining ground" doesn't require parsing the trailing
    summary sentence.

    `generated_at` is optional and defaults to `datetime.now(utc)`
    — same contract `report.render_html` exposes, including the
    naive-datetime rejection. Pass an explicit tz-aware datetime
    for deterministic snapshot tests, or to reflect the time of
    an earlier history-build (e.g. when the HTML is rendered
    offline from a cached series).

    Snapshot filenames are HTML-escaped — a directory contaminated
    with a filename containing `<` or `&` can't break the layout
    or inject markup. Same defence the report formatter applies
    to qualified identifiers.
    """
    generated_at = resolve_generated_at(generated_at, caller_name="render_html")
    now = to_iso_z(generated_at)

    summary = _summary_dict(rows)
    summary_sentence = html.escape(_summary_line(rows))

    # Only add the Other column when some snapshot has an off-spec
    # severity, so the common all-standard table is not widened (mirrors
    # render_text/markdown and the JSON 'others' key). An empty history
    # has no rows and thus no 'other', so the colspan stays 8.
    show_other = any(row.snapshot.counts.get("other", 0) for row in rows)
    other_th = '\n        <th class="num">Other</th>' if show_other else ""
    colspan = "9" if show_other else "8"

    if not rows:
        rows_html = (
            f'<tr><td colspan="{colspan}" class="empty">'
            "No snapshots found."
            "</td></tr>"
        )
    else:
        row_lines: list[str] = []
        for row in rows:
            snap = row.snapshot
            ts = snap.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
            fn = html.escape(snap.path.name)
            new_cls = " class=\"num new\"" if row.new_count else ' class="num"'
            fix_cls = (
                ' class="num fixed"' if row.fixed_count else ' class="num"'
            )
            new_cell = str(row.new_count) if row.new_count else "—"
            fix_cell = (
                str(row.fixed_count) if row.fixed_count else "—"
            )
            other_cell = (
                f'<td class="num">{snap.counts.get("other", 0)}</td>'
                if show_other
                else ""
            )
            row_lines.append(
                f"      <tr>"
                f"<td>{ts}</td>"
                f"<td><code>{fn}</code></td>"
                f'<td class="num">{snap.raw_total}</td>'
                f'<td class="num">{snap.counts.get("error", 0)}</td>'
                f'<td class="num">{snap.counts.get("warning", 0)}</td>'
                f'<td class="num">{snap.counts.get("info", 0)}</td>'
                f"{other_cell}"
                f"<td{new_cls}>{new_cell}</td>"
                f"<td{fix_cls}>{fix_cell}</td>"
                "</tr>"
            )
        rows_html = "\n".join(row_lines)

    # Summary band — a one-row strip showing first→last totals
    # and the net change. Coloured by sign so the at-a-glance
    # read matches the table-row NEW/FIXED colours.
    net = summary["net_change"]
    if summary["snapshots"] == 0:
        band_html = '<p class="summary">No snapshots in this directory.</p>'
    elif summary["snapshots"] == 1:
        n = summary["first_total"]
        band_html = (
            f'<p class="summary"><strong>{n}</strong> '
            f"{pluralize(n, 'finding')} in the only snapshot.</p>"
        )
    else:
        net_cls = "net-good" if net < 0 else ("net-bad" if net > 0 else "net-flat")
        sign = "+" if net > 0 else ""
        band_html = (
            f'<p class="summary"><strong>{summary["first_total"]}</strong>'
            f" → <strong>{summary['last_total']}</strong> findings across "
            f"<strong>{summary['snapshots']}</strong> snapshots "
            f'(<span class="{net_cls}">net {sign}{net}</span>; '
            f"{summary['total_new']} new, {summary['total_fixed']} fixed).</p>"
        )

    body = f"""  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>File</th>
        <th class="num">Total</th>
        <th class="num">Error</th>
        <th class="num">Warn</th>
        <th class="num">Info</th>{other_th}
        <th class="num">New</th>
        <th class="num">Fixed</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>"""

    return html_page(
        title="pgrls history",
        heading="pgrls history",
        command="pgrls history --format html",
        generated_at_iso=html.escape(now),
        extra_css=_HISTORY_CSS,
        max_width="72rem",
        header_extra=f"    {band_html}",
        body=body,
        footer_extra=f" · <em>{summary_sentence}</em>",
    )


render, HISTORY_FORMATS = make_dispatcher({
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
})
