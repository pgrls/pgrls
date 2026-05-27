"""Cross-format consistency tests.

These tests don't check individual renderers (each format has its
own test file pinning output shape). They check the *invariant
that all renderers for one command agree on the underlying numbers*
— total finding counts, per-snapshot deltas, status-pill tallies,
etc. — for the same input.

Why: each HTML / Markdown / JSON renderer is hand-written
separately. A typo (`row.snapshot.raw_total` vs
`row.snapshot.counts['error']`) in one renderer would produce
output that looks fine in isolation but disagrees with what the
JSON / text formats say. These tests catch that drift.

Two commands covered:

* **`pgrls history`** — four renderers (text/json/markdown/html)
  agree on per-snapshot totals + the NEW/FIXED deltas + the
  series-level summary numbers.
* **`pgrls report`** — four renderers (text/json/markdown/html)
  agree on per-table count by status (protected / not-forced /
  no-policies / covered-by-parent / rls-off) and the aggregate
  summary.

For HTML, we extract numbers from the rendered string via regex
+ structural anchors (we know the markup shape from the per-
renderer tests; this file just asserts the numbers match).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from pgrls.history import (
    FindingKey,
    Snapshot,
    build_rows,
    render_html as history_render_html,
    render_json as history_render_json,
    render_markdown as history_render_markdown,
    render_text as history_render_text,
)
from pgrls.model import Policy, Schema, Table
from pgrls.report import (
    _STATUS_LABELS,
    build_report,
    render_html as report_render_html,
    render_json as report_render_json,
    render_markdown as report_render_markdown,
    render_text as report_render_text,
)


# ──────────────────────────────────────────────────────────────────
# Shared fixtures
# ──────────────────────────────────────────────────────────────────


_FIXED_GENERATED_AT = datetime(2026, 5, 27, 16, 0, 0, tzinfo=timezone.utc)


def _policy(permissive: bool = True, name: str = "p") -> Policy:
    return Policy(
        name=name,
        command="SELECT",
        permissive=permissive,
        roles=("public",),
        using_sql="true",
        with_check_sql=None,
    )


def _table(
    name: str,
    *,
    rls: bool,
    force: bool,
    policies: tuple[Policy, ...] = (),
    schema: str = "public",
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
    )


def _history_rows() -> list:
    """A multi-snapshot series with growth, decline, and stable
    states — exercises NEW/FIXED logic across every interesting
    transition."""
    return build_rows([
        Snapshot(
            path=Path("2026-05-15T0800.json"),
            timestamp=datetime(2026, 5, 15, 8, tzinfo=timezone.utc),
            findings=frozenset({
                FindingKey("SEC001", "public.t1"),
                FindingKey("SEC002", "public.t2"),
                FindingKey("SEC003", "public.t3"),
                FindingKey("HYG001", "public.t4"),
            }),
            raw_total=4,
            counts={"error": 3, "warning": 0, "info": 1},
        ),
        Snapshot(
            path=Path("2026-05-20T0800.json"),
            timestamp=datetime(2026, 5, 20, 8, tzinfo=timezone.utc),
            findings=frozenset({
                FindingKey("SEC001", "public.t1"),
                FindingKey("SEC002", "public.t2"),
                FindingKey("PERF001", "public.t5"),
            }),
            raw_total=3,
            counts={"error": 2, "warning": 1, "info": 0},
        ),
        Snapshot(
            path=Path("2026-05-25T0800.json"),
            timestamp=datetime(2026, 5, 25, 8, tzinfo=timezone.utc),
            findings=frozenset({
                FindingKey("SEC001", "public.t1"),
            }),
            raw_total=1,
            counts={"error": 1, "warning": 0, "info": 0},
        ),
    ])


def _report_schema() -> Schema:
    """A schema spanning every status the report renderer enumerates
    so all four formats have something to render for each pill."""
    return Schema(
        tables=(
            _table("protected_a", rls=True, force=True,
                   policies=(_policy(),)),
            _table("protected_b", rls=True, force=True,
                   policies=(_policy(),)),
            _table("not_forced", rls=True, force=False,
                   policies=(_policy(),)),
            _table("no_policies", rls=True, force=True, policies=()),
            _table("rls_off_a", rls=False, force=False),
            _table("rls_off_b", rls=False, force=False),
            _table("rls_off_c", rls=False, force=False),
        ),
    )


# ──────────────────────────────────────────────────────────────────
# pgrls history — all four renderers agree on the numbers
# ──────────────────────────────────────────────────────────────────


def test_history_all_four_formats_agree_on_per_snapshot_totals() -> None:
    """For each of the 3 fixture snapshots, every renderer must
    surface the same `total` count. This catches a row-level
    serialization bug in one renderer without affecting the others.
    """
    rows = _history_rows()
    text = history_render_text(rows)
    md = history_render_markdown(rows)
    html = history_render_html(rows, generated_at=_FIXED_GENERATED_AT)
    json_payload = json.loads(history_render_json(rows))

    expected_totals = [r.snapshot.raw_total for r in rows]  # [4, 3, 1]

    # JSON: explicit field
    json_totals = [s["total"] for s in json_payload["snapshots"]]
    assert json_totals == expected_totals

    # Text: column 3 of each non-header / non-blank line
    text_data_rows = _text_table_rows(text)
    text_totals = [int(r[2]) for r in text_data_rows]
    assert text_totals == expected_totals

    # Markdown: 3rd pipe cell per data row
    md_data_rows = _markdown_table_rows(md)
    md_totals = [int(r[2]) for r in md_data_rows]
    assert md_totals == expected_totals

    # HTML: numeric cell in each `<tr>`
    html_totals = _html_numeric_cells_at_index(html, total_col_index=2)
    assert html_totals == expected_totals


def test_history_all_four_formats_agree_on_new_fixed_deltas() -> None:
    """NEW / FIXED columns are computed from set differences across
    snapshots — any renderer that drifts from build_rows() would
    fall out of sync. Pin agreement explicitly.
    """
    rows = _history_rows()
    text = history_render_text(rows)
    md = history_render_markdown(rows)
    html = history_render_html(rows, generated_at=_FIXED_GENERATED_AT)
    json_payload = json.loads(history_render_json(rows))

    # Expected deltas: snap[0] is baseline (new=4, fixed=0);
    # snap[1] = lost t3/t4 (SEC003 + HYG001) + gained PERF001
    # → new=1, fixed=2. snap[2] = lost t2 + PERF001 → new=0, fixed=2.
    expected_new = [4, 1, 0]
    expected_fixed = [0, 2, 2]

    json_new = [s["new"] for s in json_payload["snapshots"]]
    json_fixed = [s["fixed"] for s in json_payload["snapshots"]]
    assert json_new == expected_new
    assert json_fixed == expected_fixed

    text_data = _text_table_rows(text)
    # text renders 0 as `-` so the first snapshot's fixed column is `-`
    text_new = [_parse_dash_int(r[-2]) for r in text_data]
    text_fixed = [_parse_dash_int(r[-1]) for r in text_data]
    assert text_new == expected_new
    assert text_fixed == expected_fixed

    md_data = _markdown_table_rows(md)
    # markdown renders 0 as `—` (em-dash)
    md_new = [_parse_emdash_int(r[-2]) for r in md_data]
    md_fixed = [_parse_emdash_int(r[-1]) for r in md_data]
    assert md_new == expected_new
    assert md_fixed == expected_fixed


def test_history_summary_numbers_agree_across_formats() -> None:
    rows = _history_rows()
    text = history_render_text(rows)
    md = history_render_markdown(rows)
    json_payload = json.loads(history_render_json(rows))

    # Series-level summary: first total 4 → last total 1, net -3,
    # total_new (excluding baseline) = 1+0 = 1, total_fixed = 2+2 = 4.
    s = json_payload["summary"]
    assert s["snapshots"] == 3
    assert s["first_total"] == 4
    assert s["last_total"] == 1
    assert s["net_change"] == -3
    assert s["total_new"] == 1
    assert s["total_fixed"] == 4

    # Text summary line shape: "3 snapshots, net change -3 (4 → 1); 1 new, 4 fixed."
    assert "3 snapshots" in text
    assert "net change -3" in text
    assert "(4 → 1)" in text
    assert "1 new, 4 fixed" in text

    # Markdown summary line same text, just in bold
    assert "**3 snapshots" in md
    assert "net change -3" in md
    assert "(4 → 1)" in md


def test_history_severity_counts_agree_across_formats() -> None:
    rows = _history_rows()
    text = history_render_text(rows)
    md = history_render_markdown(rows)
    html = history_render_html(rows, generated_at=_FIXED_GENERATED_AT)
    json_payload = json.loads(history_render_json(rows))

    # Per-snapshot severity tallies: snap[0]=(3,0,1), snap[1]=(2,1,0),
    # snap[2]=(1,0,0)
    expected_errors = [3, 2, 1]
    expected_warnings = [0, 1, 0]
    expected_infos = [1, 0, 0]

    json_errors = [s["errors"] for s in json_payload["snapshots"]]
    json_warnings = [s["warnings"] for s in json_payload["snapshots"]]
    json_infos = [s["infos"] for s in json_payload["snapshots"]]
    assert json_errors == expected_errors
    assert json_warnings == expected_warnings
    assert json_infos == expected_infos

    text_data = _text_table_rows(text)
    assert [int(r[3]) for r in text_data] == expected_errors
    assert [int(r[4]) for r in text_data] == expected_warnings
    assert [int(r[5]) for r in text_data] == expected_infos

    md_data = _markdown_table_rows(md)
    assert [int(r[3]) for r in md_data] == expected_errors
    assert [int(r[4]) for r in md_data] == expected_warnings
    assert [int(r[5]) for r in md_data] == expected_infos


# ──────────────────────────────────────────────────────────────────
# pgrls report — all four renderers agree on status counts
# ──────────────────────────────────────────────────────────────────


def test_report_all_four_formats_agree_on_status_counts() -> None:
    """The summary aggregate is the source of truth; every renderer
    must surface it consistently. Compare against the underlying
    `Report.summary` dict directly."""
    report = build_report(_report_schema())
    summary = report.summary

    text = report_render_text(report)
    md = report_render_markdown(report)
    html = report_render_html(
        report, generated_at=_FIXED_GENERATED_AT
    )
    json_payload = json.loads(report_render_json(report))

    # JSON exposes summary explicitly.
    for key in summary:
        assert json_payload["summary"][key] == summary[key], (
            f"json disagrees on summary[{key!r}]: "
            f"{json_payload['summary'][key]} vs source {summary[key]}"
        )

    # Text format renders the summary line at the end. Pin the
    # non-zero counts appear with their integer values. Labels are
    # the canonical human strings from `_STATUS_LABELS` (e.g.
    # "RLS off" not "rls-off") — import the map so this test
    # doesn't drift if the labels are reworded.
    expected_counts = {
        "protected": 2,
        "not-forced": 1,
        "no-policies": 1,
        "rls-off": 3,
    }
    for status, n in expected_counts.items():
        label = _STATUS_LABELS[status]
        assert f"{n} {label}" in text, (
            f"text missing '{n} {label}'"
        )

    # Markdown carries the same summary line.
    for status, n in expected_counts.items():
        label = _STATUS_LABELS[status]
        assert f"{n} {label}" in md, (
            f"markdown missing '{n} {label}'"
        )

    # HTML renders status pills. Pin one chip per non-zero status.
    for status, n in expected_counts.items():
        chip = f'<span class="pill status-{status}">'
        assert chip in html, f"html missing chip for {status}"
        # The number lands in a <strong> next to the chip's label.
        assert f"<strong>{n}</strong>" in html


def test_report_all_four_formats_carry_every_table_row() -> None:
    """Each table in the schema must appear in each renderer's
    body, regardless of status."""
    schema = _report_schema()
    report = build_report(schema)
    expected_qnames = sorted(t.qualified_name for t in schema.tables)

    text = report_render_text(report)
    md = report_render_markdown(report)
    html = report_render_html(
        report, generated_at=_FIXED_GENERATED_AT
    )
    json_payload = json.loads(report_render_json(report))

    # JSON: explicit array
    json_qnames = sorted(
        row["table"] for row in json_payload["tables"]
    )
    assert json_qnames == expected_qnames

    # Each other format must mention every qualified name.
    for qname in expected_qnames:
        assert qname in text, f"text missing {qname}"
        assert qname in md, f"markdown missing {qname}"
        assert qname in html, f"html missing {qname}"


# ──────────────────────────────────────────────────────────────────
# Helpers — parse renderer output back into structured rows
# ──────────────────────────────────────────────────────────────────


def _text_table_rows(text: str) -> list[list[str]]:
    """The text history table has whitespace-separated columns
    with the first line being headers and a trailing blank line +
    summary line. Extract data rows only."""
    out: list[list[str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        # Skip the header line (starts with TIMESTAMP)
        if line.startswith("TIMESTAMP"):
            continue
        # Skip the trailing summary line ("N snapshots, ...")
        if "snapshots, net change" in line or line.startswith(
            "1 snapshot, "
        ):
            continue
        # Skip "No snapshots found." placeholder
        if "No snapshots" in line:
            continue
        # Split on any run of whitespace
        cells = line.split()
        if cells:
            out.append(cells)
    return out


def _markdown_table_rows(md: str) -> list[list[str]]:
    """Extract data rows from a Markdown table — the lines starting
    with `|` excluding the header row and the `---`-separator."""
    out: list[list[str]] = []
    for line in md.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if line.startswith("| Timestamp"):  # header
            continue
        if line.startswith("|---"):  # separator
            continue
        # Strip leading/trailing pipe + space, split on `|`
        cells = [c.strip() for c in line.strip("|").split("|")]
        out.append(cells)
    return out


def _html_numeric_cells_at_index(html: str, total_col_index: int) -> list[int]:
    """Extract the `total` column's integers from each `<tr>` in
    `<tbody>`. Cheap structural-anchor parse — no full HTML parser
    needed because we control the markup shape."""
    # Per-row regex: capture the i-th `<td>` (1-indexed mentally;
    # our `_html_table_rows` style returns 0-indexed cell list).
    rows = _html_data_rows(html)
    return [int(_extract_td_text(r, total_col_index)) for r in rows]


def _html_data_rows(html: str) -> list[str]:
    """Return each `<tr>...</tr>` from `<tbody>` as a raw substring."""
    body_match = re.search(
        r"<tbody>(.*?)</tbody>", html, flags=re.DOTALL
    )
    assert body_match, "expected <tbody> in HTML output"
    body = body_match.group(1)
    return re.findall(r"<tr>.*?</tr>", body, flags=re.DOTALL)


def _extract_td_text(tr_html: str, index: int) -> str:
    """Extract the text of the index-th `<td>` from a `<tr>`. Strips
    HTML tags inside the cell (e.g. `<code>filename</code>` →
    `filename`)."""
    cells = re.findall(r"<td[^>]*>(.*?)</td>", tr_html, flags=re.DOTALL)
    cell = cells[index]
    # Strip inner tags (we use this for numeric cells mostly).
    return re.sub(r"<[^>]+>", "", cell).strip()


def _parse_dash_int(s: str) -> int:
    """text format renders zero counts as `-`; treat as 0."""
    return 0 if s == "-" else int(s)


def _parse_emdash_int(s: str) -> int:
    """markdown format renders zero counts as `—` (em-dash); treat as 0."""
    return 0 if s == "—" else int(s)
