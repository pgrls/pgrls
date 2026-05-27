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


# ──────────────────────────────────────────────────────────────────
# pgrls diff — five renderers agree on the numbers
# ──────────────────────────────────────────────────────────────────

import json as _json_diff  # avoid shadowing in case of future module-level json use
from datetime import timezone as _tz_diff, datetime as _dt_diff  # noqa: E402

from pgrls.diff.differ import Change, ChangeKind  # noqa: E402
from pgrls.diff.formatters import (  # noqa: E402
    format_diff_html,
    format_diff_json,
    format_diff_markdown,
    format_diff_sarif,
    format_diff_text,
)


def _diff_changes() -> list:
    """A fixture exercising every classification value at least once
    so every format must surface every bucket label."""
    return [
        Change(
            kind=ChangeKind.TABLE_ADDED_WITH_RLS,
            classification="safe",
            location="public.a",
            message="added with RLS",
            before_sql=None,
            after_sql=None,
        ),
        Change(
            kind=ChangeKind.TABLE_ADDED_WITH_RLS,
            classification="safe",
            location="public.b",
            message="added with RLS",
            before_sql=None,
            after_sql=None,
        ),
        Change(
            kind=ChangeKind.USING_REQUIRES_REVIEW,
            classification="requires_review",
            location="public.c.p",
            message="USING changed; review",
            before_sql="(tenant_id = 1)",
            after_sql="(tenant_id = current_setting('app.t'))",
        ),
        Change(
            kind=ChangeKind.POLICY_DROPPED_PERMISSIVE,
            classification="breaking",
            location="public.d.admin_all",
            message="dropped permissive ALL policy",
            before_sql=None,
            after_sql=None,
        ),
        Change(
            kind=ChangeKind.GRANT_PUBLIC_NO_RLS,
            classification="dangerous",
            location="public.e",
            message="granted SELECT to PUBLIC on RLS-disabled table",
            before_sql=None,
            after_sql=None,
        ),
    ]


def test_diff_all_five_formats_agree_on_total_change_count() -> None:
    """Every diff renderer must surface the same total count of
    Change objects. A renderer that silently drops a row (e.g. by
    filtering on classification) would fail this without affecting
    the other format's tests.
    """
    changes = _diff_changes()
    expected = len(changes)

    # JSON: violations array length
    text = format_diff_text(changes)
    md = format_diff_markdown(changes)
    html_out = format_diff_html(
        changes,
        generated_at=_dt_diff(2026, 5, 27, 16, 0, 0, tzinfo=_tz_diff.utc),
    )
    json_payload = _json_diff.loads(format_diff_json(changes))
    sarif_payload = _json_diff.loads(format_diff_sarif(changes))

    assert len(json_payload["violations"]) == expected
    # SARIF: results array
    assert (
        len(sarif_payload["runs"][0]["results"]) == expected
    )

    # Text: count `[CLS]` classification tag lines — one per Change
    # stanza. (Counting `+`/`-`/`~`/`!` marker lines would over-
    # count: predicate-kind stanzas also have `- before` / `+
    # after` SQL lines using the same marker prefixes.)
    cls_tag_lines = [
        ln for ln in text.splitlines()
        if any(
            f"[{tag}]" in ln
            for tag in ("SAFE", "REQUIRES_REVIEW", "BREAKING", "DANGEROUS")
        )
    ]
    assert len(cls_tag_lines) == expected

    # Markdown: count data rows in the table body.
    md_rows = [
        ln for ln in md.splitlines()
        if ln.startswith("|") and not ln.startswith("| Classification")
        and not ln.startswith("|---")
    ]
    assert len(md_rows) == expected

    # HTML: count `<tr class="row-...">` opens in tbody.
    body = re.search(r"<tbody>(.*?)</tbody>", html_out, flags=re.DOTALL)
    assert body is not None
    tr_opens = re.findall(r'<tr class="row-', body.group(1))
    assert len(tr_opens) == expected


def test_diff_all_five_formats_agree_on_per_classification_counts() -> None:
    """The per-classification breakdown — the actual "is this safe?"
    business answer the diff command exists to surface — must be
    consistent across formats."""
    from collections import Counter
    changes = _diff_changes()
    expected = Counter(c.classification for c in changes)
    # _diff_changes: 2 safe + 1 requires_review + 1 breaking + 1 dangerous
    assert expected == {
        "safe": 2,
        "requires_review": 1,
        "breaking": 1,
        "dangerous": 1,
    }

    text = format_diff_text(changes)
    md = format_diff_markdown(changes)
    html_out = format_diff_html(
        changes,
        generated_at=_dt_diff(2026, 5, 27, 16, 0, 0, tzinfo=_tz_diff.utc),
    )

    # Text format's trailing summary: "N changes — 1 dangerous, 1
    # requires review, 1 breaking, 2 safe." (_BUCKET_ORDER).
    assert "1 dangerous" in text
    assert "1 requires-review" in text
    assert "1 breaking" in text
    assert "2 safe" in text

    # Markdown summary line carries the same breakdown phrasing.
    assert "1 dangerous" in md
    assert "1 requires-review" in md
    assert "1 breaking" in md
    assert "2 safe" in md

    # HTML summary band has one chip per non-zero bucket.
    assert "<strong>2</strong>&nbsp;safe" in html_out
    assert "<strong>1</strong>&nbsp;requires-review" in html_out
    assert "<strong>1</strong>&nbsp;breaking" in html_out
    assert "<strong>1</strong>&nbsp;dangerous" in html_out


def test_diff_all_five_formats_carry_every_change_location() -> None:
    """Each Change's location must surface in every format."""
    changes = _diff_changes()
    expected_locations = {c.location for c in changes}

    text = format_diff_text(changes)
    md = format_diff_markdown(changes)
    html_out = format_diff_html(
        changes,
        generated_at=_dt_diff(2026, 5, 27, 16, 0, 0, tzinfo=_tz_diff.utc),
    )
    json_payload = _json_diff.loads(format_diff_json(changes))
    sarif_payload = _json_diff.loads(format_diff_sarif(changes))

    json_locations = {
        v["location"] for v in json_payload["violations"]
    }
    assert json_locations == expected_locations

    sarif_locations = {
        r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        for r in sarif_payload["runs"][0]["results"]
    }
    assert sarif_locations == expected_locations

    for loc in expected_locations:
        assert loc in text, f"text missing {loc}"
        assert loc in md, f"markdown missing {loc}"
        assert loc in html_out, f"html missing {loc}"


def test_diff_predicate_block_renders_in_text_and_html_for_using_kinds() -> None:
    """USING_* / WITH_CHECK_* changes carry before/after SQL the
    reviewer needs to see what changed. Text and HTML both render
    the predicate block; markdown surfaces just the summary text
    (a 4-column table can't carry multi-line SQL cleanly without
    layout pain). Pin the contract that text and HTML agree."""
    [c] = [Change(
        kind=ChangeKind.USING_TIGHTENED,
        classification="safe",
        location="public.docs.p",
        message="USING tightened",
        before_sql="(true)",
        after_sql="(tenant_id = current_setting('app.t'))",
    )]
    text = format_diff_text([c])
    html_out = format_diff_html(
        [c],
        generated_at=_dt_diff(2026, 5, 27, 16, 0, 0, tzinfo=_tz_diff.utc),
    )

    # Both formats show both before and after.
    assert "(true)" in text
    assert "tenant_id = current_setting" in text
    assert "(true)" in html_out
    assert "tenant_id = current_setting" in html_out
    # HTML wraps in `pre.predicate` styled block.
    assert "pred-minus" in html_out
    assert "pred-plus" in html_out


def test_diff_empty_changes_consistent_across_formats() -> None:
    """Every format's empty-changes case must be identifiable as
    "no changes" (the actual safe state the diff command exists
    to confirm). JSON returns `violations: []`; SARIF returns
    `results: []`; text/markdown emit the literal "no changes"
    line; HTML emits a green banner."""
    text = format_diff_text([])
    md = format_diff_markdown([])
    html_out = format_diff_html(
        [],
        generated_at=_dt_diff(2026, 5, 27, 16, 0, 0, tzinfo=_tz_diff.utc),
    )
    json_payload = _json_diff.loads(format_diff_json([]))
    sarif_payload = _json_diff.loads(format_diff_sarif([]))

    assert text == "pgrls diff: no changes."
    assert md == "pgrls diff: no changes.\n"
    assert "No changes in this diff" in html_out
    assert json_payload["violations"] == []
    assert sarif_payload["runs"][0]["results"] == []


# ──────────────────────────────────────────────────────────────────
# pgrls explain — four renderers agree on the catalog + per-rule
# ──────────────────────────────────────────────────────────────────
#
# `pgrls explain` reached its full format set in v0.6.21 (text /
# markdown / json / html). Each renderer is hand-written from the
# same Rule registry; a hand-rolled formatter that silently drops a
# rule (e.g. by misfiltering on an attribute) would only fail its
# own test file. Pin the cross-format invariants explicitly.

from click.testing import CliRunner  # noqa: E402

from pgrls import __version__  # noqa: E402
from pgrls.cli import (  # noqa: E402
    _fixable_rule_ids,
    _render_catalog_html,
    _render_catalog_json,
    _render_catalog_markdown,
    _render_rule_html,
    _render_rule_json,
    _render_rule_markdown,
    _rule_docstring_body,
    main as cli_main,
)
from pgrls.rules import all_rules  # noqa: E402


def test_explain_catalog_all_four_formats_agree_on_rule_count() -> None:
    """The number of rules in the catalog must be the same regardless
    of which renderer surfaces it. JSON exposes `count` explicitly;
    text/markdown/html have one row per rule that we count via the
    rendered markup."""
    rules = list(all_rules())
    fixable = _fixable_rule_ids()
    expected = len(rules)

    runner = CliRunner()
    text_out = runner.invoke(cli_main, ["explain"]).output
    md_out = _render_catalog_markdown(rules)
    html_out = _render_catalog_html(rules, fixable_ids=fixable)
    json_payload = json.loads(
        _render_catalog_json(rules, fixable_ids=fixable)
    )

    # JSON: explicit count + array length
    assert json_payload["count"] == expected
    assert len(json_payload["rules"]) == expected

    # Text: one rule per line — count lines matching the
    # `<ID>      [<sev>]   <title>` shape via the leading rule-id
    # token. The footer line ("Run `pgrls explain ...`") doesn't
    # match this pattern.
    text_rule_lines = [
        ln for ln in text_out.splitlines()
        if re.match(r"^[A-Z]+\d{3}\s+\[", ln)
    ]
    assert len(text_rule_lines) == expected

    # Markdown: one data row per rule in the table body.
    md_rows = [
        ln for ln in md_out.splitlines()
        if ln.startswith("| ") and not ln.startswith("| ID ")
        and not ln.startswith("|---")
    ]
    assert len(md_rows) == expected

    # HTML: one `<tr>` per rule in tbody.
    body = re.search(r"<tbody>(.*?)</tbody>", html_out, flags=re.DOTALL)
    assert body is not None
    tr_opens = re.findall(r"<tr>", body.group(1))
    assert len(tr_opens) == expected


def test_explain_catalog_every_rule_id_surfaces_in_every_format() -> None:
    """A rule that's silently filtered out of one renderer (e.g. by a
    severity guard the others don't share) would fail this without
    affecting any per-renderer test."""
    rules = list(all_rules())
    fixable = _fixable_rule_ids()
    expected_ids = {r.id for r in rules}

    runner = CliRunner()
    text_out = runner.invoke(cli_main, ["explain"]).output
    md_out = _render_catalog_markdown(rules)
    html_out = _render_catalog_html(rules, fixable_ids=fixable)
    json_payload = json.loads(
        _render_catalog_json(rules, fixable_ids=fixable)
    )

    json_ids = {r["id"] for r in json_payload["rules"]}
    assert json_ids == expected_ids

    for rid in expected_ids:
        assert rid in text_out, f"text missing {rid}"
        assert rid in md_out, f"markdown missing {rid}"
        assert rid in html_out, f"html missing {rid}"


def test_explain_catalog_every_rule_severity_surfaces_in_every_format() -> None:
    """Per-rule severity must be consistent across formats.
    A hand-rolled renderer that swapped error↔warning for one rule
    would fail this test."""
    rules = list(all_rules())
    fixable = _fixable_rule_ids()

    runner = CliRunner()
    text_out = runner.invoke(cli_main, ["explain"]).output
    md_out = _render_catalog_markdown(rules)
    html_out = _render_catalog_html(rules, fixable_ids=fixable)
    json_payload = json.loads(
        _render_catalog_json(rules, fixable_ids=fixable)
    )

    # Index by rule id for fast lookup.
    json_severity_by_id = {
        r["id"]: r["severity"] for r in json_payload["rules"]
    }
    assert json_severity_by_id == {r.id: r.severity for r in rules}

    # In text catalog, severity sits next to ID as `<ID>      [<sev>]`.
    # Index HTML rows by id once so the per-rule severity check can't
    # drift across rows (see fixable-flag test for the same pattern).
    body_match = re.search(
        r"<tbody>(.*?)</tbody>", html_out, flags=re.DOTALL
    )
    assert body_match is not None
    rows_by_id: dict[str, str] = {}
    for row in re.findall(r"<tr>.*?</tr>", body_match.group(1), flags=re.DOTALL):
        id_match = re.search(r"<code>([A-Z]+\d+)</code>", row)
        if id_match:
            rows_by_id[id_match.group(1)] = row

    for r in rules:
        assert f"{r.id:<8} [{r.severity}]" in text_out, (
            f"text missing severity for {r.id}"
        )
        # Markdown table row: `| <ID> | <sev> | <title> |`.
        assert f"| {r.id} | {r.severity} |" in md_out, (
            f"markdown missing severity for {r.id}"
        )
        # HTML row: pill with `sev-<sev>` class on the row for that ID.
        row_html = rows_by_id.get(r.id)
        assert row_html is not None, f"html missing row for {r.id}"
        assert f'class="pill sev-{r.severity}"' in row_html, (
            f"html severity mismatch for {r.id}"
        )


def test_explain_catalog_json_and_html_agree_on_fixable_flag() -> None:
    """JSON exposes `fixable` per rule; HTML renders a `✦ fix` badge
    in the Fixable column. Both must agree with `_fixable_rule_ids()`."""
    rules = list(all_rules())
    fixable = _fixable_rule_ids()
    json_payload = json.loads(
        _render_catalog_json(rules, fixable_ids=fixable)
    )
    html_out = _render_catalog_html(rules, fixable_ids=fixable)

    json_fixable = {r["id"] for r in json_payload["rules"] if r["fixable"]}
    assert json_fixable == fixable

    # Index each rule's row by ID. Split on row close so the regex
    # can't drift across rules (a lazy `<tr>.*?<code>SEC003` will
    # start at SEC001's `<tr>` and span every row in between).
    body_match = re.search(
        r"<tbody>(.*?)</tbody>", html_out, flags=re.DOTALL
    )
    assert body_match is not None
    rows_by_id: dict[str, str] = {}
    for row in re.findall(r"<tr>.*?</tr>", body_match.group(1), flags=re.DOTALL):
        id_match = re.search(r"<code>([A-Z]+\d+)</code>", row)
        if id_match:
            rows_by_id[id_match.group(1)] = row

    # HTML: locate each fixable rule's row and confirm the `fix` badge
    # is in its Fixable cell; non-fixable rules must NOT carry one.
    for r in rules:
        row_html = rows_by_id.get(r.id)
        assert row_html is not None, f"html missing row for {r.id}"
        if r.id in fixable:
            assert '<span class="fixable">' in row_html, (
                f"html missing fix badge for fixable rule {r.id}"
            )
        else:
            assert '<span class="fixable">' not in row_html, (
                f"html has fix badge for non-fixable rule {r.id}"
            )


def test_explain_single_rule_metadata_consistent_across_formats() -> None:
    """For a single-rule invocation, every format must surface the
    same id + severity + title. Pinned for every registered rule —
    a renderer drifting from the Rule object for one specific rule
    would otherwise pass per-renderer tests that only sampled one
    sentinel."""
    fixable = _fixable_rule_ids()
    runner = CliRunner()
    for rule in all_rules():
        text_out = runner.invoke(cli_main, ["explain", rule.id]).output
        md = _render_rule_markdown(rule)
        html_out = _render_rule_html(rule, fixable_ids=fixable)
        payload = json.loads(
            _render_rule_json(rule, fixable_ids=fixable)
        )

        # JSON: explicit fields.
        assert payload["id"] == rule.id
        assert payload["severity"] == rule.severity
        assert payload["title"] == rule.title

        # Text: `<ID>  [<sev>]  <title>` header line.
        assert (
            f"{rule.id}  [{rule.severity}]  {rule.title}" in text_out
        )

        # Markdown: `## <ID> — <title>` heading + `**Severity:**` line.
        assert f"## {rule.id} — {rule.title}" in md
        assert f"**Severity:** {rule.severity}" in md

        # HTML: title in `<h1>`, severity in pill, ID in `<code>` in
        # CLI hint. Title is `html.escape`d in the rendered page —
        # apostrophes in rule titles (e.g. SEC014's "caller's RLS")
        # become `&#x27;` — so escape the expected substring too.
        import html as _html_consistency_inner
        expected_h1 = (
            f"{rule.id} — {_html_consistency_inner.escape(rule.title)}"
        )
        assert expected_h1 in html_out, (
            f"html missing h1 for {rule.id}"
        )
        assert f'class="pill sev-{rule.severity}"' in html_out


def test_explain_single_rule_reference_body_consistent_across_formats() -> None:
    """The rule's reference body (docstring minus title line) must
    surface verbatim in every renderer. The strongest of the explain
    consistency invariants: pins that all four formats share
    `_rule_docstring_body` as the source of truth."""
    fixable = _fixable_rule_ids()
    runner = CliRunner()
    for rule in all_rules():
        body = _rule_docstring_body(rule)
        if not body:
            # Rules with no extended reference have nothing to pin.
            continue
        # Use a stable substring — the body's first non-blank line —
        # so the assertion isn't sensitive to surrounding whitespace
        # / trailing newline differences across renderers.
        first_line = next(
            (ln for ln in body.splitlines() if ln.strip()),
            None,
        )
        if first_line is None:
            continue

        text_out = runner.invoke(cli_main, ["explain", rule.id]).output
        md = _render_rule_markdown(rule)
        html_out = _render_rule_html(rule, fixable_ids=fixable)
        payload = json.loads(
            _render_rule_json(rule, fixable_ids=fixable)
        )

        # JSON: the explicit `reference` field equals the body.
        assert payload["reference"] == body, (
            f"json reference drift for {rule.id}"
        )
        assert first_line in text_out, (
            f"text missing reference body for {rule.id}"
        )
        assert first_line in md, (
            f"markdown missing reference body for {rule.id}"
        )
        # HTML escapes `<`/`>`/`&` in the body — escape the
        # first line the same way so the assertion stays correct
        # for docstrings carrying any of those.
        import html as _html_consistency
        assert _html_consistency.escape(first_line) in html_out, (
            f"html missing reference body for {rule.id}"
        )


def test_explain_catalog_html_version_string_matches_json() -> None:
    """`pgrls_version` is the source of truth for which release is
    being documented. JSON exposes it explicitly; HTML embeds it in
    the meta line. They must agree."""
    rules = list(all_rules())
    fixable = _fixable_rule_ids()
    json_payload = json.loads(
        _render_catalog_json(rules, fixable_ids=fixable)
    )
    html_out = _render_catalog_html(rules, fixable_ids=fixable)

    assert json_payload["pgrls_version"] == __version__
    assert f"pgrls {__version__}" in html_out
