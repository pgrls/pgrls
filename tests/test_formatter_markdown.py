"""Unit tests for `pgrls.formatters.markdown`.

Pin the user-visible Markdown shape (table columns, summary line,
empty-case wording) and the structural invariants (cell escaping,
schema-wide sentinel, AGENTS.md anchor convention shared with the
SARIF helpUri).
"""
from __future__ import annotations

import pytest

from pgrls.formatters import format_violations
from pgrls.violations import Violation


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    title: str = "RLS not enabled on table",
    message: str = "Table public.users does not have row-level security enabled.",
    location: str | None = "public.users",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        message=message,
        location=location,
    )


def test_markdown_zero_violations_matches_text_clean_message() -> None:
    # The "clean DB" line is intentionally identical to the text
    # formatter's so a one-liner that gates on the literal string
    # works against either format.
    out = format_violations([], format="markdown")
    assert out == "pgrls: no issues found.\n"


def test_markdown_emits_h2_heading_so_it_composes_into_larger_doc() -> None:
    out = format_violations([_v()], format="markdown")
    # H2 not H1 — the user is presumably embedding this in a PR
    # body or a wiki page that already owns the H1.
    assert out.startswith("## pgrls findings\n")


def test_markdown_emits_table_header_with_four_columns() -> None:
    out = format_violations([_v()], format="markdown")
    assert "| Severity | Rule | Location | Message |" in out
    assert "|---|---|---|---|" in out


def test_markdown_one_row_per_violation_in_caller_order() -> None:
    vs = [
        _v(rule_id="SEC003", location="public.c"),
        _v(rule_id="SEC001", location="public.a"),
        _v(rule_id="SEC002", location="public.b"),
    ]
    out = format_violations(vs, format="markdown")
    # Caller order survives — the formatter does not sort.
    i_c = out.index("public.c")
    i_a = out.index("public.a")
    i_b = out.index("public.b")
    assert i_c < i_a < i_b
    # One table row per violation (not counting header + separator).
    body_lines = [
        line for line in out.splitlines() if line.startswith("| ❌")
        or line.startswith("| ⚠️")
        or line.startswith("| ℹ️")
    ]
    assert len(body_lines) == 3


def test_markdown_severity_label_includes_emoji_and_text() -> None:
    out_err = format_violations([_v(severity="error")], format="markdown")
    out_warn = format_violations(
        [_v(severity="warning")], format="markdown"
    )
    out_info = format_violations([_v(severity="info")], format="markdown")
    assert "❌ error" in out_err
    assert "⚠️ warning" in out_warn
    assert "ℹ️ info" in out_info


def test_markdown_rule_id_links_to_per_rule_anchor_in_agents_md() -> None:
    out = format_violations([_v(rule_id="SEC001")], format="markdown")
    # Lowercase anchor, GitHub blob URL — same convention the SARIF
    # helpUri uses. A change to one needs the matching change in the
    # other (markdown.py and sarif.py both call this out).
    expected = (
        "[SEC001](https://github.com/pgrls/pgrls/blob/main/"
        "AGENTS.md#rule-sec001)"
    )
    assert expected in out


def test_markdown_diff_rule_links_to_diff_rules_anchor() -> None:
    # `DIFF_*` rule_ids share the `#diff-rules` heading anchor —
    # AGENTS.md doesn't have per-DIFF-kind anchors, the
    # classification table covers them all under one section.
    out = format_violations(
        [_v(rule_id="DIFF_RLS_FLIPPED")], format="markdown"
    )
    expected = (
        "[DIFF_RLS_FLIPPED](https://github.com/pgrls/pgrls/blob/main/"
        "AGENTS.md#diff-rules)"
    )
    assert expected in out


def test_markdown_location_uses_backticks_for_qualified_names() -> None:
    out = format_violations(
        [_v(location="public.users.tenant_isolation")],
        format="markdown",
    )
    assert "`public.users.tenant_isolation`" in out


def test_markdown_schema_wide_sentinel_is_italicized() -> None:
    # Match the sentinel the SARIF and text formatters use so all
    # three formats agree on the human-facing wording for a finding
    # with no specific table or policy.
    out = format_violations(
        [_v(rule_id="SEC001", location=None)], format="markdown"
    )
    assert "_(schema-wide)_" in out


def test_markdown_escapes_pipe_in_message_so_table_layout_holds() -> None:
    out = format_violations(
        [_v(message="bad | char in message")],
        format="markdown",
    )
    # The literal `|` inside the message becomes `\|`; otherwise the
    # cell would split into two columns and break the table.
    assert "bad \\| char in message" in out
    assert "| bad | char | in | message |" not in out


def test_markdown_escapes_newline_in_message_to_br() -> None:
    out = format_violations(
        [_v(message="line one\nline two")],
        format="markdown",
    )
    # Newlines turn into `<br>` so the row stays a row.
    assert "line one<br>line two" in out
    # And the literal newline character is gone from the cell body.
    body = out.split("\n\n**Summary:")[0]
    assert "line one\nline two" not in body


def test_markdown_summary_orders_severities_error_then_warning_then_info() -> None:
    vs = [
        _v(rule_id="HYG001", severity="info", location="public.c"),
        _v(rule_id="SEC001", severity="error", location="public.a"),
        _v(rule_id="SEC002", severity="warning", location="public.b"),
    ]
    out = format_violations(vs, format="markdown")
    summary_line = [
        line for line in out.splitlines() if line.startswith("**Summary:")
    ][0]
    i_err = summary_line.index("error")
    i_warn = summary_line.index("warning")
    i_info = summary_line.index("info")
    assert i_err < i_warn < i_info


def test_markdown_summary_skips_zero_count_severities() -> None:
    out = format_violations([_v(severity="error")], format="markdown")
    summary_line = [
        line for line in out.splitlines() if line.startswith("**Summary:")
    ][0]
    assert "warning" not in summary_line
    assert "info" not in summary_line


def test_markdown_summary_includes_total() -> None:
    vs = [
        _v(severity="error", location="public.a"),
        _v(severity="warning", location="public.b"),
        _v(severity="info", location="public.c"),
    ]
    out = format_violations(vs, format="markdown")
    assert "Total: 3" in out


def test_markdown_singular_versus_plural_summary() -> None:
    one = format_violations([_v(severity="error")], format="markdown")
    assert "1 error" in one
    assert "1 errors" not in one
    two = format_violations(
        [_v(severity="error"), _v(severity="error")],
        format="markdown",
    )
    assert "2 errors" in two


def test_markdown_output_ends_with_newline_for_shell_friendliness() -> None:
    out = format_violations([_v()], format="markdown")
    assert out.endswith("\n")


def test_markdown_format_is_advertised_by_supported_formats() -> None:
    # Anywhere the CLI introspects supported formats (Click choices,
    # README docs, integration glue) reads the `SUPPORTED_FORMATS`
    # tuple. Pin that markdown landed in the dispatch table.
    from pgrls.formatters import SUPPORTED_FORMATS

    assert "markdown" in SUPPORTED_FORMATS


def test_markdown_handles_none_location_with_schema_wide_sentinel() -> None:
    # Belt-and-suspenders coverage parallel to the text and SARIF
    # formatters' schema-wide tests.
    out = format_violations(
        [_v(rule_id="SEC001", location=None)], format="markdown"
    )
    body_row = [
        line for line in out.splitlines()
        if line.startswith("| ❌")
    ][0]
    # The row's location cell is the italicized sentinel, not a
    # bare backtick-empty.
    assert "_(schema-wide)_" in body_row
    assert "``" not in body_row


@pytest.mark.parametrize(
    "rule_id,expected_anchor",
    [
        ("SEC001", "rule-sec001"),
        ("PERF002", "rule-perf002"),
        ("HYG002", "rule-hyg002"),
        ("DIFF_POLICY_DROPPED_RESTRICTIVE", "diff-rules"),
        ("DIFF_GRANT_PUBLIC_NO_RLS", "diff-rules"),
    ],
)
def test_markdown_rule_link_matches_sarif_anchor_convention(
    rule_id: str, expected_anchor: str
) -> None:
    # Every rule_id the SARIF formatter knows how to anchor must
    # produce the same anchor in the Markdown formatter. The two
    # link surfaces share a contract; this test pins it
    # parametrically so a future renaming of the AGENTS.md anchor
    # scheme has to update both formatters together.
    out = format_violations([_v(rule_id=rule_id)], format="markdown")
    assert f"#{expected_anchor})" in out


# ---------------------------------------------------------------------------
# Hostile-input hardening (operator-controlled identifiers)
# ---------------------------------------------------------------------------


def test_markdown_location_with_newline_does_not_split_table_row() -> None:
    # The most critical contract: a `\n` inside a Postgres
    # quoted-identifier name MUST NOT split the GFM pipe-table row.
    # A row split would push the next cell ("Message") onto a fresh
    # line that the parser treats as a header-less continuation,
    # corrupting the visible table.
    out = format_violations(
        [
            _v(
                rule_id="SEC013",
                severity="warning",
                location="public.invoices.evil\nINJECTED",
                message="audit",
            )
        ],
        format="markdown",
    )
    # Locate the violation row. It must be a single line containing
    # all four expected `|` separators (5 pipes since each row starts
    # and ends with `|`).
    table_rows = [
        line for line in out.splitlines() if line.startswith("| ⚠️")
    ]
    assert len(table_rows) == 1
    assert table_rows[0].count("|") == 5
    # The escape representation is visible in the cell.
    assert "evil\\nINJECTED" in table_rows[0]
    # And no bare newline leaked into the table portion.
    table_section = out.split("**Summary:**")[0]
    assert "evil\nINJECTED" not in table_section


def test_markdown_location_with_pipe_escaped() -> None:
    # A `|` character in a Postgres identifier (quoted form allows
    # it) would split the cell mid-row. Must be backslash-escaped
    # so the pipe-table parser treats it as part of the location
    # cell.
    out = format_violations(
        [_v(location="public.weird|name")], format="markdown"
    )
    table_rows = [
        line for line in out.splitlines() if line.startswith("| ❌")
    ]
    assert len(table_rows) == 1
    # 5 pipes for cell separators + 1 backslash-escaped pipe
    # inside the location cell. (The backslash precedes the pipe.)
    assert table_rows[0].count("\\|") == 1
    # Total pipe count is 5 separators + 1 escaped = 6. If it were
    # an unescaped pipe, the row would have 6 cell separators which
    # would push everything one column to the right.
    assert table_rows[0].count("|") == 6
    # The escape sequence is right next to "weird" in the location.
    assert "weird\\|name" in table_rows[0]


def test_markdown_location_with_zero_width_dropped() -> None:
    # Zero-width formatting chars (U+200B etc.) hide content from
    # visual inspection. Drop them so the rendered cell shows the
    # real identifier the lint output is referring to.
    out = format_violations(
        [_v(location="public.use​rs")], format="markdown"
    )
    assert "public.users" in out
    assert "​" not in out


def test_markdown_location_with_tab_escaped() -> None:
    # Tabs render as variable-width whitespace in GFM. Escape so
    # the column boundary stays visible and the rendered text
    # matches the actual identifier.
    out = format_violations(
        [_v(location="public.a\tcol")], format="markdown"
    )
    assert "public.a\\tcol" in out
    # No raw tab in the table section.
    table_section = out.split("**Summary:**")[0]
    assert "\t" not in table_section


def test_markdown_location_well_formed_uses_backticks_unchanged() -> None:
    # The fast-path: a well-formed location renders inside
    # backticks just like before the hardening. Pin so a future
    # tightening of `safe_location` doesn't accidentally introduce
    # escape sequences for benign input.
    out = format_violations(
        [_v(location="public.invoices.audit_writes")], format="markdown"
    )
    assert "`public.invoices.audit_writes`" in out
    # And no stray backslashes appear next to the well-formed name.
    table_rows = [
        line for line in out.splitlines() if line.startswith("| ❌")
    ]
    assert "\\" not in table_rows[0].split("audit_writes")[0]


def test_markdown_location_newline_escape_does_not_double_escape() -> None:
    # safe_location turns `\n` into the two characters `\n` (backslash
    # + n). The markdown formatter intentionally skips `_escape_cell`'s
    # backslash doubling for the location field, so the rendered text
    # shows `\n` (one backslash, one n) — not `\\n` (two backslashes,
    # which would render as the literal two-char text "\\n" in a code
    # span and be misleading). Pin both halves of the contract.
    out = format_violations(
        [_v(location="public.a\nb")], format="markdown"
    )
    assert "public.a\\nb" in out
    # NOT double-escaped — `\\nb` with two backslashes would mean
    # `\\` doubled by `_escape_cell` got applied on top.
    assert "public.a\\\\nb" not in out
