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
