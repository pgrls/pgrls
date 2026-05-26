"""Tests for the `pr-comment` formatter.

The pr-comment formatter is intended for the GitHub PR comment
reading context — collapsible per-rule blocks, severity emoji, and
locations grouped per rule rather than flattened into a pipe table.

These tests cover the shape contract; they don't assert on every
HTML detail because GFM tolerates minor whitespace + ordering
variations. Each test pins one observable property.
"""
from __future__ import annotations

from pgrls.formatters import format_violations
from pgrls.formatters.pr_comment import format_pr_comment
from pgrls.violations import Violation


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    title: str = "RLS not enabled on table",
    message: str = "Table public.t has RLS disabled.",
    location: str = "public.t",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        message=message,
        location=location,
    )


# ──────────────────────────────────────────────────────────────────
# Empty / single / multi
# ──────────────────────────────────────────────────────────────────


def test_empty_emits_success_banner() -> None:
    out = format_pr_comment([])
    assert "## pgrls findings" in out
    assert "✅" in out
    assert "No issues found" in out


def test_single_violation_emits_one_block() -> None:
    out = format_pr_comment([_v()])
    assert out.startswith("## pgrls findings\n")
    assert "<details>" in out
    assert "</details>" in out
    # No multiplier suffix when count == 1
    assert "×1" not in out
    assert "(×" not in out


def test_multiple_findings_of_same_rule_collapse_into_one_block() -> (
    None
):
    out = format_pr_comment(
        [
            _v(location="public.a"),
            _v(location="public.b"),
            _v(location="public.c"),
        ]
    )
    # Three findings, one rule → one details block + ×3 count
    assert out.count("<details>") == 1
    assert "(×3)" in out
    # All three locations rendered as inline-code chips
    assert "`public.a`" in out
    assert "`public.b`" in out
    assert "`public.c`" in out


def test_findings_across_rules_emit_one_block_each() -> None:
    out = format_pr_comment(
        [
            _v(rule_id="SEC001", location="a"),
            _v(rule_id="SEC002", title="FORCE missing", location="b"),
        ]
    )
    assert out.count("<details>") == 2
    assert "SEC001" in out
    assert "SEC002" in out


# ──────────────────────────────────────────────────────────────────
# Severity rendering
# ──────────────────────────────────────────────────────────────────


def test_severity_emoji_in_summary_line() -> None:
    out = format_pr_comment(
        [
            _v(severity="error", rule_id="SEC001"),
            _v(severity="warning", rule_id="SEC002"),
            _v(severity="info", rule_id="HYG001"),
        ]
    )
    # Top-line summary breaks counts down per severity with emoji
    assert "❌ 1 error" in out
    assert "⚠️ 1 warning" in out
    assert "ℹ️ 1 info" in out


def test_top_line_summary_pluralises() -> None:
    out = format_pr_comment(
        [_v(severity="error"), _v(severity="error", rule_id="SEC002")]
    )
    assert "❌ 2 errors" in out


# ──────────────────────────────────────────────────────────────────
# Locations: edge cases
# ──────────────────────────────────────────────────────────────────


def test_none_location_renders_schema_wide_sentinel() -> None:
    out = format_pr_comment([_v(location=None)])
    assert "`(schema-wide)`" in out


def test_locations_with_backticks_are_escaped() -> None:
    out = format_pr_comment([_v(location="weird`name")])
    # GFM inline code uses doubled backticks for content containing
    # a backtick; we conservatively double-escape inner backticks
    assert "weird``name" in out


# ──────────────────────────────────────────────────────────────────
# Rule reference link
# ──────────────────────────────────────────────────────────────────


def test_lint_rule_links_to_docs_rules_md() -> None:
    out = format_pr_comment([_v(rule_id="SEC033")])
    assert (
        "docs/RULES.md#rule-sec033" in out
    ), "lint rule reference should point at docs/RULES.md anchor"


def test_diff_rule_links_to_agents_diff_rules() -> None:
    out = format_pr_comment([_v(rule_id="DIFF_USING_TIGHTENED")])
    assert "AGENTS.md#diff-rules" in out


# ──────────────────────────────────────────────────────────────────
# HTML escaping
# ──────────────────────────────────────────────────────────────────


def test_message_with_angle_brackets_is_escaped() -> None:
    # A future rule could carry SQL operators (<>, <=, >=). The
    # `<details>` body is HTML-ish; `<` would otherwise be parsed.
    out = format_pr_comment(
        [_v(message="Use `col1 <> col2` instead.")]
    )
    assert "&lt;&gt;" in out
    # Sanity: a literal `<` should NOT appear in the rendered body
    # (other than the `<details>`/`</details>` tags themselves).
    body = out.replace("<details>", "").replace("</details>", "")
    body = body.replace("<summary>", "").replace("</summary>", "")
    body = body.replace("<strong>", "").replace("</strong>", "")
    assert "<" not in body.replace("&lt;", "").replace("\n<", "")


# ──────────────────────────────────────────────────────────────────
# Format dispatch wiring
# ──────────────────────────────────────────────────────────────────


def test_pr_comment_is_a_registered_format() -> None:
    # Sanity check: the formatter is reachable via the
    # `format_violations` dispatch table that the CLI uses.
    out = format_violations([_v()], format="pr-comment")
    assert "## pgrls findings" in out


def test_unknown_format_rejected_with_pr_comment_in_message() -> None:
    import pytest

    with pytest.raises(ValueError) as exc:
        format_violations([_v()], format="nonsense")
    # `pr-comment` should appear in the "Supported:" list so the
    # error message advertises the new format to anyone debugging.
    assert "pr-comment" in str(exc.value)
