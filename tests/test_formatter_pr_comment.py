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


def test_locations_with_backticks_use_wider_wrapper() -> None:
    # GFM rule: a code-span wrapper must be LONGER than any
    # backtick run inside the content. One inner backtick → 2-
    # backtick wrapper + space padding. The chip MUST actually
    # render as inline code, not bleed into literal text.
    out = format_pr_comment([_v(location="weird`name")])
    assert "`` weird`name ``" in out, (
        "wrapper must be wider than the inner backtick run, "
        "with space padding (GFM idiom)"
    )


def test_locations_with_multiple_backticks_use_even_wider_wrapper() -> None:
    # Two consecutive inner backticks → 3-backtick wrapper.
    out = format_pr_comment([_v(location="x``y")])
    assert "``` x``y ```" in out


def test_locations_within_a_rule_preserve_duplicates() -> None:
    # Two findings on the same location each get their own chip —
    # the formatter does NOT collapse duplicates. Pinning today's
    # behavior so a future change is a deliberate decision.
    out = format_pr_comment(
        [_v(location="public.t"), _v(location="public.t")]
    )
    assert out.count("`public.t`") == 2


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


def test_message_with_closing_details_tag_is_escaped() -> None:
    # A future extra rule could emit `</details>` in a message —
    # without escaping, that would prematurely close the
    # surrounding `<details>` block and break the comment layout.
    out = format_pr_comment(
        [_v(message="Avoid `</details>` in your DDL comments.")]
    )
    # The escaped form appears…
    assert "&lt;/details&gt;" in out
    # …and the only literal `</details>` is the block's own close
    # tag (one per rule block, one block here).
    assert out.count("</details>") == 1


def test_message_with_ampersand_escapes_to_amp() -> None:
    # If `&` were not escaped first, `A & B` next to a `<` rewrite
    # could produce `A &amp; B` getting re-escaped to `A &amp;amp; B`.
    # Pin the canonical single-escape pass.
    out = format_pr_comment([_v(message="Use A & B in clauses.")])
    assert "A &amp; B" in out
    assert "&amp;amp;" not in out


def test_empty_title_falls_back_to_rule_id() -> None:
    # The fixture forces an empty title; the summary line must
    # still carry the rule_id rather than a dangling em-dash.
    out = format_pr_comment([_v(rule_id="SEC050", title="")])
    assert "<strong>SEC050</strong> — SEC050" in out


def test_unknown_severity_degrades_to_neutral_bullet() -> None:
    # An extra rule's malformed severity (a `# type: ignore` cast,
    # or a future fourth level shipped before the emoji map is
    # updated) must not crash the formatter — degrade to "•" and
    # render the block.
    out = format_pr_comment([_v(severity="critical")])
    assert "<details>" in out
    # The block summary carries the fallback bullet rather than
    # KeyError-ing on the missing dict entry.
    assert "• <strong>SEC001</strong>" in out


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
