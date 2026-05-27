"""Tests for the `html` lint formatter.

The html formatter is intended for the "archive a lint result as a
standalone artifact" reading context — distinct from `pr-comment`
(Markdown for GitHub PR comments) and `markdown` (table for runbooks
and wikis). Embedded CSS, no external assets, ISO-Z timestamp,
escapable cells.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest

from pgrls.formatters import format_violations
from pgrls.formatters.html import format_html
from pgrls.violations import Violation


_FIXED_GEN = datetime(2026, 5, 27, 16, 0, 0, tzinfo=timezone.utc)


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    title: str = "RLS not enabled on table",
    message: str = "Table public.t has RLS disabled.",
    location: str | None = "public.t",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        message=message,
        location=location,
    )


# ──────────────────────────────────────────────────────────────────
# Self-contained document skeleton
# ──────────────────────────────────────────────────────────────────


def test_html_is_standalone_html5_document() -> None:
    out = format_html([_v()], generated_at=_FIXED_GEN)
    assert out.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in out
    assert '<meta charset="utf-8">' in out
    assert "<title>pgrls lint</title>" in out
    assert "<style>" in out
    assert "</html>" in out


def test_html_has_no_external_assets() -> None:
    out = format_html([_v()], generated_at=_FIXED_GEN)
    assert "<link" not in out
    assert "<script" not in out


def test_html_carries_iso_utc_timestamp() -> None:
    out = format_html([_v()], generated_at=_FIXED_GEN)
    assert "2026-05-27T16:00:00Z" in out


# ──────────────────────────────────────────────────────────────────
# Empty / non-empty cases
# ──────────────────────────────────────────────────────────────────


def test_html_empty_violations_renders_green_banner() -> None:
    out = format_html([], generated_at=_FIXED_GEN)
    assert "No findings" in out
    assert "net-good" in out
    # The empty-state placeholder row still renders so the table
    # frame stays consistent.
    assert "No violations to display" in out


def test_html_renders_one_row_per_violation() -> None:
    vs = [
        _v(rule_id="SEC001", location="public.a"),
        _v(rule_id="SEC001", location="public.b"),
        _v(rule_id="HYG001", severity="info", location="public.c"),
    ]
    out = format_html(vs, generated_at=_FIXED_GEN)
    body = re.search(r"<tbody>(.*?)</tbody>", out, flags=re.DOTALL)
    assert body is not None
    rows = re.findall(r"<tr class=", body.group(1))
    assert len(rows) == 3


def test_html_summary_band_has_chip_per_severity() -> None:
    vs = [
        _v(severity="error", rule_id="SEC001"),
        _v(severity="error", rule_id="SEC002"),
        _v(severity="warning", rule_id="SEC008"),
        _v(severity="info", rule_id="HYG001"),
    ]
    out = format_html(vs, generated_at=_FIXED_GEN)
    # `<strong>N</strong>&nbsp;<sev>s` for non-zero severities,
    # nothing for zero ones.
    assert "<strong>2</strong>&nbsp;errors" in out
    assert "<strong>1</strong>&nbsp;warning" in out  # singular
    assert "<strong>1</strong>&nbsp;info" in out  # info uses no `s`


# ──────────────────────────────────────────────────────────────────
# Severity colour + emoji
# ──────────────────────────────────────────────────────────────────


def test_html_each_severity_carries_distinct_emoji_and_class() -> None:
    vs = [
        _v(severity="error", rule_id="SEC001"),
        _v(severity="warning", rule_id="SEC008"),
        _v(severity="info", rule_id="HYG001"),
    ]
    out = format_html(vs, generated_at=_FIXED_GEN)
    # Row CSS classes encode severity for downstream targeting.
    assert 'class="row-error"' in out
    assert 'class="row-warning"' in out
    assert 'class="row-info"' in out
    # Per-row pill emoji.
    assert "❌" in out
    assert "⚠️" in out
    assert "ℹ️" in out


def test_html_unknown_severity_degrades_to_bullet_marker() -> None:
    # A future severity not in _SEVERITY_EMOJI must not crash —
    # mirror SEC017's defensive shape (pr-comment formatter handles
    # this same case).
    v = _v(severity="critical")
    out = format_html([v], generated_at=_FIXED_GEN)
    assert 'class="row-other"' in out
    assert 'class="pill sev-other"' in out
    # The summary band carries the unknown severity too.
    assert "• <strong>1</strong>&nbsp;critical" in out


# ──────────────────────────────────────────────────────────────────
# Rule link / location / message escaping
# ──────────────────────────────────────────────────────────────────


def test_html_rule_id_links_to_docs_rules_anchor() -> None:
    out = format_html([_v(rule_id="SEC033")], generated_at=_FIXED_GEN)
    assert (
        "docs/RULES.md#rule-sec033" in out
    ), "rule ID should link to docs/RULES.md anchor"


def test_html_diff_rule_links_to_agents_md_anchor() -> None:
    out = format_html(
        [_v(rule_id="DIFF_USING_TIGHTENED")],
        generated_at=_FIXED_GEN,
    )
    assert "AGENTS.md#diff-rules" in out


def test_html_none_location_renders_schema_wide_sentinel() -> None:
    out = format_html([_v(location=None)], generated_at=_FIXED_GEN)
    assert "(schema-wide)" in out


def test_html_escapes_special_chars_in_message() -> None:
    # SQL operators or future rules quoting Postgres error text
    # could carry `<`/`>`/`&`. Without escaping, those would inject
    # markup into the rendered page.
    out = format_html(
        [_v(message="Use `col1 <> col2` instead of `col = NULL`.")],
        generated_at=_FIXED_GEN,
    )
    assert "&lt;&gt;" in out
    # No literal `<>` in the rendered body.
    body = re.search(r"<tbody>(.*?)</tbody>", out, flags=re.DOTALL)
    assert body and "<>" not in body.group(1)


def test_html_escapes_special_chars_in_location() -> None:
    # Postgres quoted identifiers may contain `<`/`>`/`&`/`"`. Same
    # defence the diff/report/history HTML formatters apply.
    out = format_html(
        [_v(location='weird<name>&"')],
        generated_at=_FIXED_GEN,
    )
    assert "weird&lt;name&gt;&amp;&quot;" in out
    assert "<name>" not in out


def test_html_collapses_message_newlines_to_br() -> None:
    out = format_html(
        [_v(message="line one\nline two")],
        generated_at=_FIXED_GEN,
    )
    assert "line one<br>line two" in out


# ──────────────────────────────────────────────────────────────────
# Generated-at semantics
# ──────────────────────────────────────────────────────────────────


def test_html_accepts_injected_generated_at() -> None:
    fixed = datetime(2026, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
    out = format_html([_v()], generated_at=fixed)
    assert "2026-01-15T10:30:45Z" in out


def test_html_rejects_naive_generated_at() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        format_html([_v()], generated_at=datetime(2026, 1, 15, 10, 30))


def test_html_normalizes_non_utc_generated_at_to_utc() -> None:
    cet = timezone(timedelta(hours=1))
    out = format_html(
        [_v()],
        generated_at=datetime(2026, 1, 15, 11, 30, 45, tzinfo=cet),
    )
    assert "2026-01-15T10:30:45Z" in out  # CET 11:30 → UTC 10:30


# ──────────────────────────────────────────────────────────────────
# Dispatch
# ──────────────────────────────────────────────────────────────────


def test_html_is_registered_format() -> None:
    out = format_violations([_v()], format="html")
    assert "<!DOCTYPE html>" in out
    assert "pgrls lint" in out


def test_unknown_format_rejected_with_html_in_message() -> None:
    with pytest.raises(ValueError) as exc:
        format_violations([_v()], format="nonsense")
    # `html` should appear in the "Supported:" list so the error
    # message advertises the new format.
    assert "html" in str(exc.value)
