from __future__ import annotations

from pgrls.formatters import format_violations
from pgrls.violations import Violation


def _v(rule_id: str = "SEC001", location: str | None = "public.users") -> Violation:
    return Violation(
        rule_id=rule_id,
        severity="error",
        title="RLS not enabled on table",
        message="Table public.users does not have row-level security enabled.",
        location=location,
    )


def test_text_zero_violations() -> None:
    out = format_violations([], format="text")
    assert "no issues" in out.lower()


def test_text_includes_rule_id_and_location() -> None:
    out = format_violations([_v()], format="text")
    assert "SEC001" in out
    assert "public.users" in out
    assert "error" in out.lower()


def test_text_summary_counts_by_severity() -> None:
    vs = [
        _v(rule_id="SEC001"),
        Violation(
            rule_id="SEC002",
            severity="warning",
            title="t",
            message="m",
            location="public.x",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "1 error" in out
    assert "1 warning" in out


def test_unknown_format_raises() -> None:
    try:
        format_violations([], format="yaml")
    except ValueError as exc:
        assert "yaml" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_text_location_none_uses_schema_fallback() -> None:
    out = format_violations([_v(location=None)], format="text")
    assert "<schema>" in out
    assert "SEC001" in out


def test_text_summary_pluralizes_for_multiple_violations() -> None:
    vs = [_v(rule_id="SEC001"), _v(rule_id="SEC001")]
    out = format_violations(vs, format="text")
    assert "2 errors" in out
    assert "1 error" not in out


def test_text_summary_with_all_three_severities() -> None:
    vs = [
        Violation(
            rule_id="SEC001", severity="error", title="t",
            message="m", location="public.a",
        ),
        Violation(
            rule_id="SEC002", severity="warning", title="t",
            message="m", location="public.b",
        ),
        Violation(
            rule_id="HYG001", severity="info", title="t",
            message="m", location="public.c",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "1 error" in out
    assert "1 warning" in out
    assert "1 info" in out


def test_text_preserves_caller_order() -> None:
    # The formatter does not sort. Whatever order the caller passes is
    # the order that appears in the body. Pin this so anyone introducing
    # sorting later does it deliberately.
    vs = [
        Violation(rule_id="SEC003", severity="error", title="t",
                  message="m3", location="public.c"),
        Violation(rule_id="SEC001", severity="error", title="t",
                  message="m1", location="public.a"),
        Violation(rule_id="SEC002", severity="error", title="t",
                  message="m2", location="public.b"),
    ]
    out = format_violations(vs, format="text")
    i_c = out.index("public.c")
    i_a = out.index("public.a")
    i_b = out.index("public.b")
    assert i_c < i_a < i_b


def test_text_summary_orders_severities_error_then_warning_then_info() -> None:
    vs = [
        Violation(rule_id="HYG001", severity="info", title="t",
                  message="m", location="public.c"),
        Violation(rule_id="SEC001", severity="error", title="t",
                  message="m", location="public.a"),
        Violation(rule_id="SEC002", severity="warning", title="t",
                  message="m", location="public.b"),
    ]
    out = format_violations(vs, format="text")
    summary_line = out.strip().splitlines()[-1]
    i_err = summary_line.index("error")
    i_warn = summary_line.index("warning")
    i_info = summary_line.index("info")
    assert i_err < i_warn < i_info


def test_text_summary_skips_zero_count_severities() -> None:
    # Only errors present — summary must not say "0 warnings, 0 info".
    vs = [_v(rule_id="SEC001")]
    out = format_violations(vs, format="text")
    summary_line = out.strip().splitlines()[-1]
    assert "warning" not in summary_line
    assert "info" not in summary_line


def test_text_includes_message_body_per_violation() -> None:
    vs = [
        Violation(
            rule_id="SEC001", severity="error", title="t",
            message="distinctive_message_content_xyz", location="public.a",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "distinctive_message_content_xyz" in out


def test_text_warning_label_is_padded_to_align_columns() -> None:
    # The label width is fixed across severities so output columns line
    # up. Pin the visible widths so output stays grep-friendly.
    err = format_violations([_v(rule_id="SEC001")], format="text")
    warn = format_violations(
        [Violation(rule_id="SEC001", severity="warning", title="t",
                   message="m", location="public.a")],
        format="text",
    )
    info = format_violations(
        [Violation(rule_id="SEC001", severity="info", title="t",
                   message="m", location="public.a")],
        format="text",
    )
    # All three start the body with two leading spaces + 5-char label.
    assert "  ERROR  " in err
    assert "  WARN   " in warn
    assert "  INFO   " in info


def test_text_zero_violations_does_not_emit_summary_line() -> None:
    out = format_violations([], format="text")
    # No "pgrls: N error" line, just the friendly no-issues message.
    assert "no issues" in out.lower()
    assert "error" not in out.lower()
    assert "warning" not in out.lower()


def test_text_singular_versus_plural_summary() -> None:
    one = format_violations([_v(rule_id="SEC001")], format="text")
    assert "1 error" in one
    assert "1 errors" not in one  # no double 's'
    two = format_violations(
        [_v(rule_id="SEC001"), _v(rule_id="SEC001")], format="text"
    )
    assert "2 errors" in two


def test_text_handles_long_message_and_special_chars() -> None:
    msg = (
        "Policy 'p' references column \"weird name\" that doesn't exist. "
        "Use ALTER POLICY ... or DROP POLICY p ON public.t."
    )
    vs = [
        Violation(
            rule_id="HYG001", severity="error", title="t",
            message=msg, location="public.t.p",
        ),
    ]
    out = format_violations(vs, format="text")
    assert msg in out
    assert "public.t.p" in out


def test_unknown_format_message_lists_supported_formats() -> None:
    # `sarif` is on the roadmap but not yet shipping. Use a format
    # that's still unsupported so this test keeps exercising the
    # unknown-format error path.
    import pytest
    with pytest.raises(ValueError, match="text"):
        format_violations([], format="sarif")
