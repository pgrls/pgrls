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
    assert "(schema-wide)" in out
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
    # Pick a format that's never been on the roadmap so the test
    # keeps exercising the unknown-format error path even as new
    # formats land. `xml` and `yaml` are the obvious pseudo-formats
    # users sometimes try; either is fine.
    import pytest
    with pytest.raises(ValueError, match="text"):
        format_violations([], format="xml")


# ---------------------------------------------------------------------------
# Hostile-input hardening (operator-controlled identifiers)
# ---------------------------------------------------------------------------


def test_text_location_with_newline_renders_single_line() -> None:
    # Postgres allows `\n` inside quoted identifiers
    # (`"weird\nname"`), so an attacker (or a confused dev) can
    # create a trigger whose name embeds a newline. The text
    # formatter must escape it so the violation row stays on a
    # single line — otherwise CI scripts grepping with
    # line-anchored patterns silently break.
    vs = [
        Violation(
            rule_id="SEC013",
            severity="warning",
            title="t",
            message="m",
            location="public.invoices.evil\nINJECTED",
        ),
    ]
    out = format_violations(vs, format="text")
    # The literal newline is gone from the location row.
    location_line = [
        ln for ln in out.splitlines() if "SEC013" in ln
    ][0]
    assert "evil\\nINJECTED" in location_line
    assert "INJECTED" in location_line
    # No bare-newline split: the rule_id, location, and any
    # injected content are all in one line.
    assert location_line.count("SEC013") == 1


def test_text_location_with_carriage_return_escaped() -> None:
    # `\r` alone (no `\n`) can hide content from naive grep:
    # `printf "first\rsecond" | cat` prints `second`, overwriting
    # `first`. Escape so the operator sees both halves.
    vs = [
        Violation(
            rule_id="SEC001",
            severity="error",
            title="t",
            message="m",
            location="public.a\rhidden",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "\\r" in out
    assert "hidden" in out
    # No bare CR remains.
    assert "\rhidden" not in out


def test_text_location_with_tab_escaped() -> None:
    # Tabs in identifiers shift downstream column alignment in
    # whitespace-delimited parsers. Escape so the output columns
    # stay aligned.
    vs = [
        Violation(
            rule_id="SEC001",
            severity="error",
            title="t",
            message="m",
            location="public.a\tcol",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "public.a\\tcol" in out
    # No literal tab remains in the location segment.
    location_line = [
        ln for ln in out.splitlines() if "SEC001" in ln
    ][0]
    assert "\t" not in location_line


def test_text_location_with_zero_width_dropped() -> None:
    # Zero-width formatting chars (U+200B etc.) hide content from
    # visual inspection. Drop them outright — leaving them in the
    # output would let a malicious identifier visually shadow a
    # well-known one (e.g. `users` vs `use​rs`).
    vs = [
        Violation(
            rule_id="SEC001",
            severity="error",
            title="t",
            message="m",
            location="public.use​rs",
        ),
    ]
    out = format_violations(vs, format="text")
    # The zero-width char is gone — what remains reads as `users`.
    assert "public.users" in out
    assert "​" not in out


def test_text_location_with_other_control_chars_hex_escaped() -> None:
    # ASCII control chars other than \n/\r/\t (e.g. BEL = 0x07,
    # DEL = 0x7F) are uncommon in identifiers but legal in quoted
    # form. Render them as `\xHH` so the operator sees what's
    # there. Pin BEL specifically since terminals beep on it,
    # which could be used to harass an operator scrolling the
    # output.
    vs = [
        Violation(
            rule_id="SEC001",
            severity="error",
            title="t",
            message="m",
            location="public.a\x07bell",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "\\x07" in out
    # The raw BEL byte is gone.
    assert "\x07" not in out


def test_text_location_well_formed_passes_through_unchanged() -> None:
    # The fast-path: no special chars, no rewrite. Pin so a
    # well-formed location renders byte-identical to pre-hardening
    # output (no perf regression on the common case).
    vs = [_v(rule_id="SEC013", location="public.invoices.audit_writes")]
    out = format_violations(vs, format="text")
    assert "public.invoices.audit_writes" in out
    # And the location segment doesn't gain stray escape chars.
    assert "\\" not in out.split("public.invoices.audit_writes")[1].split("\n")[0]
