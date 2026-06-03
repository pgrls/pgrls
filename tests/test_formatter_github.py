"""Unit tests for `pgrls.formatters.github`.

Pin the GitHub Actions workflow-command shape: one `::error` /
`::warning` / `::notice` line per violation, the rule+location
title, the escaping rules for message and property text, the
schema-wide sentinel, and the empty-input → empty-output contract.
"""
from __future__ import annotations

from pgrls.formatters import format_violations
from pgrls.formatters._common import EMPTY_OR_ZERO_WIDTH_SENTINEL
from pgrls.formatters.github import format_github
from pgrls.violations import Violation


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    title: str = "RLS not enabled on table",
    message: str = "Table public.users does not have RLS enabled.",
    location: str | None = "public.users",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        message=message,
        location=location,
    )


def test_github_registered_as_a_format() -> None:
    from pgrls.formatters import SUPPORTED_FORMATS

    assert "github" in SUPPORTED_FORMATS


def test_github_empty_violations_emits_nothing() -> None:
    # A clean run produces no annotations — the exit code carries
    # the clean/dirty signal.
    assert format_violations([], format="github") == ""


def test_github_error_severity_uses_error_command() -> None:
    out = format_github([_v(severity="error")])
    assert out.startswith("::error ")


def test_github_warning_severity_uses_warning_command() -> None:
    out = format_github([_v(rule_id="SEC027", severity="warning")])
    assert out.startswith("::warning ")


def test_github_info_severity_uses_notice_command() -> None:
    # GitHub has no "info" level; pgrls info maps to ::notice.
    out = format_github([_v(rule_id="SEC007", severity="info")])
    assert out.startswith("::notice ")


def test_github_title_carries_rule_id_and_location() -> None:
    out = format_github(
        [_v(rule_id="SEC004", location="public.documents.p")]
    )
    assert "title=SEC004 public.documents.p::" in out


def test_github_message_is_the_command_body() -> None:
    out = format_github([_v(message="Anonymous clients see all rows.")])
    # rstrip the trailing terminator before checking the body tail.
    assert out.rstrip("\n").endswith("::Anonymous clients see all rows.")


def test_github_nonempty_output_ends_with_trailing_newline() -> None:
    # The final workflow command must be newline-terminated on
    # stdout — the CLI echoes with nl=False, matching the other
    # formatters which all end in "\n".
    out = format_github([_v()])
    assert out.endswith("\n")
    assert not out.endswith("\n\n")


def test_github_one_line_per_violation() -> None:
    out = format_github(
        [
            _v(rule_id="SEC001", severity="error"),
            _v(rule_id="SEC027", severity="warning"),
            _v(rule_id="SEC007", severity="info"),
        ]
    )
    # splitlines() ignores the trailing terminator newline.
    lines = out.splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("::error ")
    assert lines[1].startswith("::warning ")
    assert lines[2].startswith("::notice ")


def test_github_schema_wide_location_sentinel() -> None:
    out = format_github([_v(location=None)])
    assert "title=SEC001 (schema-wide)::" in out


def test_github_escapes_message_percent_and_newline() -> None:
    # `%` must be escaped first (so the `%` in `%0A` isn't doubled),
    # then CR/LF. A raw newline would otherwise terminate the
    # command and dump the rest of the message as plain log text.
    out = format_github([_v(message="50% off\nsecond line\r")])
    # Strip the trailing terminator the formatter appends, then take
    # the command body (everything after the second `::`).
    body = out.rstrip("\n").split("::", 2)[2]
    assert body == "50%25 off%0Asecond line%0D"
    # The message's own newline was escaped to %0A — no raw newline
    # survives in the body.
    assert "\n" not in body


def test_github_escapes_property_colon_and_comma_in_title() -> None:
    # `:` and `,` delimit the command header, so a quoted-identifier
    # location containing them must be property-escaped in the title.
    out = format_github([_v(location='public."a:b,c".p')])
    # The header is everything up to the `::` separator.
    header = out.split("::", 2)[1]
    assert "%3A" in header  # the colon
    assert "%2C" in header  # the comma
    # And the literal delimiters must NOT survive in the title.
    title = header.split("title=", 1)[1]
    assert ":" not in title
    assert "," not in title


def test_github_zero_width_only_location_uses_sentinel() -> None:
    out = format_github([_v(location="​‌")])
    assert EMPTY_OR_ZERO_WIDTH_SENTINEL in out


def test_github_via_format_violations_dispatch() -> None:
    # The public entry point routes "github" to the formatter
    # (and ignores rationale_map, which is text-only).
    out = format_violations(
        [_v()], format="github", rationale_map={"SEC001": "ignored"}
    )
    assert out.startswith("::error ")
    assert "ignored" not in out


def test_github_off_spec_severity_fails_closed_to_error() -> None:
    # CI annotation path: an off-spec severity must not KeyError; emit the
    # most-visible `::error` annotation (fail closed) so it still surfaces.
    out = format_github([_v(severity="critical")])
    assert out.startswith("::error ")
