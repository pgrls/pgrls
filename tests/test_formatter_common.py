"""Unit tests for `pgrls.formatters._common.safe_location`.

Pins the helper's contract directly so a future refactor of the
text or markdown formatter (which exercise the helper indirectly)
can't drop or weaken a guarantee without a dedicated test failure.
"""
from __future__ import annotations

import pytest

from pgrls.formatters._common import (
    EMPTY_OR_ZERO_WIDTH_SENTINEL,
    safe_location,
)


def test_safe_location_empty_string_passes_through() -> None:
    # The fast-path short-circuit at the top of safe_location:
    # empty input returns empty output unchanged, no regex match
    # attempt. Pin the contract since the formatters distinguish
    # `""` (sentinel) from `None` (schema-wide) and the helper's
    # behavior matters for that branch.
    assert safe_location("") == ""


def test_safe_location_well_formed_passes_through_unchanged() -> None:
    # No control chars, no zero-width — fast-path returns input
    # byte-identical. Pin so a future refactor doesn't accidentally
    # introduce a copy / normalize pass on the common case.
    inputs = [
        "public.users",
        "public.users.tenant_isolation",
        "audit_writes",
        "my$schema.table_name",
        "schema with space.table",  # internal whitespace is fine
        "üñîçødé",  # extended Unicode passes through
    ]
    for s in inputs:
        assert safe_location(s) == s, s


def test_safe_location_newline_escaped_as_two_chars() -> None:
    # `\n` (one char) becomes literal `\n` (two chars: backslash + n).
    result = safe_location("a\nb")
    assert result == "a\\nb"
    assert len(result) == 4  # a, \, n, b


def test_safe_location_carriage_return_escaped() -> None:
    assert safe_location("a\rb") == "a\\rb"


def test_safe_location_tab_escaped() -> None:
    assert safe_location("a\tb") == "a\\tb"


@pytest.mark.parametrize(
    "control_char, expected_escape",
    [
        ("\x00", "\\x00"),  # NUL
        ("\x07", "\\x07"),  # BEL
        ("\x08", "\\x08"),  # BS
        ("\x0b", "\\x0b"),  # VT
        ("\x0c", "\\x0c"),  # FF
        ("\x1b", "\\x1b"),  # ESC
        ("\x1f", "\\x1f"),  # US
        ("\x7f", "\\x7f"),  # DEL
    ],
)
def test_safe_location_other_control_chars_hex_escaped(
    control_char: str, expected_escape: str
) -> None:
    # Every ASCII control char outside the \n/\r/\t set gets
    # `\xHH` lowercase-hex representation.
    result = safe_location(f"a{control_char}b")
    assert expected_escape in result
    # The raw control char must NOT appear in the output.
    assert control_char not in result


@pytest.mark.parametrize(
    "zero_width",
    [
        "\u200b",  # ZWSP
        "\u200c",  # ZWNJ
        "\u200d",  # ZWJ
        "\ufeff",  # BOM
    ],
)
def test_safe_location_zero_width_dropped(zero_width: str) -> None:
    # Zero-width formatting chars have no readable representation
    # and are commonly used to spoof identifiers. Drop them silently.
    assert safe_location(f"a{zero_width}b") == "ab"
    assert zero_width not in safe_location(f"a{zero_width}b")


def test_safe_location_only_zero_width_collapses_to_empty() -> None:
    # Caller (formatter) is expected to check for the empty result
    # and substitute `EMPTY_OR_ZERO_WIDTH_SENTINEL`. The helper's
    # contract is purely the rewrite — display policy lives at the
    # call site.
    assert safe_location("\u200b\u200c\u200d\ufeff") == ""


def test_safe_location_pipes_pass_through() -> None:
    # Pipes are a Markdown-table concern, not a line-integrity one.
    # The helper leaves them alone; the markdown formatter handles
    # the escape after safe_location returns.
    assert safe_location("a|b") == "a|b"


def test_safe_location_backslashes_pass_through() -> None:
    # The helper doesn't double backslashes — that would re-escape
    # its own visible-escape output (`\n` → `\\n`) and produce
    # misleading rendered text in the markdown code-span path.
    assert safe_location("a\\b") == "a\\b"


def test_safe_location_backticks_pass_through() -> None:
    # The markdown formatter has its own code-span-wrapper logic
    # for backticks (switches to a longer-than-internal-run wrap).
    # The helper leaves them alone.
    assert safe_location("a`b") == "a`b"


def test_safe_location_mixed_input_handled_correctly() -> None:
    # Pin the interaction of multiple unsafe chars in one input:
    # newline + zero-width + tab + control char. Each gets the
    # right treatment independently; order is preserved.
    result = safe_location("a\nb\u200bc\td\x07e")
    assert result == "a\\nbc\\td\\x07e"


def test_safe_location_long_well_formed_input_unchanged() -> None:
    # Stress the fast-path: a long well-formed string must not
    # gain extra characters or be normalized.
    s = "public." + "x" * 1000 + ".policy_name"
    assert safe_location(s) == s


def test_empty_or_zero_width_sentinel_is_stable_string() -> None:
    # Both formatters and both test files import this constant.
    # Pin the string value so a future renaming hits this test
    # first and the operator changes it in one place.
    assert EMPTY_OR_ZERO_WIDTH_SENTINEL == "(empty-or-zero-width)"
