"""Shared helpers for human-readable formatters (`text`, `markdown`).

JSON and SARIF formatters handle `Violation.location` safely via
`json.dumps` escaping; they don't need anything from this module.
"""
from __future__ import annotations

import re

# Match characters that break line-oriented or table-oriented
# rendering: ASCII control chars (0x00-0x1F, including \n / \r /
# \t which split rows), DEL (0x7F), and the four zero-width
# unicode formatting chars commonly used for spoofing identifiers.
# Postgres allows any of these inside a quoted-identifier form
# (`"weird\nname"`), so operator-supplied names that flow into
# `Violation.location` can in fact carry them.
_UNSAFE_PATTERN = re.compile(r"[\x00-\x1F\x7F​-‍﻿]")

# The four zero-width formatting chars worth dropping outright:
# ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D), BOM / ZWNBSP (U+FEFF).
# They have no readable representation, so showing them as an
# escape sequence would just lengthen the line without helping
# the operator find the offending content in their schema.
_ZERO_WIDTH = frozenset("​‌‍﻿")


def safe_location(text: str) -> str:
    """Make `text` safe to embed in single-line human-readable output.

    Postgres allows any character inside a quoted identifier
    (`"weird\\nname"`, `"  spaced  "`, `"tab\\there"`), so table /
    policy / trigger names that surface in `Violation.location` can
    carry newlines, tabs, and zero-width formatting chars. Those
    break:

    * Line-oriented CI grep patterns — a `\\n` in a name splits the
      output row into two lines, so `^  WARN \\s+ SEC\\d+\\s+ <loc>$`
      no longer anchors.
    * GFM pipe-table layouts — a raw `\\n` ends the row early and
      the next cell starts on a new line.
    * Visual inspection — zero-width chars hide content from
      whoever's reading the lint output.

    This helper rewrites the problematic chars with visible escape
    text so the location renders on a single line and shows the
    operator exactly what's in the name. Locations without any of
    these characters pass through unchanged — including the full
    set of unqualified Postgres identifiers (letters, digits, `_`,
    `$`) and the standard qualified forms (`schema.table`,
    `schema.table.policy_name`).

    Rewrite rules:

    * `\\n` → literal `\\n` text (backslash + n, two characters)
    * `\\r` → literal `\\r` text
    * `\\t` → literal `\\t` text
    * Other ASCII control chars (0x00-0x1F minus the above, plus
      0x7F) → `\\xHH` hex escape
    * Zero-width formatting chars (U+200B, U+200C, U+200D, U+FEFF)
      → dropped silently — they have no visible representation, so
      showing them as text would just lengthen the line for no
      clarity gain.

    Backticks, pipes, and backslashes are NOT rewritten here.
    Pipes are a Markdown-table concern that the markdown formatter
    handles separately; backticks visually disrupt the markdown
    code-span wrap but don't break the table structure; backslashes
    are common in regex hints elsewhere in the message stream and
    rewriting them here would prevent a future caller from passing
    a deliberately escaped string through.
    """
    if not text:
        return text
    if not _UNSAFE_PATTERN.search(text):
        return text

    out: list[str] = []
    for ch in text:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch in _ZERO_WIDTH:
            pass
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)
