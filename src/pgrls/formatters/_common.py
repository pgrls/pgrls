"""Shared helpers for human-readable formatters (`text`, `markdown`,
`pr-comment`, `github`).

JSON and SARIF formatters handle `Violation.location` safely via
`json.dumps` escaping; they don't need anything from this module.
"""
from __future__ import annotations

import re


def gfm_inline_code(content: str) -> str:
    """Wrap `content` as a GFM inline-code span using the shortest
    delimiter run that can't be closed prematurely by backticks in
    the content.

    GFM rule (CommonMark 6.1): a backtick code span is delimited by
    a run of N backticks; the matching closer is also N backticks,
    and any shorter run inside the content renders as a literal
    backtick. So `` `a` `` works for content with no backticks, ` ```a``` `
    is needed for content containing two consecutive backticks, etc.
    Space padding (`` ` foo ` ``) is the GFM idiom that lets content
    start or end with a backtick — the renderer strips one space
    from each side before rendering literal content.

    Caller is responsible for any other escaping (pipe-table `|`,
    HTML `<`/`>`, etc.) — this helper only handles the backtick-run
    arithmetic.

    Shared between `markdown._location_cell` (table cell) and
    `pr_comment._safe_chip` (inline-code chip) so both formatters
    produce the same GFM-safe output for the same input.
    """
    if "`" not in content:
        return f"`{content}`"
    longest_run = max(
        (len(m) for m in re.findall(r"`+", content)),
        default=0,
    )
    wrapper = "`" * (longest_run + 1)
    return f"{wrapper} {content} {wrapper}"

# Sentinel shown by the text and markdown formatters when a
# non-`None` location collapses to `""` after `safe_location` drops
# every character (e.g. a location consisting entirely of zero-width
# formatting chars). Imported by both formatters and both formatter
# test files so the wording is changed in exactly one place.
EMPTY_OR_ZERO_WIDTH_SENTINEL = "(empty-or-zero-width)"

# Match characters that break line-oriented or table-oriented
# rendering. The character class is built from explicit \uXXXX
# escapes — no literal zero-width chars in the source — so editor
# tooling that strips invisible bytes (autoformat passes, terminal
# copy/paste through normalizers, locale-aware editors) can't
# silently delete part of the range and leave a gap.
#
# Members, in order:
#   * \x00-\x1f  — ASCII control chars (NUL through US). Includes
#     \n (0x0a), \r (0x0d), \t (0x09) which split lines / table
#     rows, plus rarer chars (BEL, VT, FF) that disrupt terminal
#     output.
#   * \x7f       — DEL (ASCII 127). Pre-emptive: most renderers
#     skip it silently, masking content.
#   * U+200B..U+200D — Zero-width space, non-joiner, joiner.
#     Invisible formatting chars commonly used for spoofing
#     identifiers.
#   * U+FEFF     — Byte order mark / zero-width no-break space.
#     Same risk; UTF-8 BOMs sometimes leak into name strings.
_UNSAFE_PATTERN = re.compile(
    "[\x00-\x1f\x7f\u200b-\u200d\ufeff]"
)

# Zero-width formatting chars that are dropped outright. They have
# no readable representation, so showing them as a `\xHH` escape
# would just lengthen the line without helping the operator find
# the offending content in their schema. Built from explicit \u
# escapes for the same anti-bit-rot reason as `_UNSAFE_PATTERN`.
_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\ufeff")


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
    code-span wrap but the markdown formatter switches to a
    double-backtick wrapper when it sees one — see `markdown._row`.
    Backslashes are common in regex hints elsewhere in the
    formatter pipeline and rewriting them here would prevent a
    future caller from passing a deliberately escaped string
    through.

    Edge case: a string composed entirely of zero-width chars
    (e.g. `chr(0x200B)`) collapses to `""`. Callers must check the
    result and choose their own fallback (the `text` and `markdown`
    formatters fall back to the `(schema-wide)` sentinel) — this
    helper's contract is strictly the rewrite, not display policy.
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
