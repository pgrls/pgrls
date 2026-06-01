"""Shared, format-agnostic helpers for the renderer family.

`pgrls coverage` / `report` / `perf` / `history` each grew a hand-written
`render_text` / `render_markdown` and a `_RENDERERS` / `render` dispatch
tail. The text-table width-and-ljust loop, the markdown heading/summary/
header/separator skeleton, the `n == 1` pluralization ternary, and the
dispatch tuple were copy-pasted verbatim across all four. They live here
now so the shape has one definition.

The HTML scaffold is intentionally *not* here — it lives in
`pgrls._html_common` alongside the timestamp helpers, because it carries
HTML-specific escaping concerns. This module is plain-text only.

Every helper is byte-for-byte faithful to the inlined code it replaces:
the text table still separates columns with two spaces and right-pads
each cell with `str.ljust`; the markdown table still emits `# heading`,
a blank line, the summary line, a blank line, then the `|header|` /
`|---|` rows. Callers keep building their own already-stringified rows
(including each module's own zero-as-dash glyph) and own
summary/caveat lines.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

_R = TypeVar("_R")


def pluralize(n: int, singular: str, plural: str | None = None) -> str:
    """`singular` when ``n == 1``, else `plural` (default ``singular + "s"``).

    Replaces the `noun = "x" if n == 1 else "xs"` ternary repeated across
    the renderers' summary lines. Returns the *noun only* (no count) so
    callers keep full control of the surrounding phrasing.
    """
    if n == 1:
        return singular
    return plural if plural is not None else singular + "s"


def render_text_table(
    headers: Sequence[str], rows: Sequence[Sequence[str]]
) -> list[str]:
    """Width-computed, two-space-separated, left-justified text table.

    Returns the header line followed by one line per row — *no* trailing
    blank line or summary (callers append those). Column width is
    ``max(len(header), max(len(cell)))`` per column, exactly as the four
    `render_text` functions computed inline; cells are right-padded with
    `str.ljust`. `rows` must already be stringified — including each
    module's own zero-as-dash glyph, which this helper never touches.

    `rows` is assumed non-empty (every caller guards the empty case with
    its own placeholder string before calling). Each row must have the
    same length as `headers`.
    """
    widths = [
        max(len(headers[i]), max(len(r[i]) for r in rows))
        for i in range(len(headers))
    ]
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    for r in rows:
        out.append("  ".join(r[i].ljust(widths[i]) for i in range(len(r))))
    return out


def markdown_table(
    *,
    heading: str,
    summary: str,
    header_row: str,
    separator_row: str,
    body_rows: Sequence[str],
) -> str:
    """The GFM heading / blank / summary / blank / table skeleton.

    Emits, joined by newlines with a single trailing newline:

    ```
    <heading>
    <blank>
    <summary>
    <blank>
    <header_row>
    <separator_row>
    <body_rows…>
    ```

    `header_row` / `separator_row` are the full `| … |` / `|---|` lines
    (column specs differ per module — alignment colons, count, labels —
    so the caller supplies them whole). `body_rows` are the already-built
    `| … |` data lines. Mirrors the inlined `out = [...]; ...; return
    "\\n".join(out) + "\\n"` shape every `render_markdown` used.
    """
    out = [heading, "", summary, "", header_row, separator_row]
    out.extend(body_rows)
    return "\n".join(out) + "\n"


def make_dispatcher(
    renderers: Mapping[str, Callable[[_R], str]],
) -> tuple[Callable[[_R, str], str], tuple[str, ...]]:
    """Build a ``(render, FORMATS)`` pair from a format→renderer map.

    Replaces the identical ``_RENDERERS`` dict + ``render()`` lookup +
    ``*_FORMATS = tuple(_RENDERERS)`` tail in coverage / report / perf /
    history. ``FORMATS`` preserves insertion order (Python dicts are
    ordered), so the user-facing `--format` choice list is unchanged.
    The returned ``render`` does the same ``renderers[output_format](x)``
    lookup — an unknown format raises ``KeyError`` exactly as before.
    """
    formats = tuple(renderers)

    def render(value: _R, output_format: str) -> str:
        return renderers[output_format](value)

    return render, formats
