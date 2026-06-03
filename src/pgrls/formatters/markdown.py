"""Markdown output for `pgrls lint`.

Designed to render cleanly in GitHub-flavored Markdown — paste into a
PR comment, drop into an issue template, or commit as a CI artifact.
The shape:

- An H2 heading (`## pgrls findings`) so the output composes into a
  larger document without leaking out of an existing H1 hierarchy.
- A pipe table with one row per violation: severity (with a leading
  emoji for at-a-glance scanning), rule_id (linked to its
  per-rule anchor in docs/RULES.md), location, message. Pipes inside
  cells are escaped to `\\|` and embedded newlines become `<br>` so
  the table layout never breaks on adversarial message text.
- A summary line below the table.

Empty findings list emits a single line: `pgrls: no issues found.` —
matches the text formatter's clean-DB output verbatim so a one-liner
"if `pgrls: no issues found.` not in output, comment with the diff"
script works against either format.

Stable between releases of the same major-zero series; adding new
columns is a breaking change for consumers that parse the table, so
do it with a CHANGELOG note.

The rule-link URL convention (`/blob/main/docs/RULES.md#rule-<lower>` for
lint rules, `#diff-rules` for `DIFF_*`) is shared with the SARIF
formatter's `_help_uri_for`. Keep them in lockstep — a SARIF consumer
and a Markdown consumer pointing at different anchors for the same
rule_id is exactly the kind of subtle drift that surfaces only when
a reader follows the link.
"""
from __future__ import annotations

from collections import Counter

from pgrls.formatters._common import (
    EMPTY_OR_ZERO_WIDTH_SENTINEL,
    gfm_inline_code,
    safe_location,
)
from pgrls.violations import ALL_SEVERITIES, Severity, Violation

_SEVERITY_LABEL: dict[Severity, str] = {
    "error": "❌ error",
    "warning": "⚠️ warning",
    "info": "ℹ️ info",
}

_INFORMATION_URI = "https://github.com/pgrls/pgrls"


def format_markdown(violations: list[Violation]) -> str:
    if not violations:
        return "pgrls: no issues found.\n"

    rows = "".join(_row(v) for v in violations)

    counts: Counter[Severity] = Counter(v.severity for v in violations)
    parts: list[str] = []
    for sev in ALL_SEVERITIES:
        n = counts.get(sev, 0)
        if n:
            parts.append(f"{n} {sev}{'s' if n != 1 else ''}")
    # Off-spec severities (from an extra rule) appended after the known
    # ones, sorted, so the tally never silently drops a finding.
    for sev in sorted((s for s in counts if s not in ALL_SEVERITIES), key=str):
        n = counts[sev]
        parts.append(f"{n} {sev}{'s' if n != 1 else ''}")
    summary = ", ".join(parts)
    total = len(violations)

    return (
        "## pgrls findings\n"
        "\n"
        "| Severity | Rule | Location | Message |\n"
        "|---|---|---|---|\n"
        f"{rows}"
        "\n"
        f"**Summary:** {summary}. Total: {total}.\n"
    )


def _row(v: Violation) -> str:
    # Fail soft on an off-spec severity (the gate tolerates it): fall back
    # to the raw severity string rather than KeyError-ing the whole run.
    severity = _SEVERITY_LABEL.get(v.severity, str(v.severity))
    rule_link = _rule_link(v.rule_id)
    message = _escape_cell(v.message)
    return f"| {severity} | {rule_link} | {_location_cell(v.location)} | {message} |\n"


def _location_cell(location: str | None) -> str:
    """Render a `Violation.location` for the GFM table.

    Backtick the location so identifiers with mixed case or spaces
    don't get auto-linked or re-rendered. Schema-wide findings
    match the SARIF / text formatters' `(schema-wide)` sentinel
    but italicize it so it visually distinguishes from a real
    qualified name in the same column.

    `safe_location` strips / escapes newlines, tabs, and zero-width
    chars first so the table row stays intact even when a Postgres
    identifier carries `\\n` (legal inside a quoted identifier). The
    remaining `|` characters then get backslash-escaped manually —
    we deliberately skip `_escape_cell` because that helper doubles
    `\\` (correct for rule-author messages that contain literal
    backslashes, wrong for our own backslash-escaped representation
    of a newline, which would become a misleading `\\\\n` in the
    rendered cell). The cell-content is also a no-op for the well-
    formed case: `safe_location` short-circuits on clean input and
    the `.replace("|", "\\|")` does nothing.

    Two edge cases need special handling:

    * **Backticks inside the location.** Wrapping in single
      backticks `` `loc` `` would let an inner backtick close the
      code span early, leaving the rest of the cell as plain
      markdown (where `*`, `_`, `[`, etc. would re-render). The
      GFM rule for code spans is that the wrapper must be a run
      of backticks LONGER than any run inside the content — a
      cell with 2 consecutive `` `` `` requires a 3-backtick
      wrapper, and so on. The wrapper width here is computed as
      `(longest_run_inside + 1)`, with space padding so the
      content can also start or end with backticks. Pure-single-
      backtick path stays cheap: no inner backticks → 1-backtick
      wrapper, no padding (matches the well-formed common case).
    * **Empty after sanitization.** A location composed entirely
      of zero-width chars (e.g. `chr(0x200B)`) collapses to `""`
      once `safe_location` drops the formatting chars. Emitting
      `` ` ` `` (empty backtick pair) renders as a blank cell
      that's indistinguishable from `None`; instead, fall back
      to the `EMPTY_OR_ZERO_WIDTH_SENTINEL` so the operator sees
      there WAS something at that location, just nothing
      displayable.
    """
    if not location:
        return "_(schema-wide)_"
    clean = safe_location(location).replace("|", "\\|")
    if not clean:
        # The original location was non-empty but `safe_location`
        # dropped every character (e.g. all zero-width). Surface
        # this fact rather than rendering a silent blank cell.
        return f"_{EMPTY_OR_ZERO_WIDTH_SENTINEL}_"
    # Backtick-wrap delegated to the shared `gfm_inline_code` helper
    # so the markdown table cell and the pr-comment inline-code chip
    # produce identical output for identical input.
    return gfm_inline_code(clean)


def _rule_link(rule_id: str) -> str:
    """Build the per-rule deep link.

    Mirrors the SARIF formatter's `_help_uri_for`. Lint rule IDs
    point at the canonical per-rule reference in `docs/RULES.md`;
    `DIFF_*` rule IDs share the `#diff-rules` heading anchor in
    `AGENTS.md` (the diff classification table documents all of
    them under one section). A URL change here MUST land in the
    SARIF helpUri at the same time.
    """
    if rule_id.startswith("DIFF_"):
        return (
            f"[{rule_id}]({_INFORMATION_URI}"
            "/blob/main/AGENTS.md#diff-rules)"
        )
    return (
        f"[{rule_id}]({_INFORMATION_URI}"
        f"/blob/main/docs/RULES.md#rule-{rule_id.lower()})"
    )


def _escape_cell(text: str) -> str:
    """Make `text` safe to embed in a Markdown pipe-table cell.

    Pipe characters split cells; raw newlines end the row entirely;
    backslashes that aren't already escapes get reinterpreted by
    some renderers. The replacements here are the minimal set that
    keeps the table layout intact for any input — `pgrls` violation
    messages today are plain ASCII English with the rare backtick,
    but the formatter shouldn't make assumptions a future rule's
    message can't break.
    """
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "<br>")
    )
