"""Markdown output for `pgrls lint`.

Designed to render cleanly in GitHub-flavored Markdown — paste into a
PR comment, drop into an issue template, or commit as a CI artifact.
The shape:

- An H2 heading (`## pgrls findings`) so the output composes into a
  larger document without leaking out of an existing H1 hierarchy.
- A pipe table with one row per violation: severity (with a leading
  emoji for at-a-glance scanning), rule_id (linked to its
  per-rule anchor in AGENTS.md), location, message. Pipes inside
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

The rule-link URL convention (`/blob/main/AGENTS.md#rule-<lower>` for
lint rules, `#diff-rules` for `DIFF_*`) is shared with the SARIF
formatter's `_help_uri_for`. Keep them in lockstep — a SARIF consumer
and a Markdown consumer pointing at different anchors for the same
rule_id is exactly the kind of subtle drift that surfaces only when
a reader follows the link.
"""
from __future__ import annotations

from collections import Counter

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
    severity = _SEVERITY_LABEL[v.severity]
    rule_link = _rule_link(v.rule_id)
    # Backtick the location so identifiers with mixed case or spaces
    # don't get auto-linked or re-rendered. Schema-wide findings
    # match the SARIF / text formatters' `(schema-wide)` sentinel
    # but italicize it so it visually distinguishes from a real
    # qualified name in the same column.
    location = f"`{v.location}`" if v.location else "_(schema-wide)_"
    message = _escape_cell(v.message)
    return f"| {severity} | {rule_link} | {location} | {message} |\n"


def _rule_link(rule_id: str) -> str:
    """Build the per-rule deep link to AGENTS.md.

    Mirrors the SARIF formatter's `_help_uri_for`: lint rule IDs get
    their own per-rule anchor (`#rule-sec001`), `DIFF_*` rule IDs
    share the `#diff-rules` heading anchor (the diff classification
    table documents all of them under one section). A URL change
    here MUST land in the SARIF helpUri at the same time.
    """
    if rule_id.startswith("DIFF_"):
        anchor = "diff-rules"
    else:
        anchor = f"rule-{rule_id.lower()}"
    return f"[{rule_id}]({_INFORMATION_URI}/blob/main/AGENTS.md#{anchor})"


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
