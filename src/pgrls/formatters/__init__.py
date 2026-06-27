"""Output formatters.

`text` is the human-readable default. `json` is the machine-readable
output for generic CI integrations (shape documented in
`formatters/json.py`). `sarif` is SARIF v2.1.0 for GitHub Code
Scanning and similar aggregators (shape documented in
`formatters/sarif.py`). `markdown` is GitHub-flavored Markdown for
PR comments and rendered CI reports (shape documented in
`formatters/markdown.py`). `pr-comment` is a denser, grouped-by-
rule Markdown variant tuned for the GitHub PR review reading
context — collapsible blocks, severity emoji in the summary line
(shape documented in `formatters/pr_comment.py`). `github` emits
GitHub Actions workflow commands so findings show up as run
annotations (shape documented in `formatters/github.py`). `junit`
emits a JUnit XML report so findings surface in a CI run's test-
report UI (shape documented in `formatters/junit.py`).

Adding a format = creating a sibling module and wiring it into
`_FORMATTERS` here. The rule-link URL convention used by SARIF,
Markdown, and `pr-comment` (the helpUri / table anchors that point
into docs/RULES.md (lint rules) or AGENTS.md (DIFF_*)) must stay
synchronized — see the cross-reference comments in
`sarif._help_uri_for`, `markdown._rule_link`, and
`pr_comment._rule_link`.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pgrls.formatters.github import format_github
from pgrls.formatters.html import format_html
from pgrls.formatters.json import format_json
from pgrls.formatters.junit import format_junit
from pgrls.formatters.markdown import format_markdown
from pgrls.formatters.pr_comment import format_pr_comment
from pgrls.formatters.sarif import format_sarif
from pgrls.formatters.text import format_text
from pgrls.violations import Violation

_FORMATTERS: dict[str, Callable[[list[Violation]], str]] = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
    "markdown": format_markdown,
    "pr-comment": format_pr_comment,
    "github": format_github,
    "junit": format_junit,
    "html": format_html,
}

SUPPORTED_FORMATS: tuple[str, ...] = tuple(_FORMATTERS.keys())


def format_violations(
    violations: list[Violation],
    *,
    format: str,
    rationale_map: dict[str, str] | None = None,
    extra_json: dict[str, Any] | None = None,
) -> str:
    """Render `violations` in the requested output `format`.

    `rationale_map` is an optional `{rule_id: rationale_text}` dict
    used by `pgrls lint --explain` to append each rule's reference
    paragraph beneath its finding. Honoured by the text formatter
    only; every other format (json, sarif, markdown, github)
    ignores it to keep their output stable.

    `extra_json` is an optional dict of additive top-level keys to
    include in the JSON output (e.g. offline coverage signal). Only
    honoured by the json formatter; ignored by all other formats.
    """
    if format not in _FORMATTERS:
        raise ValueError(
            f"Unknown output format {format!r}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    if format == "text":
        return format_text(violations, rationale_map=rationale_map)
    if format == "json":
        return format_json(violations, extra=extra_json)
    return _FORMATTERS[format](violations)
