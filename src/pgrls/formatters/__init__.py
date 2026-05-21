"""Output formatters.

`text` is the human-readable default. `json` is the machine-readable
output for generic CI integrations (shape documented in
`formatters/json.py`). `sarif` is SARIF v2.1.0 for GitHub Code
Scanning and similar aggregators (shape documented in
`formatters/sarif.py`). `markdown` is GitHub-flavored Markdown for
PR comments and rendered CI reports (shape documented in
`formatters/markdown.py`). `github` emits GitHub Actions workflow
commands so findings show up as run annotations (shape documented
in `formatters/github.py`).

Adding a format = creating a sibling module and wiring it into
`_FORMATTERS` here. The rule-link URL convention used by SARIF and
Markdown (the helpUri / table anchors that point into AGENTS.md)
must stay synchronized — see the cross-reference comments in
`sarif._help_uri_for` and `markdown._rule_link`.
"""
from __future__ import annotations

from collections.abc import Callable

from pgrls.formatters.github import format_github
from pgrls.formatters.json import format_json
from pgrls.formatters.markdown import format_markdown
from pgrls.formatters.sarif import format_sarif
from pgrls.formatters.text import format_text
from pgrls.violations import Violation

_FORMATTERS: dict[str, Callable[[list[Violation]], str]] = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
    "markdown": format_markdown,
    "github": format_github,
}

SUPPORTED_FORMATS: tuple[str, ...] = tuple(_FORMATTERS.keys())


def format_violations(
    violations: list[Violation],
    *,
    format: str,
    rationale_map: dict[str, str] | None = None,
) -> str:
    """Render `violations` in the requested output `format`.

    `rationale_map` is an optional `{rule_id: rationale_text}` dict
    used by `pgrls lint --explain` to append each rule's reference
    paragraph beneath its finding. Honoured by the text formatter
    only; the structured formats (json, sarif, markdown) ignore
    it to keep their schemas stable.
    """
    if format not in _FORMATTERS:
        raise ValueError(
            f"Unknown output format {format!r}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    if format == "text":
        return format_text(violations, rationale_map=rationale_map)
    return _FORMATTERS[format](violations)
