"""Output formatters.

`text` is the human-readable default. `json` is the machine-readable
output for generic CI integrations (shape documented in
`formatters/json.py`). `sarif` is SARIF v2.1.0 for GitHub Code
Scanning and similar aggregators (shape documented in
`formatters/sarif.py`). `markdown` is GitHub-flavored Markdown for
PR comments and rendered CI reports (shape documented in
`formatters/markdown.py`).

Adding a format = creating a sibling module and wiring it into
`_FORMATTERS` here. The rule-link URL convention used by SARIF and
Markdown (the helpUri / table anchors that point into AGENTS.md)
must stay synchronized — see the cross-reference comments in
`sarif._help_uri_for` and `markdown._rule_link`.
"""
from __future__ import annotations

from collections.abc import Callable

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
}

SUPPORTED_FORMATS: tuple[str, ...] = tuple(_FORMATTERS.keys())


def format_violations(violations: list[Violation], *, format: str) -> str:
    if format not in _FORMATTERS:
        raise ValueError(
            f"Unknown output format {format!r}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    return _FORMATTERS[format](violations)
