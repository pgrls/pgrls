"""Output formatters.

`text` is the human-readable default. `json` is the machine-readable
output for CI integrations — its shape is documented in
`formatters/json.py`. SARIF and Markdown remain on the roadmap; adding
a format = creating a sibling module and wiring it into `_FORMATTERS`
here.
"""
from __future__ import annotations

from typing import Callable

from pgrls.formatters.json import format_json
from pgrls.formatters.text import format_text
from pgrls.violations import Violation

_FORMATTERS: dict[str, Callable[[list[Violation]], str]] = {
    "text": format_text,
    "json": format_json,
}

SUPPORTED_FORMATS: tuple[str, ...] = tuple(_FORMATTERS.keys())


def format_violations(violations: list[Violation], *, format: str) -> str:
    if format not in _FORMATTERS:
        raise ValueError(
            f"Unknown output format {format!r}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    return _FORMATTERS[format](violations)
