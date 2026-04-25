"""Output formatters. Currently only `text` ships in v0.0.1.

JSON, SARIF, and Markdown formats are planned for a future release. Adding a
format = creating a sibling module and wiring it into `_FORMATTERS` here.
"""
from __future__ import annotations

from typing import Callable

from pgrls.formatters.text import format_text
from pgrls.violations import Violation

_FORMATTERS: dict[str, Callable[[list[Violation]], str]] = {
    "text": format_text,
}

SUPPORTED_FORMATS: tuple[str, ...] = tuple(_FORMATTERS.keys())


def format_violations(violations: list[Violation], *, format: str) -> str:
    if format not in _FORMATTERS:
        raise ValueError(
            f"Unknown output format {format!r}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    return _FORMATTERS[format](violations)
