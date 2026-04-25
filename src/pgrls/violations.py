"""Violation and Severity types reported by rules."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["error", "warning", "info"]
SEVERITY_ORDER: dict[Severity, int] = {"error": 0, "warning": 1, "info": 2}


@dataclass(frozen=True)
class Violation:
    rule_id: str
    severity: Severity
    title: str
    message: str
    location: str | None  # qualified table name or policy id; None for schema-wide


def is_at_or_above(severity: Severity, threshold: Severity) -> bool:
    """True when `severity` is at least as severe as `threshold` (lower = more severe)."""
    return SEVERITY_ORDER[severity] <= SEVERITY_ORDER[threshold]
