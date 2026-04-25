"""Human-readable text output."""
from __future__ import annotations

from collections import Counter

from pgrls.violations import Severity, Violation

_SEVERITY_LABEL: dict[Severity, str] = {
    "error": "ERROR",
    "warning": "WARN ",
    "info": "INFO ",
}


def format_text(violations: list[Violation]) -> str:
    if not violations:
        return "pgrls: no issues found.\n"

    lines: list[str] = []
    for v in violations:
        loc = v.location or "<schema>"
        lines.append(
            f"  {_SEVERITY_LABEL[v.severity]}  {v.rule_id}  {loc}\n"
            f"         {v.message}"
        )

    counts: Counter[Severity] = Counter(v.severity for v in violations)
    parts: list[str] = []
    for sev in ("error", "warning", "info"):
        n = counts.get(sev, 0)  # type: ignore[arg-type]
        if n:
            parts.append(f"{n} {sev}{'s' if n != 1 else ''}")
    summary = ", ".join(parts) or "0 issues"

    body = "\n\n".join(lines)
    return f"{body}\n\npgrls: {summary}.\n"
