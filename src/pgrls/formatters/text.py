"""Human-readable text output."""
from __future__ import annotations

from collections import Counter

from pgrls.formatters._common import safe_location
from pgrls.violations import ALL_SEVERITIES, Severity, Violation

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
        # Sentinel matches the SARIF formatter's
        # `(schema-wide)` for cross-format consistency. Real
        # qualified names never contain parentheses, so the
        # placeholder is unambiguous.
        # `safe_location` keeps the line single — operator-supplied
        # identifiers can contain `\n` (legal in quoted Postgres
        # identifiers) which would otherwise split the row and
        # break line-anchored CI grep patterns like
        # `^  WARN \s+ SEC\d+\s+ <loc>$`. A location that's entirely
        # zero-width chars collapses to `""` after sanitization; in
        # that case the `(empty-or-zero-width)` sentinel surfaces
        # the fact that there WAS something at that location, just
        # nothing displayable.
        if not v.location:
            loc = "(schema-wide)"
        else:
            cleaned = safe_location(v.location)
            loc = cleaned if cleaned else "(empty-or-zero-width)"
        lines.append(
            f"  {_SEVERITY_LABEL[v.severity]}  {v.rule_id}  {loc}\n"
            f"         {v.message}"
        )

    counts: Counter[Severity] = Counter(v.severity for v in violations)
    parts: list[str] = []
    for sev in ALL_SEVERITIES:
        n = counts.get(sev, 0)
        if n:
            parts.append(f"{n} {sev}{'s' if n != 1 else ''}")
    summary = ", ".join(parts) or "0 issues"

    body = "\n\n".join(lines)
    return f"{body}\n\npgrls: {summary}.\n"
