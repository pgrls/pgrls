"""Violation and Severity types reported by rules.

Single source of truth for the severity vocabulary. Other modules
(`config`, `cli`, formatters, individual rules) import `Severity`
and `ALL_SEVERITIES` from here — adding a fourth severity in a
future release is a one-line edit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, get_args

__all__ = [
    "ALL_SEVERITIES",
    "SEVERITY_ORDER",
    "Severity",
    "Violation",
    "coerce_severity",
    "is_at_or_above",
]

Severity = Literal["error", "warning", "info"]

# Exhaustive list of valid severities, ordered most-to-least
# severe. Anything that needs to enumerate severities (Click choice
# list, runtime validators, formatters that iterate severities for
# count summaries) imports this instead of duplicating the tuple.
# Order is explicit (not derived from `get_args(Severity)`) — the
# `is_at_or_above` contract depends on it, and `Literal[...]` member
# order is a contract Python doesn't surface. The assert below pins
# both halves: the tuple covers every Literal member, and the
# Literal covers every tuple entry.
ALL_SEVERITIES: tuple[Severity, ...] = ("error", "warning", "info")
assert set(ALL_SEVERITIES) == set(get_args(Severity)), (
    "ALL_SEVERITIES must enumerate every Severity Literal member "
    "exactly once"
)
SEVERITY_ORDER: dict[Severity, int] = {
    sev: i for i, sev in enumerate(ALL_SEVERITIES)
}


def coerce_severity(value: str) -> Severity:
    """Validate and normalize a string into a Severity.

    Accepts case-insensitive input (`"ERROR"` → `"error"`) — Click
    has `case_sensitive=False` on the `--fail-on` choice and we
    honor that contract here too. Raises ValueError on any other
    input so a typo in a config file or programmatic API call
    surfaces at the validation boundary instead of as a KeyError
    deep inside `is_at_or_above`.
    """
    normalized = value.lower() if isinstance(value, str) else value
    if normalized not in ALL_SEVERITIES:
        raise ValueError(
            f"severity {value!r} is not one of {ALL_SEVERITIES}"
        )
    # The membership check narrows `normalized` to Severity; mypy
    # picks this up so an explicit `cast` would be a redundant
    # no-op. Defensive type-check still preserved at the boundary.
    return normalized


@dataclass(frozen=True)
class Violation:
    rule_id: str
    severity: Severity
    title: str
    message: str
    location: str | None  # qualified table name or policy id; None for schema-wide
    # Optional structured leaking-row counterexample, carried only by
    # `pgrls diff` loosened-predicate violations on the Z3 path (a
    # `{column: value}` row HEAD admits but BASE rejects). `compare=False`
    # keeps the frozen dataclass hashable despite the dict payload —
    # no current call site hashes raw Violations (baseline.py hashes a
    # finding_key tuple, pr_comment hashes rule_id), and excluding it
    # from __eq__/__hash__ preserves the prior equality semantics while
    # forestalling a latent `unhashable type: 'dict'` crash if a future
    # caller builds a `set[Violation]`.
    counterexample: dict[str, object] | None = field(
        default=None, compare=False, hash=False
    )

    def __post_init__(self) -> None:
        # Fold a case-variant of a known severity to its canonical form
        # ("ERROR" -> "error") so an extra (user-supplied) rule's casing
        # typo is treated as the real severity rather than as unknown.
        # A genuinely off-spec value is deliberately LEFT UNTOUCHED, not
        # rejected: formatters render it defensively (see the unknown-
        # severity formatter tests) and `is_at_or_above` fails closed on
        # it, so one off-spec finding degrades gracefully instead of
        # crashing the whole run. The dataclass is frozen, so assign via
        # object.__setattr__.
        if isinstance(self.severity, str):
            lowered = self.severity.lower()
            if lowered != self.severity and lowered in ALL_SEVERITIES:
                object.__setattr__(self, "severity", lowered)


def is_at_or_above(severity: Severity, threshold: Severity) -> bool:
    """True when `severity` is at least as severe as `threshold` (lower = more severe).

    `threshold` is always a validated Severity (a CLI choice / config
    value). `severity` comes off a Violation and may be off-spec when an
    extra (user) rule stamped a value outside ALL_SEVERITIES; rather than
    KeyError-ing the exit-code gate, treat an unknown severity as failing
    any threshold — a custom rule fired, so its finding counts instead of
    being silently dropped (fail closed).
    """
    rank = SEVERITY_ORDER.get(severity)
    if rank is None:
        return True
    return rank <= SEVERITY_ORDER[threshold]
