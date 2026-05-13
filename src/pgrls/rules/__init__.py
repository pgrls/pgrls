"""Rule protocol and registry.

Every built-in rule (SEC001-SEC013, PERF001-PERF002, HYG001-HYG002,
VIEW001-VIEW004) is registered lazily on the first call to
`default_registry()` or `all_rules()`. When a new rule lands, add its
import + `registry.register(...)` call to `_build_default_registry()`
below.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pgrls.model import Schema
from pgrls.violations import ALL_SEVERITIES, Severity, Violation

__all__ = [
    "Rule",
    "RuleRegistry",
    "all_rules",
    "default_registry",
]


@runtime_checkable
class Rule(Protocol):
    id: str
    severity: Severity
    title: str

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]: ...


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        # `@runtime_checkable Protocol`'s `isinstance` only verifies
        # that the named attributes exist — it does NOT check that
        # `severity` is a Severity Literal or that `check` is
        # callable. Validate the contract explicitly so a malformed
        # rule (typo'd severity, non-callable `check`, empty id,
        # missing attribute entirely) fails fast at registration
        # with a useful message instead of KeyError-ing inside
        # `is_at_or_above` or TypeError-ing inside `_run_rules` on
        # the first lint.
        rid = getattr(rule, "id", None)
        if not isinstance(rid, str) or not rid:
            raise TypeError(
                f"Rule.id must be a non-empty str, got "
                f"{type(rid).__name__}"
            )
        sev = getattr(rule, "severity", None)
        if sev not in ALL_SEVERITIES:
            raise TypeError(
                f"Rule {rid!r} severity {sev!r} is "
                f"not one of {ALL_SEVERITIES}"
            )
        title = getattr(rule, "title", None)
        if not isinstance(title, str) or not title:
            raise TypeError(
                f"Rule {rid!r} title must be a non-empty str"
            )
        if not callable(getattr(rule, "check", None)):
            raise TypeError(
                f"Rule {rid!r} must define a callable "
                "check(schema, options) method"
            )
        if rid in self._rules:
            raise ValueError(f"Rule {rid!r} is already registered")
        self._rules[rid] = rule

    def enabled(self, disabled_ids: list[str]) -> list[Rule]:
        skip = set(disabled_ids)
        return [r for rid, r in self._rules.items() if rid not in skip]


_DEFAULT_REGISTRY: RuleRegistry | None = None


def _build_default_registry() -> RuleRegistry:
    from pgrls.rules.hyg001 import HYG001
    from pgrls.rules.hyg002 import HYG002
    from pgrls.rules.perf001 import PERF001
    from pgrls.rules.perf002 import PERF002
    from pgrls.rules.sec001 import SEC001
    from pgrls.rules.sec002 import SEC002
    from pgrls.rules.sec003 import SEC003
    from pgrls.rules.sec004 import SEC004
    from pgrls.rules.sec005 import SEC005
    from pgrls.rules.sec006 import SEC006
    from pgrls.rules.sec007 import SEC007
    from pgrls.rules.sec008 import SEC008
    from pgrls.rules.sec009 import SEC009
    from pgrls.rules.sec010 import SEC010
    from pgrls.rules.sec011 import SEC011
    from pgrls.rules.sec012 import SEC012
    from pgrls.rules.sec013 import SEC013
    from pgrls.rules.view001 import VIEW001
    from pgrls.rules.view002 import VIEW002
    from pgrls.rules.view003 import VIEW003
    from pgrls.rules.view004 import VIEW004

    registry = RuleRegistry()
    registry.register(SEC001())
    registry.register(SEC002())
    registry.register(SEC003())
    registry.register(SEC004())
    registry.register(SEC005())
    registry.register(SEC006())
    registry.register(SEC007())
    registry.register(SEC008())
    registry.register(SEC009())
    registry.register(SEC010())
    registry.register(SEC011())
    registry.register(SEC012())
    registry.register(SEC013())
    registry.register(PERF001())
    registry.register(PERF002())
    registry.register(HYG001())
    registry.register(HYG002())
    registry.register(VIEW001())
    registry.register(VIEW002())
    registry.register(VIEW003())
    registry.register(VIEW004())
    return registry


def default_registry() -> RuleRegistry:
    """Return the registry of all built-in rules."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = _build_default_registry()
    return _DEFAULT_REGISTRY


def all_rules() -> list[Rule]:
    """Return every rule shipped with pgrls."""
    return default_registry().enabled(disabled_ids=[])
