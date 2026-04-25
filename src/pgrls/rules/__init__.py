"""Rule protocol and registry.

Rule discovery happens here. SEC001 is registered eagerly. When more rules land,
add their imports below.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pgrls.model import Schema
from pgrls.violations import Severity, Violation


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
        if rule.id in self._rules:
            raise ValueError(f"Rule {rule.id!r} is already registered")
        self._rules[rule.id] = rule

    def enabled(self, disabled_ids: list[str]) -> list[Rule]:
        skip = set(disabled_ids)
        return [r for rid, r in self._rules.items() if rid not in skip]


_DEFAULT_REGISTRY: RuleRegistry | None = None


def _build_default_registry() -> RuleRegistry:
    from pgrls.rules.sec001 import SEC001

    registry = RuleRegistry()
    registry.register(SEC001())
    return registry


def all_rules() -> list[Rule]:
    """Return every rule shipped with pgrls."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = _build_default_registry()
    return _DEFAULT_REGISTRY.enabled(disabled_ids=[])


def default_registry() -> RuleRegistry:
    """Return the registry of all built-in rules."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = _build_default_registry()
    return _DEFAULT_REGISTRY
