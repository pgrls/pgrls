"""Rule protocol and registry.

Every built-in rule (SEC001-SEC041, PERF001-PERF005, HYG001-HYG004,
VIEW001-VIEW004) is registered lazily on the first call to
`default_registry()` or `all_rules()`. When a new rule lands, add its
import + `registry.register(...)` call to `_build_default_registry()`
below.

## Extending pgrls with project-specific rules

A project can ship additional rules — closed-source, internal, or
just experimental — without forking. Add `[lint].extra_rules` to
`pgrls.toml`:

    [lint]
    extra_rules = ["mycompany.pgrls_rules"]

Each named module must expose a `RULES` sequence of `Rule`-protocol
objects:

    # mycompany/pgrls_rules/__init__.py
    from .mycompany_001 import MyCompany001

    RULES = [MyCompany001()]

`load_extra_rules()` (below) is the loader — used by
`pgrls.cli._run_rules` to merge extras into the per-invocation
registry. See `docs/RULE_AUTHORING.md` for the rule-authoring
walkthrough; the same Rule shape that built-ins use applies here.
"""
from __future__ import annotations

import importlib
from typing import Any, Iterable, Protocol, runtime_checkable

from pgrls.model import Schema
from pgrls.violations import ALL_SEVERITIES, Severity, Violation

__all__ = [
    "ExtraRulesError",
    "Rule",
    "RuleRegistry",
    "all_rules",
    "default_registry",
    "load_extra_rules",
]


class ExtraRulesError(Exception):
    """Raised when `[lint].extra_rules` fails to load.

    Message names the failing entry and the specific failure mode
    (import error, missing `RULES` attribute, non-Rule item, etc.)
    so a config typo doesn't fail silently with rules just not
    firing.
    """


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
    from pgrls.rules.hyg003 import HYG003
    from pgrls.rules.hyg004 import HYG004
    from pgrls.rules.perf001 import PERF001
    from pgrls.rules.perf002 import PERF002
    from pgrls.rules.perf003 import PERF003
    from pgrls.rules.perf004 import PERF004
    from pgrls.rules.perf005 import PERF005
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
    from pgrls.rules.sec014 import SEC014
    from pgrls.rules.sec015 import SEC015
    from pgrls.rules.sec016 import SEC016
    from pgrls.rules.sec017 import SEC017
    from pgrls.rules.sec018 import SEC018
    from pgrls.rules.sec019 import SEC019
    from pgrls.rules.sec020 import SEC020
    from pgrls.rules.sec021 import SEC021
    from pgrls.rules.sec022 import SEC022
    from pgrls.rules.sec023 import SEC023
    from pgrls.rules.sec024 import SEC024
    from pgrls.rules.sec025 import SEC025
    from pgrls.rules.sec026 import SEC026
    from pgrls.rules.sec027 import SEC027
    from pgrls.rules.sec028 import SEC028
    from pgrls.rules.sec029 import SEC029
    from pgrls.rules.sec030 import SEC030
    from pgrls.rules.sec031 import SEC031
    from pgrls.rules.sec032 import SEC032
    from pgrls.rules.sec033 import SEC033
    from pgrls.rules.sec034 import SEC034
    from pgrls.rules.sec035 import SEC035
    from pgrls.rules.sec036 import SEC036
    from pgrls.rules.sec037 import SEC037
    from pgrls.rules.sec038 import SEC038
    from pgrls.rules.sec039 import SEC039
    from pgrls.rules.sec040 import SEC040
    from pgrls.rules.sec041 import SEC041
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
    registry.register(SEC014())
    registry.register(SEC015())
    registry.register(SEC016())
    registry.register(SEC017())
    registry.register(SEC018())
    registry.register(SEC019())
    registry.register(SEC020())
    registry.register(SEC021())
    registry.register(SEC022())
    registry.register(SEC023())
    registry.register(SEC024())
    registry.register(SEC025())
    registry.register(SEC026())
    registry.register(SEC027())
    registry.register(SEC028())
    registry.register(SEC029())
    registry.register(SEC030())
    registry.register(SEC031())
    registry.register(SEC032())
    registry.register(SEC033())
    registry.register(SEC034())
    registry.register(SEC035())
    registry.register(SEC036())
    registry.register(SEC037())
    registry.register(SEC038())
    registry.register(SEC039())
    registry.register(SEC040())
    registry.register(SEC041())
    registry.register(PERF001())
    registry.register(PERF002())
    registry.register(PERF003())
    registry.register(PERF004())
    registry.register(PERF005())
    registry.register(HYG001())
    registry.register(HYG002())
    registry.register(HYG003())
    registry.register(HYG004())
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


def load_extra_rules(module_paths: Iterable[str]) -> list[Rule]:
    """Import the listed modules and return their declared `RULES`.

    Each `module_paths` entry is a Python dotted module path
    (e.g. `"mycompany.pgrls_rules"`). For each one:

      1. The module is imported via `importlib.import_module`.
         `ImportError` is wrapped in `ExtraRulesError` with the
         offending dotted path included.
      2. The module must expose a `RULES` attribute. The attribute
         must be iterable; we accept lists, tuples, or any iterable.
         Missing-attribute and non-iterable surfaces both raise
         `ExtraRulesError` with the offending module named.
      3. Each item in `RULES` must implement the `Rule` Protocol —
         a non-empty string `id`, a valid `Severity` (`severity`),
         a non-empty string `title`, and a callable `check`. The
         per-item shape is validated here AND again at
         registry-`register()` time so the same constraint applies
         to built-ins and extras alike.

    Returns an empty list if `module_paths` is empty. Does not
    deduplicate: if the same module is listed twice, every rule
    in its `RULES` list is returned twice — the downstream registry
    will refuse the duplicate ID with a clear error.

    Caller is responsible for handling the `Rule.id` collision case
    (built-in vs extra, or extra-vs-extra) — typically by passing
    the returned rules into a fresh `RuleRegistry` whose
    `register()` raises on duplicate IDs.
    """
    out: list[Rule] = []
    for dotted in module_paths:
        if not isinstance(dotted, str) or not dotted:
            raise ExtraRulesError(
                f"[lint].extra_rules entry must be a non-empty "
                f"string (got {dotted!r}); use a dotted Python "
                f'module path like "mycompany.pgrls_rules"'
            )
        try:
            module = importlib.import_module(dotted)
        except ImportError as exc:
            raise ExtraRulesError(
                f"[lint].extra_rules: cannot import {dotted!r} "
                f"({exc}). Verify the package is installed in the "
                "same environment as pgrls."
            ) from exc

        rules_attr = getattr(module, "RULES", None)
        if rules_attr is None:
            raise ExtraRulesError(
                f"[lint].extra_rules: module {dotted!r} does not "
                "expose a `RULES` attribute. Define it as a "
                "sequence of Rule-protocol objects — see "
                "docs/RULE_AUTHORING.md for the rule shape."
            )
        try:
            rules_iter = list(rules_attr)
        except TypeError as exc:
            raise ExtraRulesError(
                f"[lint].extra_rules: {dotted!r}.RULES must be "
                f"iterable (got {type(rules_attr).__name__})"
            ) from exc

        for index, rule in enumerate(rules_iter):
            # `runtime_checkable` `isinstance` only verifies the
            # attribute names exist; it does NOT check that they
            # carry the right shape. Validate explicitly so a
            # malformed extra fails at load time with a useful
            # message rather than crashing inside the rule walk.
            rid = getattr(rule, "id", None)
            if not isinstance(rid, str) or not rid:
                raise ExtraRulesError(
                    f"[lint].extra_rules: {dotted!r}.RULES[{index}] "
                    "is not a valid Rule — `id` must be a non-empty "
                    f"string (got {rid!r})"
                )
            sev = getattr(rule, "severity", None)
            if sev not in ALL_SEVERITIES:
                raise ExtraRulesError(
                    f"[lint].extra_rules: {dotted!r}.RULES[{index}] "
                    f"({rid!r}) has invalid severity {sev!r}; expected "
                    f"one of {ALL_SEVERITIES}"
                )
            title = getattr(rule, "title", None)
            if not isinstance(title, str) or not title:
                raise ExtraRulesError(
                    f"[lint].extra_rules: {dotted!r}.RULES[{index}] "
                    f"({rid!r}) has empty or non-string title"
                )
            if not callable(getattr(rule, "check", None)):
                raise ExtraRulesError(
                    f"[lint].extra_rules: {dotted!r}.RULES[{index}] "
                    f"({rid!r}) must define a callable "
                    "check(schema, options) method"
                )
            out.append(rule)
    return out
