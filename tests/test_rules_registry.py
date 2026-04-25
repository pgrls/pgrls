from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules import Rule, RuleRegistry, all_rules
from pgrls.violations import Severity, Violation


class _FakeRule:
    id = "FAKE001"
    severity: Severity = "warning"
    title = "Fake rule for testing"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        return [
            Violation(
                rule_id=self.id,
                severity=self.severity,
                title=self.title,
                message="fake violation",
                location=None,
            )
        ]


def test_registry_register_and_lookup() -> None:
    registry = RuleRegistry()
    registry.register(_FakeRule())  # type: ignore[arg-type]
    rules = registry.enabled(disabled_ids=[])
    assert len(rules) == 1
    assert rules[0].id == "FAKE001"


def test_registry_disabled_filtered() -> None:
    registry = RuleRegistry()
    registry.register(_FakeRule())  # type: ignore[arg-type]
    assert registry.enabled(disabled_ids=["FAKE001"]) == []


def test_registry_rejects_duplicate_id() -> None:
    registry = RuleRegistry()
    registry.register(_FakeRule())  # type: ignore[arg-type]
    try:
        registry.register(_FakeRule())  # type: ignore[arg-type]
    except ValueError as exc:
        assert "FAKE001" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_default_registry_has_sec001() -> None:
    rules: list[Rule] = all_rules()
    ids = [r.id for r in rules]
    assert "SEC001" in ids


def test_violation_dataclass() -> None:
    v = Violation(
        rule_id="SEC001",
        severity="error",
        title="title",
        message="msg",
        location="public.foo",
    )
    assert v.rule_id == "SEC001"
    assert v.severity == "error"


def test_registry_rejects_non_rule_object() -> None:
    class _NotARule:
        id = "BAD001"
        # missing: severity, title, check

    registry = RuleRegistry()
    try:
        registry.register(_NotARule())  # type: ignore[arg-type]
    except TypeError as exc:
        assert "Rule" in str(exc)
    else:
        raise AssertionError("expected TypeError")
