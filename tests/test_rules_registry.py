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
        assert "title" in str(exc) or "check" in str(exc) or "severity" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_every_default_rule_severity_is_a_valid_literal() -> None:
    # Anchor the Severity-Literal contract for every shipped rule.
    # Catches a future rule that declares `severity = "errorr"`
    # or otherwise drifts out of the canonical vocabulary — the
    # @runtime_checkable Protocol's isinstance check does NOT
    # validate Literal members, so this is the actual gate.
    from pgrls.violations import ALL_SEVERITIES

    for rule in all_rules():
        assert rule.severity in ALL_SEVERITIES, (
            f"{rule.id} severity {rule.severity!r} not in "
            f"{ALL_SEVERITIES}"
        )


def test_register_rejects_invalid_severity_literal() -> None:
    # @runtime_checkable Protocol's isinstance check passes a rule
    # whose severity is any string. The registry must catch the
    # invalid Literal at registration time.
    class _TypoRule:
        id: str = "TYPO001"
        severity: str = "errorr"  # typo: 'errorr' not 'error'
        title: str = "fake"

        def check(self, schema, options):
            return []

    registry = RuleRegistry()
    try:
        registry.register(_TypoRule())  # type: ignore[arg-type]
    except TypeError as exc:
        assert "errorr" in str(exc)
        assert "TYPO001" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_register_rejects_non_callable_check() -> None:
    # `@runtime_checkable Protocol` validates attribute existence,
    # not callability. A `check = 42` rule passes isinstance() but
    # crashes inside `_run_rules`. Catch this at registration.
    class _BadCheckRule:
        id: str = "BADCHECK"
        severity: str = "warning"
        title: str = "fake"
        check = 42  # not callable

    registry = RuleRegistry()
    try:
        registry.register(_BadCheckRule())  # type: ignore[arg-type]
    except TypeError as exc:
        assert "callable" in str(exc).lower()
        assert "BADCHECK" in str(exc)
    else:
        raise AssertionError("expected TypeError")


def test_register_rejects_empty_id() -> None:
    class _EmptyIdRule:
        id: str = ""
        severity: str = "warning"
        title: str = "fake"

        def check(self, schema, options):
            return []

    registry = RuleRegistry()
    try:
        registry.register(_EmptyIdRule())  # type: ignore[arg-type]
    except TypeError as exc:
        assert "id" in str(exc).lower()
    else:
        raise AssertionError("expected TypeError")


def test_register_rejects_empty_title() -> None:
    class _EmptyTitleRule:
        id: str = "EMPTYT"
        severity: str = "warning"
        title: str = ""

        def check(self, schema, options):
            return []

    registry = RuleRegistry()
    try:
        registry.register(_EmptyTitleRule())  # type: ignore[arg-type]
    except TypeError as exc:
        assert "title" in str(exc).lower()
    else:
        raise AssertionError("expected TypeError")
