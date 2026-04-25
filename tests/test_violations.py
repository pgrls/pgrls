from __future__ import annotations

from pgrls.violations import SEVERITY_ORDER, Severity, Violation, is_at_or_above


def test_severity_order_strictly_descending() -> None:
    assert SEVERITY_ORDER["error"] < SEVERITY_ORDER["warning"]
    assert SEVERITY_ORDER["warning"] < SEVERITY_ORDER["info"]


def test_is_at_or_above_same_severity() -> None:
    for sev in ("error", "warning", "info"):
        sev_typed: Severity = sev  # type: ignore[assignment]
        assert is_at_or_above(sev_typed, sev_typed) is True


def test_is_at_or_above_more_severe() -> None:
    assert is_at_or_above("error", "warning") is True
    assert is_at_or_above("error", "info") is True
    assert is_at_or_above("warning", "info") is True


def test_is_at_or_above_less_severe() -> None:
    assert is_at_or_above("info", "warning") is False
    assert is_at_or_above("info", "error") is False
    assert is_at_or_above("warning", "error") is False


def test_violation_all_fields_set() -> None:
    v = Violation(
        rule_id="SEC001",
        severity="error",
        title="title",
        message="msg",
        location="public.foo",
    )
    assert v.rule_id == "SEC001"
    assert v.severity == "error"
    assert v.title == "title"
    assert v.message == "msg"
    assert v.location == "public.foo"


def test_violation_location_can_be_none() -> None:
    v = Violation(
        rule_id="SEC100",
        severity="warning",
        title="schema-wide finding",
        message="msg",
        location=None,
    )
    assert v.location is None
