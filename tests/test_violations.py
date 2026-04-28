from __future__ import annotations

import pytest

from pgrls.violations import (
    ALL_SEVERITIES,
    SEVERITY_ORDER,
    Severity,
    Violation,
    coerce_severity,
    is_at_or_above,
)


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


def test_all_severities_matches_severity_order_keys() -> None:
    # Single source of truth: ALL_SEVERITIES is the iteration
    # tuple for every consumer (Click choice, formatters, runtime
    # validators), and SEVERITY_ORDER is its dict-keyed twin used
    # for ordering. They must agree on members AND order — a
    # future "let's add a new severity" PR that updates one but
    # not the other would silently break `is_at_or_above` or
    # break the Click choice list.
    assert tuple(SEVERITY_ORDER.keys()) == ALL_SEVERITIES
    # SEVERITY_ORDER values are 0..len(ALL_SEVERITIES)-1.
    assert list(SEVERITY_ORDER.values()) == list(
        range(len(ALL_SEVERITIES))
    )


def test_coerce_severity_accepts_canonical_lowercase() -> None:
    for sev in ALL_SEVERITIES:
        assert coerce_severity(sev) == sev


def test_coerce_severity_normalizes_case() -> None:
    # Click's `case_sensitive=False` accepts `--fail-on ERROR`;
    # `coerce_severity` honors that contract so a programmatic
    # caller passing the same uppercase form doesn't crash deep
    # inside `is_at_or_above`.
    assert coerce_severity("ERROR") == "error"
    assert coerce_severity("Warning") == "warning"


def test_coerce_severity_rejects_invalid() -> None:
    # `cast(Severity, ...)` would silently accept this — the
    # whole point of `coerce_severity` is to fail fast at the
    # validation boundary instead.
    with pytest.raises(ValueError, match="not one of"):
        coerce_severity("CRITICAL")
    with pytest.raises(ValueError, match="not one of"):
        coerce_severity("")
