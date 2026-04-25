from __future__ import annotations

from pgrls.formatters import format_violations
from pgrls.violations import Violation


def _v(rule_id: str = "SEC001", location: str | None = "public.users") -> Violation:
    return Violation(
        rule_id=rule_id,
        severity="error",
        title="RLS not enabled on table",
        message="Table public.users does not have row-level security enabled.",
        location=location,
    )


def test_text_zero_violations() -> None:
    out = format_violations([], format="text")
    assert "no issues" in out.lower()


def test_text_includes_rule_id_and_location() -> None:
    out = format_violations([_v()], format="text")
    assert "SEC001" in out
    assert "public.users" in out
    assert "error" in out.lower()


def test_text_summary_counts_by_severity() -> None:
    vs = [
        _v(rule_id="SEC001"),
        Violation(
            rule_id="SEC002",
            severity="warning",
            title="t",
            message="m",
            location="public.x",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "1 error" in out
    assert "1 warning" in out


def test_unknown_format_raises() -> None:
    try:
        format_violations([], format="yaml")
    except ValueError as exc:
        assert "yaml" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_text_location_none_uses_schema_fallback() -> None:
    out = format_violations([_v(location=None)], format="text")
    assert "<schema>" in out
    assert "SEC001" in out


def test_text_summary_pluralizes_for_multiple_violations() -> None:
    vs = [_v(rule_id="SEC001"), _v(rule_id="SEC001")]
    out = format_violations(vs, format="text")
    assert "2 errors" in out
    assert "1 error" not in out


def test_text_summary_with_all_three_severities() -> None:
    vs = [
        Violation(
            rule_id="SEC001", severity="error", title="t",
            message="m", location="public.a",
        ),
        Violation(
            rule_id="SEC002", severity="warning", title="t",
            message="m", location="public.b",
        ),
        Violation(
            rule_id="HYG001", severity="info", title="t",
            message="m", location="public.c",
        ),
    ]
    out = format_violations(vs, format="text")
    assert "1 error" in out
    assert "1 warning" in out
    assert "1 info" in out
