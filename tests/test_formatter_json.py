"""Unit tests for the JSON output formatter.

The JSON shape is the public CI contract. Pin it here; downstream
parsers (GitHub Actions, dashboards, etc.) treat the keys as stable
between releases.
"""
from __future__ import annotations

import json

from pgrls.formatters import format_violations
from pgrls.violations import Violation


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    location: str | None = "public.users",
    message: str = "Table public.users does not have row-level security enabled.",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title="RLS not enabled on table",
        message=message,
        location=location,
    )


def test_json_zero_violations_emits_empty_list_and_zero_summary() -> None:
    out = format_violations([], format="json")
    parsed = json.loads(out)
    assert parsed == {
        "violations": [],
        "summary": {
            "errors": 0,
            "warnings": 0,
            "infos": 0,
            "others": 0,
            "total": 0,
        },
    }


def test_json_serializes_each_field_per_violation() -> None:
    out = format_violations([_v()], format="json")
    parsed = json.loads(out)
    assert parsed["violations"][0] == {
        "rule_id": "SEC001",
        "severity": "error",
        "title": "RLS not enabled on table",
        "message": "Table public.users does not have row-level security enabled.",
        "location": "public.users",
    }


def test_json_location_none_serializes_as_null() -> None:
    # CI consumers should not have to special-case missing keys; we
    # always emit `location` and use JSON `null` for absent values.
    out = format_violations([_v(location=None)], format="json")
    parsed = json.loads(out)
    assert parsed["violations"][0]["location"] is None


def test_json_summary_counts_by_severity() -> None:
    vs = [
        _v(rule_id="SEC001", severity="error"),
        _v(rule_id="SEC002", severity="error"),
        _v(rule_id="PERF001", severity="warning"),
        _v(rule_id="SEC007", severity="info"),
    ]
    parsed = json.loads(format_violations(vs, format="json"))
    assert parsed["summary"] == {
        "errors": 2,
        "warnings": 1,
        "infos": 1,
        "others": 0,
        "total": 4,
    }


def test_json_summary_buckets_off_spec_severity_into_others() -> None:
    # An external rule plugin may emit a severity pgrls doesn't model
    # (e.g. "critical"). It must land in `others` so the four severity
    # buckets reconcile to total — never silently dropped, which would
    # make errors + warnings + infos < total.
    vs = [
        _v(rule_id="SEC001", severity="error"),
        _v(rule_id="X001", severity="critical"),
        _v(rule_id="X002", severity="blocker"),
    ]
    summary = json.loads(format_violations(vs, format="json"))["summary"]
    assert summary["errors"] == 1
    assert summary["others"] == 2
    assert (
        summary["errors"]
        + summary["warnings"]
        + summary["infos"]
        + summary["others"]
        == summary["total"]
        == 3
    )


def test_json_preserves_caller_order() -> None:
    # The formatter does not sort. Whatever order the caller passes is
    # the order in `violations[]`. Pin this so anyone introducing
    # sorting later does it deliberately.
    vs = [
        _v(rule_id="SEC003", location="public.c"),
        _v(rule_id="SEC001", location="public.a"),
        _v(rule_id="SEC002", location="public.b"),
    ]
    parsed = json.loads(format_violations(vs, format="json"))
    locations = [v["location"] for v in parsed["violations"]]
    assert locations == ["public.c", "public.a", "public.b"]


def test_json_output_ends_with_newline_for_shell_friendliness() -> None:
    # `pgrls lint --format json > out.json` and POSIX tools both prefer
    # a trailing newline. The text formatter ends with one; match.
    out = format_violations([], format="json")
    assert out.endswith("\n")


def test_json_output_is_pretty_printed() -> None:
    # Pretty-printed (indent=2) output is grep-friendly and human-
    # readable. Compact output can come later behind a flag if there's
    # demand. Pin the indentation so output stays stable for diffs.
    out = format_violations([_v()], format="json")
    assert "  " in out  # at least one indent level
    assert "\n" in out  # multi-line


def test_json_handles_special_characters_in_message() -> None:
    # Messages can contain quotes, newlines, and Unicode. json.dumps
    # handles all of this; just confirm the round-trip works.
    msg = 'Policy "p" references column \'gone\'\nwhich does not exist. ñ'
    out = format_violations([_v(message=msg)], format="json")
    parsed = json.loads(out)
    assert parsed["violations"][0]["message"] == msg


def test_json_top_level_keys_are_stable_contract() -> None:
    # Pin the public contract: top-level object has exactly these
    # two keys. Anyone adding fields should bump and document.
    out = format_violations([_v()], format="json")
    parsed = json.loads(out)
    assert set(parsed.keys()) == {"violations", "summary"}


def test_json_summary_keys_are_stable_contract() -> None:
    out = format_violations([], format="json")
    parsed = json.loads(out)
    assert set(parsed["summary"].keys()) == {
        "errors",
        "warnings",
        "infos",
        "others",
        "total",
    }


def test_json_violation_keys_are_stable_contract() -> None:
    out = format_violations([_v()], format="json")
    parsed = json.loads(out)
    assert set(parsed["violations"][0].keys()) == {
        "rule_id",
        "severity",
        "title",
        "message",
        "location",
    }


def test_json_violation_key_order_is_stable_contract() -> None:
    # The docstring on json.py promises a specific field order
    # (rule_id, severity, title, message, location). Today this
    # works because Python 3.7+ dicts are insertion-ordered and
    # the formatter constructs the violation dict literally in
    # that order. A future refactor that builds via `**kwargs` or
    # `dataclasses.asdict` would silently change byte output —
    # baseline-diff workflows would flap. Pin the order here.
    import re

    out = format_violations([_v()], format="json")
    keys_in_violation = re.findall(
        r'"(rule_id|severity|title|message|location)":', out
    )
    assert keys_in_violation == [
        "rule_id",
        "severity",
        "title",
        "message",
        "location",
    ]


def test_json_output_is_byte_stable_across_repeated_calls() -> None:
    # Two calls with identical inputs must produce byte-identical
    # output — baseline files / "diff vs last run" workflows
    # depend on it.
    inputs = [_v(), _v(rule_id="SEC002", severity="warning")]
    a = format_violations(inputs, format="json")
    b = format_violations(inputs, format="json")
    assert a == b


def test_json_severity_values_match_internal_literals() -> None:
    for sev in ("error", "warning", "info"):
        parsed = json.loads(
            format_violations([_v(severity=sev)], format="json")
        )
        assert parsed["violations"][0]["severity"] == sev
