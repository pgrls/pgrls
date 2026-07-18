"""Tests for the GitLab Code Quality (CodeClimate JSON) formatter.

Pins the shape GitLab CI's `artifacts:reports:codequality` ingests: a
JSON array of issue objects, each with description / check_name /
fingerprint / severity / location{path, lines.begin}, plus the
severity mapping, the stable-fingerprint contract, and the schema-wide
sentinel — mirroring the SARIF formatter's location/severity handling.
"""
from __future__ import annotations

import json

import pytest

from pgrls.formatters import SUPPORTED_FORMATS, format_violations
from pgrls.formatters.gitlab import format_gitlab
from pgrls.violations import Violation


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    message: str = "Table public.users has RLS disabled.",
    location: str = "public.users",
    title: str = "Missing RLS",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        message=message,
        location=location,
    )


def _report(violations: list[Violation]) -> list[dict]:
    out = format_gitlab(violations)
    assert out.endswith("\n")  # trailing newline like the sibling JSON formats
    return json.loads(out)


# --- structure -------------------------------------------------------------


def test_emits_json_array_with_required_codeclimate_fields() -> None:
    (item,) = _report([_v()])
    # GitLab reads exactly these keys; every one must be present.
    assert set(item) == {
        "description",
        "check_name",
        "fingerprint",
        "severity",
        "location",
    }
    assert item["description"] == "Table public.users has RLS disabled."
    assert item["check_name"] == "SEC001"
    assert item["location"] == {
        "path": "public.users",
        "lines": {"begin": 1},
    }
    assert isinstance(item["fingerprint"], str) and item["fingerprint"]


def test_empty_input_is_empty_array() -> None:
    assert format_gitlab([]) == "[]\n"
    assert _report([]) == []


def test_one_object_per_violation_preserving_order() -> None:
    vs = [_v(location="public.a"), _v(location="public.b"), _v(location="public.c")]
    report = _report(vs)
    assert [i["location"]["path"] for i in report] == [
        "public.a",
        "public.b",
        "public.c",
    ]


# --- severity mapping ------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected",
    [("error", "critical"), ("warning", "major"), ("info", "info")],
)
def test_severity_maps_to_gitlab_vocabulary(severity: str, expected: str) -> None:
    (item,) = _report([_v(severity=severity)])
    assert item["severity"] == expected


def test_off_spec_severity_fails_closed_to_critical() -> None:
    # An extra rule with an off-spec severity must not KeyError the whole
    # CI report; it maps to the most visible level, like the SARIF formatter.
    (item,) = _report([_v(severity="bogus")])
    assert item["severity"] == "critical"


# --- location / sentinel ---------------------------------------------------


def test_empty_location_uses_schema_wide_sentinel() -> None:
    (item,) = _report([_v(location="")])
    assert item["location"]["path"] == "(schema-wide)"
    assert item["location"]["lines"] == {"begin": 1}


def test_policy_qualified_location_is_the_path() -> None:
    (item,) = _report([_v(location="public.orders.tenant_policy")])
    assert item["location"]["path"] == "public.orders.tenant_policy"


# --- fingerprint contract --------------------------------------------------


def test_fingerprint_is_stable_across_calls() -> None:
    # GitLab tracks new-vs-resolved by fingerprint, so the same finding must
    # hash identically on every run.
    v = _v()
    assert _report([v])[0]["fingerprint"] == _report([v])[0]["fingerprint"]


def test_fingerprint_is_order_independent() -> None:
    # Reordering findings must not change any fingerprint (else every finding
    # looks "new" after an unrelated finding appears/disappears).
    a, b = _v(location="public.a"), _v(location="public.b")
    fp_a1 = next(i for i in _report([a, b]) if i["location"]["path"] == "public.a")
    fp_a2 = next(i for i in _report([b, a]) if i["location"]["path"] == "public.a")
    assert fp_a1["fingerprint"] == fp_a2["fingerprint"]


def test_fingerprint_distinguishes_distinct_findings() -> None:
    report = _report([
        _v(rule_id="SEC001", location="public.a"),
        _v(rule_id="SEC001", location="public.b"),  # different location
        _v(rule_id="SEC002", location="public.a"),  # different rule
        _v(rule_id="SEC001", location="public.a", message="different message"),
    ])
    fps = [i["fingerprint"] for i in report]
    assert len(set(fps)) == len(fps)


def test_fingerprint_is_sha256_hex() -> None:
    (item,) = _report([_v()])
    fp = item["fingerprint"]
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


# --- json hygiene ----------------------------------------------------------


def test_non_ascii_is_preserved_not_escaped() -> None:
    # ensure_ascii=False, matching the sarif/json/snapshot JSON contract.
    (item,) = _report([_v(message="policy références auth.uid() — leaké")])
    assert "références" in item["description"]
    assert "\\u" not in json.dumps(item["description"], ensure_ascii=False)


# --- registry / dispatch ---------------------------------------------------


def test_gitlab_is_a_supported_format() -> None:
    assert "gitlab" in SUPPORTED_FORMATS


def test_reachable_through_format_violations_dispatch() -> None:
    vs = [_v()]
    assert format_violations(vs, format="gitlab") == format_gitlab(vs)


# --- CLI integration (offline --sql-file, no DB) ---------------------------


def test_lint_format_gitlab_cli_writes_clean_report(tmp_path) -> None:
    """`pgrls lint --format gitlab --output` writes a clean CodeClimate JSON
    file GitLab CI can ingest — the pgrls diagnostics go to stderr, not into
    the report file — and the RLS-off table surfaces as a `critical` finding."""
    from click.testing import CliRunner

    from pgrls.cli import main

    sql = tmp_path / "schema.sql"
    sql.write_text("CREATE TABLE public.users (id int);\n", encoding="utf-8")
    report = tmp_path / "gl-code-quality.json"

    result = CliRunner().invoke(
        main,
        [
            "lint",
            "--sql-file",
            str(sql),
            "--format",
            "gitlab",
            "--output",
            str(report),
        ],
    )
    # SEC001 (RLS off) fires → exit 1 (a finding at/above the default fail-on).
    assert result.exit_code == 1, result.output
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert isinstance(payload, list) and payload
    (sec001,) = [i for i in payload if i["check_name"] == "SEC001"]
    assert sec001["severity"] == "critical"
    assert sec001["location"] == {"path": "public.users", "lines": {"begin": 1}}
