"""Unit tests for the SARIF output formatter.

SARIF (https://docs.oasis-open.org/sarif/sarif/v2.1.0/) is the
standard JSON shape consumed by GitHub Code Scanning, Azure DevOps,
and other static-analysis aggregators. The shape matters — the keys
are mandated by the spec — so the tests pin the structural contract
rather than free-form output.
"""
from __future__ import annotations

import json

from pgrls import __version__
from pgrls.formatters import format_violations
from pgrls.violations import Violation

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/"
    "sarif-schema-2.1.0.json"
)


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    location: str | None = "public.users",
    message: str = "Table public.users does not have row-level security enabled.",
    title: str = "RLS not enabled on table",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        message=message,
        location=location,
    )


def test_sarif_has_top_level_version_and_schema() -> None:
    out = format_violations([_v()], format="sarif")
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"
    assert parsed["$schema"] == _SARIF_SCHEMA


def test_sarif_emits_one_run_with_pgrls_as_the_tool_driver() -> None:
    out = format_violations([_v()], format="sarif")
    parsed = json.loads(out)
    assert len(parsed["runs"]) == 1
    driver = parsed["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pgrls"
    assert driver["version"] == __version__
    assert driver["informationUri"].startswith("https://")


def test_sarif_includes_rule_descriptors_for_each_unique_rule_id() -> None:
    vs = [_v(rule_id="SEC001"), _v(rule_id="SEC003"), _v(rule_id="SEC001")]
    out = format_violations(vs, format="sarif")
    parsed = json.loads(out)
    rule_ids = [r["id"] for r in parsed["runs"][0]["tool"]["driver"]["rules"]]
    # Deduplicated and order-preserved.
    assert rule_ids == ["SEC001", "SEC003"]


def test_sarif_severity_to_level_mapping() -> None:
    # SARIF levels: "error" | "warning" | "note" (no "info").
    # pgrls maps info → note.
    vs = [
        _v(rule_id="SEC001", severity="error"),
        _v(rule_id="PERF001", severity="warning"),
        _v(rule_id="SEC007", severity="info"),
    ]
    out = format_violations(vs, format="sarif")
    parsed = json.loads(out)
    levels = [r["level"] for r in parsed["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_sarif_result_has_ruleid_and_message() -> None:
    out = format_violations([_v()], format="sarif")
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert result["ruleId"] == "SEC001"
    assert result["message"]["text"] == (
        "Table public.users does not have row-level security enabled."
    )


def test_sarif_result_uses_logical_location_with_fully_qualified_name() -> None:
    # Locations are database objects, not files. SARIF's
    # `logicalLocations[].fullyQualifiedName` is the right shape;
    # GitHub Code Scanning displays it in the UI.
    out = format_violations(
        [_v(location="public.users.tenant_isolation")], format="sarif"
    )
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert result["locations"][0]["logicalLocations"][0][
        "fullyQualifiedName"
    ] == "public.users.tenant_isolation"


def test_sarif_handles_location_none() -> None:
    # Schema-level diagnostics (no specific table/policy) emit the
    # result without a location entry. SARIF allows results with no
    # locations.
    out = format_violations([_v(location=None)], format="sarif")
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert result.get("locations", []) == []


def test_sarif_zero_violations_emits_valid_empty_run() -> None:
    out = format_violations([], format="sarif")
    parsed = json.loads(out)
    run = parsed["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_output_ends_with_newline_for_shell_friendliness() -> None:
    out = format_violations([], format="sarif")
    assert out.endswith("\n")


def test_sarif_output_is_pretty_printed() -> None:
    out = format_violations([_v()], format="sarif")
    assert "  " in out
    assert "\n" in out


def test_sarif_rule_descriptor_includes_short_description_and_help_uri() -> None:
    out = format_violations([_v()], format="sarif")
    parsed = json.loads(out)
    rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == "RLS not enabled on table"
    assert "AGENTS.md" in rule["helpUri"]
    assert "sec001" in rule["helpUri"].lower()


def test_sarif_handles_unicode_in_messages() -> None:
    msg = "Policy 'p' references column \"weird\" — ñ"
    out = format_violations([_v(message=msg)], format="sarif")
    parsed = json.loads(out)
    assert parsed["runs"][0]["results"][0]["message"]["text"] == msg
