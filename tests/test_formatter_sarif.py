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


def test_sarif_handles_location_none_with_schema_placeholder() -> None:
    # SARIF §3.27.12 says `locations` SHOULD be omitted when none
    # are known, but GitHub Code Scanning's upload endpoint rejects
    # results with an empty `locations` array. Synthesize a
    # `(schema-wide)` logicalLocation so a future schema-wide rule
    # that doesn't pin to a table or policy still produces an
    # ingestible SARIF document.
    out = format_violations([_v(location=None)], format="sarif")
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    locs = result["locations"]
    assert len(locs) == 1
    assert (
        locs[0]["logicalLocations"][0]["fullyQualifiedName"]
        == "(schema-wide)"
    )


def test_sarif_handles_empty_string_location_with_schema_placeholder() -> None:
    # R13 #6: Violation.location is `str | None`, so `""` is
    # representable (an extra/plugin rule may emit it). An empty-string
    # location is still effectively no location — an empty
    # `fullyQualifiedName` is GitHub-rejected just like a missing one —
    # so the guard must be falsy, not `is not None`, and must render the
    # same `(schema-wide)` sentinel the sibling formatters emit for `""`.
    out = format_violations([_v(location="")], format="sarif")
    result = json.loads(out)["runs"][0]["results"][0]
    assert (
        result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        == "(schema-wide)"
    )


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
    assert "docs/RULES.md" in rule["helpUri"]
    # helpUri uses `rule-sec001` to match an explicit
    # <a id="rule-sec001"></a> anchor in docs/RULES.md, not the
    # GitHub-slugified heading (which would include the title and
    # break on title rewording).
    assert rule["helpUri"].endswith("#rule-sec001")


def test_sarif_help_uri_for_diff_rules_routes_to_diff_section() -> None:
    """DIFF_* rule_ids (emitted by `pgrls diff` via the diff
    formatters' Change → Violation projection) don't have per-kind
    anchors in AGENTS.md. Without this routing, helpUri pointed at
    `#rule-diff_using_tightened` etc. — non-existent anchors that
    silently 404 in GitHub Code Scanning. v0.2.2 routes them to
    the shared `#diff-rules` anchor (defined just above the
    "## Diff" heading) so the user lands on the classification
    table that documents what the rule means.
    """
    diff_violation = Violation(
        rule_id="DIFF_USING_TIGHTENED",
        severity="info",
        title="Using Tightened",
        message="Test predicate change.",
        location="public.t.policy",
    )
    out = format_violations([diff_violation], format="sarif")
    parsed = json.loads(out)
    rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"].endswith("#diff-rules")
    # And lint rules continue to use their per-rule anchors:
    out2 = format_violations([_v()], format="sarif")
    rule2 = json.loads(out2)["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule2["helpUri"].endswith("#rule-sec001")


def test_sarif_rule_descriptor_name_is_rule_id_not_title() -> None:
    # SARIF §3.49.7 specifies `name` as an identifier (Pascal-ish,
    # no whitespace) — distinct from the prose `shortDescription`.
    # Emitting the title in `name` would confuse SARIF consumers
    # like CodeQL conventions and Sonar that treat the two fields
    # differently. Pin `name == rule_id`.
    out = format_violations([_v()], format="sarif")
    parsed = json.loads(out)
    rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["name"] == "SEC001"
    assert rule["shortDescription"]["text"] == "RLS not enabled on table"


def test_sarif_rule_descriptor_includes_default_configuration_level() -> None:
    # GitHub Code Scanning uses `defaultConfiguration.level` to
    # populate the rule list view. Without it, the UI shows
    # "Unknown severity" until a result fires. Pin presence and
    # the SARIF-level mapping.
    out = format_violations(
        [_v(severity="warning")], format="sarif"
    )
    parsed = json.loads(out)
    rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "warning"


def test_sarif_rule_descriptor_names_are_unique_across_descriptors() -> None:
    # SARIF §3.49.7 SHOULD: `name` unique across rule descriptors.
    # Putting rule_id in `name` makes uniqueness automatic; pin it
    # so a future change that puts the title back can't slip
    # duplicate-title rules past.
    vs = [
        _v(rule_id="SEC001", title="Same title"),
        _v(rule_id="SEC002", title="Same title"),
    ]
    out = format_violations(vs, format="sarif")
    parsed = json.loads(out)
    names = [
        r["name"] for r in parsed["runs"][0]["tool"]["driver"]["rules"]
    ]
    assert len(names) == len(set(names))


def test_sarif_handles_unicode_in_messages() -> None:
    msg = "Policy 'p' references column \"weird\" — ñ"
    out = format_violations([_v(message=msg)], format="sarif")
    parsed = json.loads(out)
    assert parsed["runs"][0]["results"][0]["message"]["text"] == msg


def test_sarif_severity_mapping_exhaustive_contract() -> None:
    # SARIF v2.1.0 levels: "error" | "warning" | "note" | "none".
    # pgrls's three severities map as follows; this is the public
    # contract for any tool that consumes pgrls's SARIF output
    # (e.g., GitHub Code Scanning treats "note" specifically).
    # Pin all three so a refactor flipping `info → "none"` fails.
    cases = [
        ("error", "error"),
        ("warning", "warning"),
        ("info", "note"),
    ]
    for severity, expected_sarif_level in cases:
        out = format_violations(
            [_v(severity=severity)], format="sarif"
        )
        parsed = json.loads(out)
        assert (
            parsed["runs"][0]["results"][0]["level"]
            == expected_sarif_level
        ), f"{severity} should map to {expected_sarif_level}"


def test_sarif_off_spec_severity_fails_closed_to_error() -> None:
    # CI / Code-Scanning path: an off-spec severity must not KeyError the
    # SARIF upload; map it to the most-visible "error" level (fail closed).
    out = format_violations([_v(severity="critical")], format="sarif")
    doc = json.loads(out)
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "error"
