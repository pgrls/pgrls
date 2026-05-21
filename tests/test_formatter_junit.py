"""Unit tests for `pgrls.formatters.junit`.

Pin the JUnit XML shape: one `<testcase>` per finding under a single
`pgrls` suite, classname = rule id, name = "<rule id> <location>",
`<failure type=severity message=title>` with the full message as
text, aggregate counts, the empty-suite clean run, the schema-wide
sentinel, and — most importantly — that hostile Postgres identifiers
can't produce malformed XML.
"""
from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from pgrls.formatters import format_violations
from pgrls.formatters._common import EMPTY_OR_ZERO_WIDTH_SENTINEL
from pgrls.formatters.junit import format_junit
from pgrls.violations import Violation


def _v(
    rule_id: str = "SEC001",
    severity: str = "error",
    title: str = "RLS not enabled on table",
    message: str = "Table public.users does not have RLS enabled.",
    location: str | None = "public.users",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        message=message,
        location=location,
    )


def test_junit_registered_as_a_format() -> None:
    from pgrls.formatters import SUPPORTED_FORMATS

    assert "junit" in SUPPORTED_FORMATS


def test_junit_dispatched_via_format_violations_ignoring_rationale() -> None:
    # `format_violations(format="junit")` routes to the junit
    # formatter, and (like every non-text format) ignores the
    # --explain rationale_map.
    vs = [_v()]
    direct = format_junit(vs)
    via = format_violations(
        vs, format="junit", rationale_map={"SEC001": "ignored rationale"}
    )
    assert via == direct
    assert "ignored rationale" not in via


def test_junit_output_is_well_formed_xml() -> None:
    out = format_junit([_v(), _v(rule_id="SEC027", severity="info")])
    # Raises on malformed XML.
    root = ET.fromstring(out)
    assert root.tag == "testsuites"


def test_junit_one_testcase_per_finding_with_counts() -> None:
    out = format_junit([_v(), _v(rule_id="SEC004"), _v(rule_id="SEC027")])
    root = ET.fromstring(out)
    assert root.attrib["tests"] == "3"
    assert root.attrib["failures"] == "3"
    assert root.attrib["errors"] == "0"
    cases = root.findall("./testsuite/testcase")
    assert len(cases) == 3


def test_junit_testcase_carries_rule_location_severity_title_message() -> None:
    out = format_junit(
        [_v(rule_id="SEC004", severity="warning",
            title="Inverted auth", message="Admits every row.",
            location="public.docs.p")]
    )
    case = ET.fromstring(out).find("./testsuite/testcase")
    assert case is not None
    assert case.attrib["classname"] == "SEC004"
    assert case.attrib["name"] == "SEC004 public.docs.p"
    failure = case.find("failure")
    assert failure is not None
    assert failure.attrib["type"] == "warning"
    assert failure.attrib["message"] == "Inverted auth"
    assert failure.text == "Admits every row."


def test_junit_clean_run_is_empty_well_formed_suite() -> None:
    out = format_junit([])
    root = ET.fromstring(out)
    assert root.attrib["tests"] == "0"
    assert root.attrib["failures"] == "0"
    assert root.findall("./testsuite/testcase") == []


def test_junit_schema_wide_location_renders_sentinel() -> None:
    out = format_junit([_v(location=None)])
    case = ET.fromstring(out).find("./testsuite/testcase")
    assert case is not None
    assert case.attrib["name"].endswith("(schema-wide)")


def test_junit_zero_width_only_location_uses_sentinel() -> None:
    out = format_junit([_v(location="​‌")])
    case = ET.fromstring(out).find("./testsuite/testcase")
    assert case is not None
    assert EMPTY_OR_ZERO_WIDTH_SENTINEL in case.attrib["name"]


def test_junit_hostile_identifiers_stay_well_formed() -> None:
    # Quotes, ampersand, angle brackets, and a newline in a quoted
    # Postgres identifier must not break the XML.
    out = format_junit(
        [
            _v(
                rule_id="SEC001",
                message='Table "a<b>&c" has RLS off.',
                location='public."a<b>&"\nweird',
            )
        ]
    )
    root = ET.fromstring(out)  # raises if the escaping leaked
    case = root.find("./testsuite/testcase")
    assert case is not None
    # The literal markup characters survive as decoded text/attribute
    # values after the parser unescapes them.
    assert "<b>&" in case.find("failure").text
    assert case.attrib["name"].startswith("SEC001 ")


def test_junit_control_chars_in_message_and_location_stay_well_formed() -> None:
    # Raw C0 control chars (NUL, BEL) are illegal in XML 1.0 and
    # quoteattr/escape do NOT remove them — safe_location must.
    out = format_junit(
        [_v(message="bad\x00msg\x07", location="public.t\x08bl")]
    )
    ET.fromstring(out)  # raises if a control char leaked into the XML


def test_junit_control_chars_in_rule_id_and_severity_stay_well_formed() -> None:
    # rule_id and severity are first-party constants today but are
    # free-form `str` on the public Violation; a control char in
    # either must not break classname / name / type.
    out = format_junit([_v(rule_id="SEC001\x07", severity="error\x00")])
    ET.fromstring(out)  # raises if either field leaked a control char


def test_junit_trailing_newline() -> None:
    assert format_junit([_v()]).endswith("</testsuites>\n")
    assert format_junit([]).endswith("</testsuites>\n")


@pytest.mark.parametrize("severity", ["error", "warning", "info"])
def test_junit_severity_becomes_failure_type(severity: str) -> None:
    out = format_junit([_v(severity=severity)])
    failure = ET.fromstring(out).find("./testsuite/testcase/failure")
    assert failure is not None
    assert failure.attrib["type"] == severity
