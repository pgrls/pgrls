"""JUnit XML output for `pgrls lint`.

Emits a JUnit-style report — the de-facto CI test-report format that
GitLab, Jenkins, CircleCI, Buildkite, and GitHub test-reporter
actions ingest — so lint findings surface in a run's "Tests" tab
alongside unit tests.

Shape: one `<testsuite name="pgrls">` whose `<testcase>` children are
the findings (one per violation). `classname` is the rule id (so
consumers group findings by rule); `name` is `"<rule id> <location>"`.
Every finding is a `<failure>` — the rule's check did not pass — whose
`type` carries the pgrls severity and `message` the rule title, with
the full finding message as the element text.

A clean run emits an empty suite (`tests="0"`), which every JUnit
consumer treats as all-green. Warning- and info-level findings are
reported as failures too: the report shows *everything* the lint
found, and the process exit code (`--fail-on`) — not the report —
decides whether the build blocks.

All attribute values go through `xml.sax.saxutils.quoteattr` and text
through `escape`, and every string is first run through
`safe_location` to strip control characters that are illegal in XML
1.0 (a quoted Postgres identifier can legally contain a newline or
NUL). So a hostile or unusual table / policy name can't produce
malformed XML.
"""
from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from pgrls.formatters._common import (
    EMPTY_OR_ZERO_WIDTH_SENTINEL,
    safe_location,
)
from pgrls.violations import Violation


def _location(location: str | None) -> str:
    """Render a `Violation.location` for the testcase name.

    Mirrors the other formatters: a falsy location is schema-wide; a
    location that survives `safe_location` empty (all zero-width) gets
    the shared sentinel.
    """
    if not location:
        return "(schema-wide)"
    return safe_location(location) or EMPTY_OR_ZERO_WIDTH_SENTINEL


def format_junit(violations: list[Violation]) -> str:
    """Render violations as a JUnit XML report.

    One `<testcase>` per finding under a single `pgrls` suite. The
    output always ends with a trailing newline (matching the other
    formatters; the CLI echoes with `nl=False`). A clean run still
    emits the well-formed empty suite — JUnit consumers reject a
    truly empty document but accept a zero-test suite.
    """
    count = len(violations)
    parts: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        f'<testsuites name="pgrls" tests="{count}" '
        f'failures="{count}" errors="0">\n',
        f'  <testsuite name="pgrls" tests="{count}" '
        f'failures="{count}" errors="0">\n',
    ]
    for v in violations:
        name = quoteattr(f"{v.rule_id} {_location(v.location)}")
        classname = quoteattr(v.rule_id)
        message = quoteattr(safe_location(v.title))
        severity = quoteattr(v.severity)
        detail = escape(safe_location(v.message))
        parts.append(
            f"    <testcase classname={classname} name={name}>\n"
            f"      <failure message={message} type={severity}>"
            f"{detail}</failure>\n"
            f"    </testcase>\n"
        )
    parts.append("  </testsuite>\n</testsuites>\n")
    return "".join(parts)
