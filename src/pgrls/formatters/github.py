"""GitHub Actions workflow-command output for `pgrls lint`.

Emits one [workflow command](https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions)
per violation so findings surface as **annotations** in a GitHub
Actions run:

    ::error title=SEC004 public.documents.p::Policy 'p' on ...
    ::warning title=SEC026 public.documents.p::Policy 'p' uses ...
    ::notice title=SEC027 public.documents::Table public.documents ...

Severity maps to the three annotation levels GitHub renders:
`error` → `::error`, `warning` → `::warning`, `info` → `::notice`.

**No `file=` / `line=`.** GitHub shows annotations *inline on the
PR diff* only when they carry a file + line, and renders them in the
run's annotation summary otherwise. pgrls lints a live database, not
source text — it has no reliable mapping from a policy back to the
migration file and line that defined it — so the annotations land in
the run summary (still surfaced on the PR's "Checks" tab), not pinned
to a diff hunk. The `title` carries the rule id and qualified
location so each annotation is self-describing.

Message and title text are escaped per GitHub's workflow-command
rules so a `%`, newline, `:`, or `,` in a rule message or a quoted
Postgres identifier can't terminate the command early or be parsed
as a property delimiter.

A clean run emits nothing — no annotations is the correct signal for
"no findings"; the exit code already distinguishes clean from dirty.
"""
from __future__ import annotations

from pgrls.formatters._common import (
    EMPTY_OR_ZERO_WIDTH_SENTINEL,
    safe_location,
)
from pgrls.violations import Severity, Violation

# pgrls severity → GitHub annotation level. `info` becomes `notice`
# (GitHub's lowest annotation level); there is no "info" command.
_COMMAND_BY_SEVERITY: dict[Severity, str] = {
    "error": "error",
    "warning": "warning",
    "info": "notice",
}


def _escape_data(text: str) -> str:
    """Escape the message body of a workflow command.

    Mirrors `@actions/core`'s `escapeData`: `%` first (so the
    percent in a subsequent `%0A` isn't itself re-escaped), then
    CR and LF. A raw newline would otherwise end the command and
    turn the remainder of the message into un-parsed log output.
    """
    return (
        text.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _escape_property(text: str) -> str:
    """Escape a property value (the `title=`).

    Mirrors `@actions/core`'s `escapeProperty`: the data escapes
    plus `:` and `,`, which delimit the command header
    (`::error title=…,file=…::`). Without these, a colon in a
    quoted identifier (`"a:b"`) would split the title from a
    phantom property.
    """
    return (
        text.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _location_for_title(location: str | None) -> str:
    """Render a `Violation.location` for the annotation title.

    Matches the text / markdown / SARIF formatters: a falsy
    location is a schema-wide finding (`(schema-wide)`); a location
    that survives `safe_location` as empty (all zero-width chars)
    gets the shared sentinel so the reader sees something was there.
    """
    if not location:
        return "(schema-wide)"
    cleaned = safe_location(location)
    return cleaned or EMPTY_OR_ZERO_WIDTH_SENTINEL


def format_github(violations: list[Violation]) -> str:
    """Render violations as GitHub Actions workflow commands.

    One command per violation, newline-separated. Empty input
    returns the empty string (a clean run prints no annotations).
    """
    lines: list[str] = []
    for v in violations:
        command = _COMMAND_BY_SEVERITY[v.severity]
        title = _escape_property(
            f"{v.rule_id} {_location_for_title(v.location)}"
        )
        message = _escape_data(v.message)
        lines.append(f"::{command} title={title}::{message}")
    return "\n".join(lines)
