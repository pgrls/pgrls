"""Baseline file support for `pgrls lint --baseline`.

A baseline records the lint findings a project currently has, so a
later `pgrls lint --baseline <file>` reports and fails only on
*new* findings — letting a team adopt pgrls on a legacy database
and ratchet down without rewriting every old policy first.

The model is auto-create-on-first-run: when the baseline file does
not exist, the run records the current findings into it and exits
clean. On every later run, findings already in the baseline are
suppressed and only findings absent from it count toward the
output and the exit code. To re-baseline, delete the file and run
again.

A finding is identified by `(rule_id, location)`. The message text
is deliberately NOT part of the key: message wording can change
between pgrls releases, and a baseline keyed on it would
spuriously "un-baseline" a finding after a harmless message tweak.
Two findings that share a `(rule_id, location)` key are treated as
one for baseline purposes — in practice rules emit one finding per
policy / table, so collisions are rare.
"""
from __future__ import annotations

import json
from pathlib import Path

from pgrls.violations import Violation

# Bumped when the on-disk baseline JSON shape changes. A file
# written by a newer pgrls is rejected by an older one with a clear
# "delete and regenerate" message rather than silently mis-parsed.
BASELINE_VERSION = 1

# A finding's identity within a baseline.
_Key = tuple[str, str | None]


class BaselineError(Exception):
    """Raised when a baseline file is malformed, unreadable, or unwritable."""


def finding_key(violation: Violation) -> _Key:
    """The `(rule_id, location)` identity used for baseline matching."""
    return (violation.rule_id, violation.location)


def write_baseline(
    path: Path, violations: list[Violation], *, tool_version: str
) -> int:
    """Write `violations` to a baseline file at `path`; return the count.

    `findings` is sorted so a regenerated baseline produces a
    stable diff regardless of rule-evaluation order.
    """
    findings = sorted(
        ({"rule_id": v.rule_id, "location": v.location} for v in violations),
        key=lambda f: (f["rule_id"] or "", f["location"] or ""),
    )
    payload = {
        "version": BASELINE_VERSION,
        "generated_by": f"pgrls {tool_version}",
        "findings": findings,
    }
    try:
        path.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise BaselineError(
            f"cannot write baseline to {path}: {exc}"
        ) from exc
    return len(findings)


def load_baseline(path: Path) -> set[_Key]:
    """Load a baseline file and return its set of `(rule_id, location)` keys."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise BaselineError(f"baseline {path} must be a JSON object")
    version = payload.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"baseline {path} has version {version!r}; this pgrls "
            f"supports baseline version {BASELINE_VERSION}. Delete "
            "the file and re-run to regenerate it."
        )
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise BaselineError(
            f"baseline {path}: 'findings' must be a list"
        )
    keys: set[_Key] = set()
    for entry in findings:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("rule_id"), str)
            or not isinstance(entry.get("location"), (str, type(None)))
        ):
            raise BaselineError(
                f"baseline {path}: every finding must be an object "
                'with a string "rule_id" and a string-or-null '
                '"location"'
            )
        keys.add((entry["rule_id"], entry["location"]))
    return keys


def partition(
    violations: list[Violation], baseline: set[_Key]
) -> tuple[list[Violation], list[Violation]]:
    """Split `violations` into `(new, baselined)` by baseline membership.

    Order within each list is preserved from `violations`.
    """
    new: list[Violation] = []
    baselined: list[Violation] = []
    for v in violations:
        (baselined if finding_key(v) in baseline else new).append(v)
    return new, baselined
