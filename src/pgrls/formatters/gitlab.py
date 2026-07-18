"""GitLab Code Quality report (CodeClimate JSON) for GitLab CI.

Spec: the CodeClimate "issue" shape GitLab ingests as a Code Quality
artifact (``artifacts:reports:codequality``). GitLab surfaces the
findings in the merge-request Code Quality widget and, where a
``location.path`` matches a changed file, inline on the diff.

Why a dedicated format when ``--format sarif`` already exists: GitLab's
**SAST** report (which ingests SARIF) is a GitLab *Ultimate* (paid-tier)
feature, whereas the **Code Quality** report works on **every** tier
including Free. So this format is what lets a GitLab-CI pipeline surface
pgrls findings in the MR UI without an Ultimate subscription:

```yaml
# .gitlab-ci.yml
pgrls:
  script: pgrls lint --database-url "$DATABASE_URL" --format gitlab --output gl-code-quality.json
  artifacts:
    reports:
      codequality: gl-code-quality.json
```

The report is a JSON array; each finding is one object with the fields
GitLab reads:

* ``description`` — the finding's actionable text (``Violation.message``),
  the same text ``--format sarif`` puts in ``result.message``.
* ``check_name`` — the rule id, used to group findings in the widget.
* ``fingerprint`` — a stable, order-independent content hash so GitLab can
  track a finding across pipeline runs (new vs. resolved). Hashing the
  finding's *identity* (rule + location + message), not its list index,
  keeps the fingerprint stable when unrelated findings come and go.
* ``severity`` — mapped to GitLab's vocabulary (see ``_SEVERITY``).
* ``location.path`` — pgrls findings are database objects, not source
  lines, so the qualified object name (``schema.table[.policy]``) is the
  ``path`` — the same logical location ``--format sarif`` reports as
  ``fullyQualifiedName``. A finding with no object uses the
  ``(schema-wide)`` sentinel the sibling formatters emit. ``lines.begin``
  is required by GitLab and set to ``1`` (there is no source line).
"""
from __future__ import annotations

import hashlib
import json

from pgrls.violations import Severity, Violation

# pgrls severity → GitLab Code Quality severity.
# GitLab's vocabulary is: info | minor | major | critical | blocker.
_SEVERITY: dict[str, str] = {
    "error": "critical",
    "warning": "major",
    "info": "info",
}


def _severity(severity: Severity) -> str:
    # Fail CLOSED on an off-spec severity from an extra rule: map it to
    # "critical" (the most visible level) rather than KeyError-ing the
    # whole CI report, so the finding still surfaces loudly — the same
    # fail-to-most-visible choice the SARIF formatter makes.
    return _SEVERITY.get(severity, "critical")


def _fingerprint(v: Violation) -> str:
    """A stable, unique-per-finding fingerprint.

    GitLab dedupes and tracks new-vs-resolved findings across pipeline
    runs by this value, so it must be stable across runs (a content hash,
    not a list index — reordering findings must not change them) and
    distinguish distinct findings. The finding's identity is
    ``(rule_id, location, message)``; NUL-joined so no field boundary can
    be forged by a value that happens to contain the separator.
    """
    raw = f"{v.rule_id}\x00{v.location}\x00{v.message}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def format_gitlab(violations: list[Violation]) -> str:
    report = [
        {
            "description": v.message,
            "check_name": v.rule_id,
            "fingerprint": _fingerprint(v),
            "severity": _severity(v.severity),
            "location": {
                # Real qualified names never contain parentheses, so the
                # sentinel is unambiguous; falsy (not `is not None`) so an
                # empty-string location maps to it too, agreeing with the
                # sibling formatters.
                "path": v.location if v.location else "(schema-wide)",
                "lines": {"begin": 1},
            },
        }
        for v in violations
    ]
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
