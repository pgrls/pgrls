"""Machine-readable JSON output.

The shape is the public CI contract. Stable between releases of the
same major-zero series; adding new keys is allowed (consumers that
ignore unknown keys keep working), removing or renaming requires a
deliberate version bump and a note in the changelog.

Top-level object:

    {
      "violations": [
        {
          "rule_id":  "SEC001",
          "severity": "error" | "warning" | "info",
          "title":    "<rule title>",
          "message":  "<full violation message>",
          "location": "<schema.table[.policy]>" | null
        }
      ],
      "summary": {
        "errors":   <int>,
        "warnings": <int>,
        "infos":    <int>,
        "total":    <int>
      }
    }

Output is pretty-printed (indent=2) and ends with a newline so
`pgrls lint --format json > out.json` produces a POSIX-friendly file.
Caller order in the input is preserved in `violations[]`; the
formatter does not sort.
"""
from __future__ import annotations

import json
from collections import Counter

from pgrls.violations import Severity, Violation


def format_json(violations: list[Violation]) -> str:
    payload = {
        "violations": [
            {
                "rule_id": v.rule_id,
                "severity": v.severity,
                "title": v.title,
                "message": v.message,
                "location": v.location,
            }
            for v in violations
        ],
        "summary": _summary(violations),
    }
    # `ensure_ascii=False` so non-ASCII characters in messages stay
    # readable instead of being escaped to `\uXXXX`. Consumers
    # parse with any standard JSON library; bytes are UTF-8.
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _summary(violations: list[Violation]) -> dict[str, int]:
    counts: Counter[Severity] = Counter(v.severity for v in violations)
    return {
        "errors": counts.get("error", 0),
        "warnings": counts.get("warning", 0),
        "infos": counts.get("info", 0),
        "total": len(violations),
    }
