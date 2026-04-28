"""SARIF v2.1.0 output for GitHub Code Scanning and similar
aggregators.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/

The SARIF document is one `run` (a single `pgrls lint` invocation),
with `tool.driver.rules` listing the unique rule descriptors for
every rule that fired (deduplicated, order-preserved). Each
violation becomes a `result` with `ruleId`, `level`, `message`,
and `locations[0].logicalLocations[0].fullyQualifiedName` set to
`<schema>.<table>[.<policy>]`. SARIF doesn't have a "table" or
"policy" location kind in its physical-source taxonomy, so we use
the logical-location form GitHub Code Scanning displays as the
finding's "Path".

Severity mapping:

    pgrls.severity → SARIF level
    --------------------------
    error          → "error"
    warning        → "warning"
    info           → "note"  (SARIF has no "info"; "note" is the
                              correct lower-than-warning level)
"""
from __future__ import annotations

import json
from typing import Any

from pgrls import __version__
from pgrls.violations import Severity, Violation

_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/"
    "sarif-schema-2.1.0.json"
)
_INFORMATION_URI = "https://github.com/pgrls/pgrls"


def format_sarif(violations: list[Violation]) -> str:
    rules = _rule_descriptors(violations)
    rule_index_by_id = {r["id"]: i for i, r in enumerate(rules)}
    results = [_result(v, rule_index_by_id) for v in violations]
    doc = {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pgrls",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _rule_descriptors(violations: list[Violation]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for v in violations:
        if v.rule_id in seen:
            continue
        seen[v.rule_id] = {
            "id": v.rule_id,
            "name": v.title,
            "shortDescription": {"text": v.title},
            "helpUri": (
                f"{_INFORMATION_URI}/blob/main/AGENTS.md#"
                f"{v.rule_id.lower()}"
            ),
        }
    return list(seen.values())


def _result(
    v: Violation, rule_index_by_id: dict[str, int]
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ruleId": v.rule_id,
        "ruleIndex": rule_index_by_id[v.rule_id],
        "level": _level(v.severity),
        "message": {"text": v.message},
    }
    out["locations"] = (
        [
            {
                "logicalLocations": [
                    {"fullyQualifiedName": v.location}
                ]
            }
        ]
        if v.location is not None
        else []
    )
    return out


def _level(severity: Severity) -> str:
    # SARIF v2.1.0 levels: "none" | "note" | "warning" | "error".
    return {"error": "error", "warning": "warning", "info": "note"}[
        severity
    ]
