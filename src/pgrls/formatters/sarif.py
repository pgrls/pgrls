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
    # SARIF §3.49.7 says `name` must be an identifier (Pascal-ish,
    # no whitespace). The rule_id is exactly that. The free-text
    # title goes in `shortDescription` instead. Don't duplicate the
    # title into `name` — some SARIF consumers (CodeQL conventions,
    # Sonar) treat the two fields differently and would render the
    # prose label where they expect a code-friendly handle.
    #
    # `defaultConfiguration.level` lets consumers like GitHub Code
    # Scanning populate the rule list view even before any result
    # fires. Pull from the first observed severity for this rule —
    # all current rules emit a single severity value, so this is
    # stable. (If a rule ever emitted mixed severities for different
    # findings, the descriptor's default would still be informative;
    # per-result `level` always wins.)
    seen: dict[str, dict[str, Any]] = {}
    for v in violations:
        if v.rule_id in seen:
            continue
        seen[v.rule_id] = {
            "id": v.rule_id,
            "name": v.rule_id,
            "shortDescription": {"text": v.title},
            "defaultConfiguration": {"level": _level(v.severity)},
            "helpUri": (
                f"{_INFORMATION_URI}/blob/main/AGENTS.md#"
                f"rule-{v.rule_id.lower()}"
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
    # SARIF §3.27.12 says `locations` SHOULD be omitted when none
    # are known, but GitHub Code Scanning's SARIF upload endpoint
    # rejects results with an empty `locations` array. Synthesize a
    # `<schema>` logicalLocation when the violation has none — keeps
    # the document GitHub-ingestible for any future schema-wide rule
    # that doesn't pin to a specific table or policy.
    fqn = v.location if v.location is not None else "<schema>"
    out["locations"] = [
        {"logicalLocations": [{"fullyQualifiedName": fqn}]}
    ]
    return out


def _level(severity: Severity) -> str:
    # SARIF v2.1.0 levels: "none" | "note" | "warning" | "error".
    return {"error": "error", "warning": "warning", "info": "note"}[
        severity
    ]
