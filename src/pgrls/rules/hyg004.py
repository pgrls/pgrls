"""HYG004 — Policy has no behavioral test exercising it.

`pgrls lint` proves a policy is well-*formed*; it can't prove the policy
actually enforces what you intend. That's what `pgrls.testing` is for —
and HYG004 closes the loop by flagging any policy your test suite never
exercised. An untested policy is the one most likely to silently stop
working: a migration narrows its `USING` clause, a role grant drifts, and
nothing fails until a tenant sees another tenant's rows.

HYG004 is **opt-in**. It does nothing on a normal `pgrls lint` run; it
only fires when lint is given a coverage artifact (`pgrls lint --coverage
.pgrls-coverage.json`), which `pgrls.testing` writes when your suite runs.
The CLI loads that artifact and injects it into this rule's options under
the private `_coverage` key — rules can't read files themselves, so lint
hands the parsed data in. Without it, `check` returns nothing rather than
flag every policy as untested.

A policy is *covered* when some test queried its table, under a role the
policy targets (or PUBLIC), with a matching command — see
`pgrls.coverage.is_policy_covered`, the shared matching that also powers
`pgrls coverage`. Severity: info — an untested policy is a gap to close,
not a live vulnerability. Allowlist a policy's qualified ID to accept it
as intentionally untested.
"""
from __future__ import annotations

from typing import Any

from pgrls.coverage import (
    CoverageData,
    ambiguous_relation_names,
    is_policy_covered,
)
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


class HYG004:
    id: str = "HYG004"
    severity: Severity = "info"
    title: str = "Policy has no behavioral test"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        coverage = options.get("_coverage")
        if not isinstance(coverage, CoverageData):
            # Opt-in: no coverage artifact was wired in (lint run without
            # --coverage). Stay silent rather than flag every policy.
            return []
        allowlist = parse_policy_id_allowlist("HYG004", options)
        ambiguous = ambiguous_relation_names(schema)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                if is_policy_covered(
                    table, policy, coverage, ambiguous_relations=ambiguous
                ):
                    continue
                roles = ", ".join(policy.roles) or "(no roles)"
                out.append(
                    Violation(
                        rule_id=self.id,
                        severity=self.severity,
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} ({policy.command} for "
                            f"{roles}) has no pgrls.testing assertion "
                            "exercising it — no test queried this table "
                            "under a matching role and command. An untested "
                            "policy can silently stop enforcing what you "
                            "intend. Add a pgrls.testing case that exercises "
                            f"it, or allowlist {pid!r} in "
                            "[lint.rules.HYG004]."
                        ),
                        location=pid,
                    )
                )
        return out
