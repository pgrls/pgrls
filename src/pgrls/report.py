"""Per-table RLS posture report for `pgrls report`.

`pgrls lint` answers "what's *wrong*?"; `pgrls report` answers "what's
the RLS posture *overall*?" — a factual, rule-free snapshot of every
table's row-level-security state, for audits and onboarding. It runs no
rules and emits no findings; it summarizes `relrowsecurity`,
`relforcerowsecurity`, and policy counts as introspected.

Each table gets a coarse `status` derived from those facts (plus
declarative-partition ancestry — see ``covered-by-parent``), in
precedence order:

* ``covered-by-parent`` — RLS not enabled on this table, but it is a
  declarative-partition child of a table that *does* have RLS. Postgres
  does not propagate ``relrowsecurity`` to children, but queries routed
  through the parent apply the parent's policies, so the child is
  covered (this mirrors how SEC001 skips such children). Direct queries
  against the child still bypass the parent's policies — a documented
  caveat.
* ``rls-off``      — RLS not enabled and no RLS-enabled ancestor (the
  table is wide open to anyone with table privileges; if it also has
  policies they are dormant).
* ``no-policies``  — RLS on but zero policies: Postgres default-denies,
  so the table is locked to non-owners.
* ``not-forced``   — RLS on with policies, but not ``FORCE``d, so the
  table owner bypasses every policy.
* ``protected``    — RLS on, ``FORCE``d, and at least one policy.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from pgrls.model import Schema

# Ordered best → worst, which is also the order the summary line lists
# non-zero counts. (The `status` property's precedence is independent of
# this tuple; this only drives summary display and the count keys.)
STATUSES = (
    "protected",
    "not-forced",
    "no-policies",
    "covered-by-parent",
    "rls-off",
)

_STATUS_LABELS = {
    "protected": "protected",
    "not-forced": "not forced",
    "no-policies": "no policies",
    "covered-by-parent": "covered by parent",
    "rls-off": "RLS off",
}


def _status_key(status: str) -> str:
    return f"status_{status.replace('-', '_')}"


@dataclass(frozen=True)
class TablePosture:
    qualified_name: str
    rls_enabled: bool
    force_rls: bool
    policy_count: int
    permissive_count: int
    restrictive_count: int
    # True when this table is a partition child whose ancestor chain
    # reaches a table with RLS enabled — it is covered via the parent
    # even though its own `relrowsecurity` is false.
    covered_by_ancestor: bool = False

    @property
    def status(self) -> str:
        if not self.rls_enabled:
            return "covered-by-parent" if self.covered_by_ancestor else "rls-off"
        if self.policy_count == 0:
            return "no-policies"
        if not self.force_rls:
            return "not-forced"
        return "protected"


@dataclass(frozen=True)
class Report:
    tables: tuple[TablePosture, ...]

    @property
    def summary(self) -> dict[str, int]:
        counts = {s: 0 for s in STATUSES}
        for t in self.tables:
            counts[t.status] += 1
        return {
            "tables": len(self.tables),
            "rls_enabled": sum(1 for t in self.tables if t.rls_enabled),
            "forced": sum(1 for t in self.tables if t.force_rls),
            "with_policies": sum(
                1 for t in self.tables if t.policy_count > 0
            ),
            **{_status_key(s): counts[s] for s in STATUSES},
        }


def build_report(schema: Schema) -> Report:
    """Build the posture report from an introspected `schema`.

    Tables are sorted by qualified name so the output is deterministic.
    A partition child whose ancestor chain reaches an RLS-enabled table
    is marked `covered_by_ancestor` (same coverage logic SEC001 uses to
    skip such children).
    """
    postures = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        permissive = sum(1 for p in table.policies if p.permissive)
        restrictive = len(table.policies) - permissive
        covered = any(
            ancestor.rls_enabled for ancestor in schema.ancestors_of(table)
        )
        postures.append(
            TablePosture(
                qualified_name=table.qualified_name,
                rls_enabled=table.rls_enabled,
                force_rls=table.force_rls,
                policy_count=len(table.policies),
                permissive_count=permissive,
                restrictive_count=restrictive,
                covered_by_ancestor=covered,
            )
        )
    return Report(tables=tuple(postures))


def _summary_line(report: Report) -> str:
    """`N table(s): X protected, Y not forced, …` — non-zero statuses
    only, pluralized, in STATUSES order."""
    n = len(report.tables)
    noun = "table" if n == 1 else "tables"
    s = report.summary
    parts = [
        f"{s[_status_key(st)]} {_STATUS_LABELS[st]}"
        for st in STATUSES
        if s[_status_key(st)]
    ]
    detail = ", ".join(parts) if parts else "none"
    return f"{n} {noun}: {detail}."


def render_text(report: Report) -> str:
    """Human-readable aligned table + a summary line."""
    if not report.tables:
        return "No tables found in the scanned schemas."
    rows = [
        (
            t.qualified_name,
            t.status,
            "yes" if t.rls_enabled else "no",
            "yes" if t.force_rls else "no",
            str(t.policy_count),
        )
        for t in report.tables
    ]
    headers = ("TABLE", "STATUS", "RLS", "FORCE", "POLICIES")
    widths = [
        max(len(headers[i]), max(len(r[i]) for r in rows))
        for i in range(len(headers))
    ]
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    out = [line]
    for r in rows:
        out.append("  ".join(r[i].ljust(widths[i]) for i in range(len(r))))
    out.append("")
    out.append(_summary_line(report))
    return "\n".join(out)


def render_json(report: Report) -> str:
    """Stable machine-readable shape: {summary, tables[]}."""
    payload = {
        "summary": report.summary,
        "tables": [
            {
                "table": t.qualified_name,
                "status": t.status,
                "rls_enabled": t.rls_enabled,
                "force_rls": t.force_rls,
                "policies": t.policy_count,
                "permissive": t.permissive_count,
                "restrictive": t.restrictive_count,
            }
            for t in report.tables
        ],
    }
    return json.dumps(payload, indent=2)


def render_markdown(report: Report) -> str:
    """Markdown table + summary, paste-ready for an audit doc / PR."""
    out = [
        "# RLS posture",
        "",
        _summary_line(report),
        "",
        "| Table | Status | RLS | FORCE | Policies |",
        "|---|---|---|---|---|",
    ]
    for t in report.tables:
        out.append(
            f"| {t.qualified_name} | {t.status} | "
            f"{'yes' if t.rls_enabled else 'no'} | "
            f"{'yes' if t.force_rls else 'no'} | {t.policy_count} |"
        )
    return "\n".join(out) + "\n"


_RENDERERS = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
}
REPORT_FORMATS = tuple(_RENDERERS)


def render(report: Report, output_format: str) -> str:
    return _RENDERERS[output_format](report)
