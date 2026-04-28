"""Auto-remediation for the rules whose fix is mechanical.

Not every rule is auto-fixable. SEC003 (which role to grant to?),
SEC005 (which column to scope by?), SEC009 (what policy should be
added?) require human intent. Rules listed here have a single
correct fix that pgrls can generate without asking.

Usage:

    from pgrls.fixers import default_fixers, generate_fixes
    fixes = generate_fixes(schema, options, rule_filter=None)
    for fix in fixes:
        print(fix.sql)

`pgrls fix` (CLI) wires this up. Default mode is dry-run — print
the SQL but don't execute. `--apply` runs each statement on the
configured database.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pgrls.model import Schema


@dataclass(frozen=True)
class Fix:
    """A single SQL statement that remediates one violation."""

    rule_id: str
    location: str
    sql: str
    description: str


@runtime_checkable
class Fixer(Protocol):
    """Per-rule fixer. Returns one Fix per offending policy/table."""

    rule_id: str

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]: ...


def default_fixers() -> list[Fixer]:
    """Every fixer the project ships."""
    from pgrls.fixers.perf001 import PERF001Fixer
    from pgrls.fixers.sec002 import SEC002Fixer

    return [SEC002Fixer(), PERF001Fixer()]


def generate_fixes(
    schema: Schema,
    rule_options: dict[str, dict[str, Any]],
    *,
    rule_filter: set[str] | None = None,
) -> list[Fix]:
    """Run every fixer (or just the ones in `rule_filter`) and
    return the union of Fix objects, ordered by (rule_id, location)."""
    out: list[Fix] = []
    for fixer in default_fixers():
        if rule_filter is not None and fixer.rule_id not in rule_filter:
            continue
        opts = rule_options.get(fixer.rule_id, {})
        out.extend(fixer.fix(schema, opts))
    return sorted(out, key=lambda f: (f.rule_id, f.location))
