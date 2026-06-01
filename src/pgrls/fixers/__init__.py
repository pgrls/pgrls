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

__all__ = [
    "Fix",
    "Fixer",
    "default_fixers",
    "generate_fixes",
    "render_fixes",
    "render_migration",
]


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
    from pgrls.fixers.hyg003 import HYG003Fixer
    from pgrls.fixers.perf001 import PERF001Fixer
    from pgrls.fixers.perf003 import PERF003Fixer
    from pgrls.fixers.perf004 import PERF004Fixer
    from pgrls.fixers.sec001 import SEC001Fixer
    from pgrls.fixers.sec002 import SEC002Fixer
    from pgrls.fixers.sec006 import SEC006Fixer
    from pgrls.fixers.sec011 import SEC011Fixer
    from pgrls.fixers.sec019 import SEC019Fixer
    from pgrls.fixers.sec020 import SEC020Fixer
    from pgrls.fixers.sec015 import SEC015Fixer
    from pgrls.fixers.sec017 import SEC017Fixer
    from pgrls.fixers.sec030 import SEC030Fixer
    from pgrls.fixers.sec031 import SEC031Fixer
    from pgrls.fixers.sec032 import SEC032Fixer
    from pgrls.fixers.view001 import VIEW001Fixer
    from pgrls.fixers.view002 import VIEW002Fixer

    return [
        SEC001Fixer(),
        SEC002Fixer(),
        SEC006Fixer(),
        SEC011Fixer(),
        SEC015Fixer(),
        SEC017Fixer(),
        SEC019Fixer(),
        SEC020Fixer(),
        SEC030Fixer(),
        SEC031Fixer(),
        SEC032Fixer(),
        PERF001Fixer(),
        PERF003Fixer(),
        PERF004Fixer(),
        HYG003Fixer(),
        VIEW001Fixer(),
        VIEW002Fixer(),
    ]


def generate_fixes(
    schema: Schema,
    rule_options: dict[str, dict[str, Any]],
    *,
    rule_filter: set[str] | None = None,
) -> list[Fix]:
    """Run every fixer (or just the ones in `rule_filter`) and
    return the union of Fix objects, ordered by (rule_id, location).

    Each fixer validates its rule's `allowlist` option with the
    rule's strict parser; a malformed allowlist raises `TypeError`,
    which `pgrls fix` surfaces as a tool error — the same failure
    `pgrls lint` produces for the same config.

    Most fixers emit independent statements (`ALTER TABLE`, `ALTER
    VIEW`, `ALTER POLICY`) whose relative order does not affect the
    final state. The one exception is HYG003, the only fixer that
    `DROP`s an object: a `DROP POLICY p` and an `ALTER POLICY p`
    (from PERF001 / SEC006 / SEC011 / SEC020 firing on the same
    duplicate policy's shared predicate) are NOT order-independent —
    run the DROP first and the ALTER fails on a policy that no longer
    exists, leaving the emitted migration unrunnable mid-script.

    We resolve this by SUPPRESSING any `ALTER`-emitting fix that
    targets a policy HYG003 is going to DROP. The drop's surviving
    twin (the name-sorted-first duplicate HYG003 keeps) carries the
    identical predicate, so the same ALTER fixer also fires on it —
    that ALTER does the remediation, and the ALTER on the doomed
    duplicate was redundant as well as unrunnable. The result is
    always a runnable statement sequence with no lost remediation.

    Note this does NOT merge multiple ALTERs that target the *same
    surviving* policy (e.g. PERF001 and SEC019 both rewriting one
    policy's USING): those remain separate `ALTER POLICY` statements
    and `pgrls fix --apply` converges over repeated runs, a contract
    pinned by
    `test_sec019_and_perf001_both_fire_on_unwrapped_one_arg_current_setting`.
    Each such ALTER only narrows or hardens the clause it names; none
    re-introduces a bypass another fixer removed, so no security
    rewrite is silently reverted.

    Within those constraints the sort is alphabetical by `rule_id`
    then `location`. A future fixer with a hard ordering dependency
    (e.g. CREATE POLICY before its referenced table is forced) would
    need explicit dependency-based ordering layered on top.
    """
    out: list[Fix] = []
    for fixer in default_fixers():
        if rule_filter is not None and fixer.rule_id not in rule_filter:
            continue
        opts = rule_options.get(fixer.rule_id, {})
        out.extend(fixer.fix(schema, opts))

    # HYG003 is the only fixer that DROPs a policy. Any ALTER fix that
    # targets a policy HYG003 will drop would be applied against a
    # now-nonexistent policy (depending on emit order) and fail. Drop
    # those ALTERs: the dropped policy's surviving duplicate gets the
    # same ALTER, so nothing is lost. `location` is the qualified
    # policy id (`schema.table.policy`) for every per-policy fixer, so
    # it is the right join key. (HYG003 also emits per-policy
    # `location`s, hence the rule_id guard so a drop never suppresses
    # itself.)
    dropped_policy_ids = {
        f.location for f in out if f.rule_id == "HYG003"
    }
    if dropped_policy_ids:
        out = [
            f
            for f in out
            if f.rule_id == "HYG003" or f.location not in dropped_policy_ids
        ]

    return sorted(out, key=lambda f: (f.rule_id, f.location))


def render_fixes(fixes: list[Fix]) -> str:
    """Render `fixes` as `-- [RULE] description` + SQL blocks.

    One block per fix — a comment line naming the rule and
    describing the change, then the SQL statement. Blocks are
    separated by a blank line. No trailing newline; the caller
    adds one (`click.echo` does, `render_migration` does).

    This is the body shared by `pgrls fix`'s stdout dry-run and
    the `--output` migration file, so the two never drift.
    """
    return "\n\n".join(
        f"-- [{fix.rule_id}] {fix.description}\n{fix.sql}"
        for fix in fixes
    )


def render_migration(fixes: list[Fix], *, tool_version: str) -> str:
    """Render `fixes` as a complete migration-ready `.sql` script.

    The text is a header comment — naming the generating pgrls
    version and the fix count — followed by the `render_fixes`
    blocks and a single trailing newline. `pgrls fix --output`
    writes exactly this.

    Deterministic: the header carries no timestamp, so
    regenerating against an unchanged schema produces a
    byte-identical file (clean diffs when the migration is
    committed). The fixes themselves are already ordered by
    `generate_fixes` (`(rule_id, location)`).
    """
    count = len(fixes)
    plural = "fix" if count == 1 else "fixes"
    header = (
        f"-- Remediation SQL generated by pgrls {tool_version}.\n"
        "--\n"
        "-- Review every statement before applying. Generated from\n"
        "-- a snapshot of the database; regenerate if the schema\n"
        f"-- has changed since. {count} {plural}.\n"
    )
    return f"{header}\n{render_fixes(fixes)}\n"
