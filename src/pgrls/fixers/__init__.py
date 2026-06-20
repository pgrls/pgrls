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
    # The policy clause(s) this fix's `ALTER POLICY` actually re-emits —
    # a subset of {"using", "with_check"}. `ALTER POLICY ... USING (x)`
    # REPLACES the whole USING clause (likewise WITH CHECK), so two fixes
    # that re-emit the SAME clause on one policy clobber each other. The
    # orchestrator uses this to keep one writer per (policy, clause) and
    # never let a clause-regenerating fixer silently revert a security
    # strip. Empty for fixes that don't rewrite a policy clause
    # (ALTER TABLE, DROP POLICY, ALTER VIEW, …).
    clauses: frozenset[str] = frozenset()


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
    from pgrls.fixers.sec004 import SEC004Fixer
    from pgrls.fixers.sec006 import SEC006Fixer
    from pgrls.fixers.sec010 import SEC010Fixer
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
        SEC004Fixer(),
        SEC006Fixer(),
        SEC010Fixer(),
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

    A second, sharper hazard: multiple fixers rewrite a policy's USING /
    WITH CHECK, and each emits a FULL `ALTER POLICY ... USING/WITH CHECK
    (...)` that REPLACES the whole clause. Two ALTERs that re-emit the
    SAME clause on one policy clobber each other (the name-sorted-last
    wins), and the clause-REGENERATING fixers (SEC019's missing_ok pass,
    PERF001's SELECT-wrap) build their clause from the ORIGINAL predicate —
    so applied after SEC011 / SEC020's `OR true` strip they silently revert
    it, leaving the policy wide open in that single migration. To prevent
    that we keep at most ONE writer per (policy, clause): the
    security-NARROWING fixer (SEC011 / SEC020) when present, else the
    name-sorted-first writer. A fix that loses a clause it would re-emit is
    dropped whole; its remaining work re-fires on the next `pgrls fix` run
    (the converges-over-repeated-runs contract) once the kept fix's change
    no longer triggers it. The keep is CLAUSE-precise (via `Fix.clauses`),
    so two narrowing strips on different clauses (SEC011 on USING, SEC020
    on WITH CHECK) both survive — they don't actually collide.

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

    # Coordinate the policy-DROP fixers (HYG003 / SEC031 / SEC010, see
    # `_DROP_FIXER_IDS`) with the clause-ALTER fixers. Any ALTER fix that
    # targets a policy a drop fixer will DROP would be applied against a
    # now-nonexistent policy (depending on emit order) and fail — e.g. SEC006
    # mirrors `USING (false)` into a `WITH CHECK (false)` on the very policy
    # SEC010 then drops. Suppress those ALTERs: dropping the dead policy is the
    # actual remedy and the ALTER was redundant. `location` is the qualified
    # policy id (`schema.table.policy`) for every per-policy fixer, the right
    # join key. Also dedup the DROPs themselves so two drop fixers targeting the
    # same policy (rare: a constant-false policy that is also a duplicate) don't
    # emit `DROP POLICY` twice — the second would fail on the already-dropped
    # policy.
    dropped_policy_ids = {
        f.location for f in out if f.rule_id in _DROP_FIXER_IDS
    }
    if dropped_policy_ids:
        kept: list[Fix] = []
        seen_drops: set[str] = set()
        for f in out:
            if f.rule_id in _DROP_FIXER_IDS:
                if f.location in seen_drops:
                    continue  # one DROP per policy
                seen_drops.add(f.location)
                kept.append(f)
            elif f.location not in dropped_policy_ids:
                kept.append(f)
            # else: a non-drop fix targeting a to-be-dropped policy → suppress
        out = kept

    out = _suppress_clobbering_clause_rewrites(out)

    return sorted(out, key=lambda f: (f.rule_id, f.location))


# Fixers that re-emit a policy clause from a non-trivial predicate — a real
# narrowing of access: SEC004 / SEC011 strip a disjunct from `USING` (read
# side), SEC020 mirrors `USING` into `WITH CHECK` (write side). They must win
# a clause contest so their strip / mirror is never clobbered by a
# clause-regenerating fixer.
_NARROWING_RULE_IDS = frozenset({"SEC004", "SEC011", "SEC020"})

# Fixers that emit `DROP POLICY` rather than rewrite a clause: HYG003 (drops a
# duplicate policy), SEC031 (drops a restrictive `USING (true)` no-op floor),
# SEC010 (drops a permissive constant-`false` no-op). `generate_fixes`
# coordinates these with the clause-ALTER fixers so a sibling ALTER never lands
# on a policy a drop removes, and dedups DROPs so the same policy is never
# dropped twice.
_DROP_FIXER_IDS = frozenset({"HYG003", "SEC031", "SEC010"})


def _suppress_clobbering_clause_rewrites(fixes: list[Fix]) -> list[Fix]:
    """Keep at most one writer per (policy, clause) among clause-rewriting
    fixes, so no `ALTER POLICY` clause replacement clobbers (and silently
    reverts) another's.

    A fix participates only if it re-emits a policy clause (``f.clauses``
    non-empty). For each contested (location, clause) the keeper is the
    security-narrowing fixer (SEC011 / SEC020) if present, else the
    name-sorted-first writer. A fix that is NOT the keeper on any clause it
    re-emits is dropped whole — `pgrls fix` re-runs converge it once the
    kept change no longer triggers it.
    """
    # winner[(location, clause)] = rule_id that keeps that clause
    contenders: dict[tuple[str, str], list[Fix]] = {}
    for f in fixes:
        for clause in f.clauses:
            contenders.setdefault((f.location, clause), []).append(f)
    winners: dict[tuple[str, str], str] = {}
    for key, group in contenders.items():
        narrowing = [f for f in group if f.rule_id in _NARROWING_RULE_IDS]
        winners[key] = min(
            (narrowing or group), key=lambda f: f.rule_id
        ).rule_id
    kept: list[Fix] = []
    for f in fixes:
        if not f.clauses:
            kept.append(f)
            continue
        if all(
            winners[(f.location, clause)] == f.rule_id for clause in f.clauses
        ):
            kept.append(f)
    return kept


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
