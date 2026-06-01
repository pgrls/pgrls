"""SEC006 fixer — emit `ALTER POLICY … WITH CHECK (…)` mirroring USING.

SEC006 fires on a write-side policy (`FOR INSERT` / `FOR UPDATE` /
`FOR ALL`) that has no `WITH CHECK` clause. For a **permissive**
policy the standard remediation is to add a `WITH CHECK` matching
the policy's `USING` predicate — exactly what SEC006's own message
recommends — so the write side enforces the same constraint as the
read side. The fixer emits:

    ALTER POLICY <name> ON <schema>.<table>
        WITH CHECK (<the USING predicate>);

The fixer is deliberately narrow. It emits only when **both**:

* the policy is **permissive**. A restrictive write-side policy
  with no `WITH CHECK` is a *dead policy* — Postgres defaults the
  missing clause to `true`, so the policy constrains nothing.
  SEC006's rule frames the fix as "express the predicate the
  policy is meant to enforce, or remove the policy" — a
  human-intent decision, not a mechanical `USING` copy — so the
  fixer skips restrictive policies.
* the policy has a `USING` clause to mirror. A `FOR INSERT`
  policy has none (Postgres forbids `FOR INSERT … USING (…)`),
  and a `FOR UPDATE` / `FOR ALL` policy can also be written
  without one; with no `USING` there is no predicate to copy.

In the skipped cases the SEC006 finding stays for the operator.

The `USING` predicate is round-tripped through
`pglast.stream.RawStream` rather than echoed verbatim — symmetric
with the PERF001 fixer, so pglast's escaping is applied
consistently regardless of where the SQL originated.

Before mirroring, a constant-true disjunct (`x = 1 OR true`) is
stripped from the predicate (via SEC011's
`strip_constant_true_for_mirror`). A verbatim mirror of an
`OR true` USING would produce a `WITH CHECK` that admits every
write — the wide-open write side this fixer exists to close — and
SEC011, which runs in the same `pgrls fix` pass, only rewrites
USING, never the WITH CHECK SEC006 just created. If nothing
non-trivial survives the strip (`true`, `true OR true`), the fixer
declines and leaves the SEC006 finding for the operator rather than
emit a constant-true WITH CHECK.
"""
from __future__ import annotations

from typing import Any

from pglast.stream import RawStream

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
# Reuse SEC011's constant-true stripping so a USING with an `OR true`
# disjunct is not mirrored verbatim into a wide-open WITH CHECK —
# single source of truth for the monotone-position stripping rule.
from pgrls.fixers.sec011 import strip_constant_true_for_mirror
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
# Single source of truth for the write-side command set — imported
# from the rule so the fixer flags exactly what the rule reports.
from pgrls.rules.sec006 import _WRITE_COMMANDS


class SEC006Fixer:
    rule_id: str = "SEC006"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser SEC006 uses):
        # a malformed allowlist raises, surfaced by the `fix` CLI.
        skip = parse_policy_id_allowlist("SEC006", options)
        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                # Mirror SEC006's detection: a write-side policy
                # (INSERT / UPDATE / ALL) with no WITH CHECK clause.
                if policy.command not in _WRITE_COMMANDS:
                    continue
                if policy.with_check_sql:
                    continue
                # Only permissive policies are auto-fixed. A
                # restrictive write-side policy with no WITH CHECK
                # is a dead policy (Postgres defaults the missing
                # clause to `true`); SEC006's rule frames the fix
                # as "express the intended predicate, or remove the
                # policy" — human intent, not a mechanical USING
                # copy. Skip it and leave the finding.
                if not policy.permissive:
                    continue
                # The fix mirrors USING into WITH CHECK, so there
                # must be a USING to mirror. A FOR INSERT policy has
                # none (Postgres forbids `FOR INSERT … USING`), and
                # a USING-less UPDATE/ALL policy has nothing to copy
                # either — the predicate then needs human intent, so
                # skip and leave the SEC006 finding for the operator.
                if policy.using_ast is None:
                    continue
                policy_id = (
                    f"{table.schema}.{table.name}.{policy.name}"
                )
                if policy_id in skip:
                    continue
                # Strip any constant-true disjunct (`x = 1 OR true`)
                # before mirroring USING into WITH CHECK. Mirrored
                # verbatim it would create a constant-true write check
                # that admits every write — the wide-open write side
                # this fixer exists to close. SEC011 (same `pgrls fix`
                # pass) only ever rewrites USING, never the WITH CHECK
                # SEC006 just emitted, so the bypass would survive the
                # pass. If nothing non-trivial survives the strip
                # (`true`, `true OR true`), decline — leave the SEC006
                # finding for the operator rather than emit a
                # constant-true WITH CHECK.
                mirror_ast = strip_constant_true_for_mirror(
                    policy.using_ast
                )
                if mirror_ast is None:
                    continue
                using_sql = RawStream()(mirror_ast)
                sql = (
                    f"ALTER POLICY {quote_ident(policy.name)} "
                    f"ON {quote_qualified(table.schema, table.name)}\n"
                    f"    WITH CHECK ({using_sql});"
                )
                out.append(
                    Fix(
                        rule_id="SEC006",
                        location=policy_id,
                        sql=sql,
                        description=(
                            f"Add a WITH CHECK clause to policy "
                            f"{policy.name!r} on "
                            f"{table.qualified_name}, mirroring its "
                            "USING predicate so writes are "
                            "constrained the same way reads are."
                        ),
                    )
                )
        return out
