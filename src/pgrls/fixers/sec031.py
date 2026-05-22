"""SEC031 fixer — emit `DROP POLICY` for a no-op restrictive floor.

SEC031 flags a **restrictive** policy whose `USING` is the literal
`true`. Restrictive policies AND-combine, and `AND true` is the
identity — so the policy restricts **nothing**. Dropping it therefore
leaves the table's effective RLS unchanged (every row it "let
through" was already passing), exactly the way HYG003's drop is safe
because an identical twin remains:

    DROP POLICY <name> ON <schema>.<table>;

This is a mechanical, behavior-preserving remedy. The *other* remedy
SEC031 suggests — giving the policy the real tenant / ownership
predicate it was meant to enforce — needs human intent (which
column?), so it is out of scope for an auto-fix; the description on
each Fix points the operator at it. Like every fixer this is dry-run
by default: review the SQL before `--apply`, and if a real floor was
intended, write the predicate instead of dropping.

**Important guard — `WITH CHECK`.** The `AND true` identity argument
covers only the *read* side (`USING`). A restrictive `WITH CHECK` is a
real *write* floor (it AND-combines for INSERT/UPDATE), so a policy
that pairs `USING (true)` with a real `WITH CHECK (...)` is NOT inert:
dropping it would let through writes the floor rejected. SEC031 still
fires (its `USING` read floor is a no-op), but the fixer **abstains**
when `with_check_ast` is a non-trivial predicate — the auto-fix is
narrowed to genuinely inert policies (`WITH CHECK` absent or itself
constant-true), where the drop is provably behavior-preserving on
both the read and write sides. A load-bearing write floor is left for
human review.

Detection otherwise mirrors SEC031 (restrictive policy, `USING` is
literal `true`, not allowlisted); the extra `WITH CHECK` guard makes
the fixer a strict subset of what the rule reports.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_true
from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist


class SEC031Fixer:
    rule_id: str = "SEC031"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing (the same parser SEC031 uses): a
        # malformed allowlist raises, surfaced by the `fix` CLI.
        skip = parse_policy_id_allowlist("SEC031", options)
        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                # Mirror SEC031's detection precisely.
                if policy.permissive:
                    continue  # permissive USING (true) is SEC008's
                if policy.using_ast is None:
                    continue
                if not is_literal_true(policy.using_ast):
                    continue
                # The DROP is behavior-preserving only for a GENUINELY
                # inert policy. A restrictive `WITH CHECK` is a real
                # write floor (it AND-combines for INSERT/UPDATE), so
                # dropping a policy that pairs `USING (true)` with a
                # real `WITH CHECK` would let through writes the floor
                # rejected — a behavior change. Only the USING side is
                # a proven no-op, so auto-fix only when WITH CHECK is
                # absent or itself constant-true; otherwise abstain and
                # leave the load-bearing write floor for human review.
                if (
                    policy.with_check_ast is not None
                    and not is_literal_true(policy.with_check_ast)
                ):
                    continue
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in skip:
                    continue
                out.append(self._fix(table.schema, table.name, policy.name))
        return out

    @staticmethod
    def _fix(schema: str, table: str, name: str) -> Fix:
        qtable = quote_qualified(schema, table)
        return Fix(
            rule_id="SEC031",
            location=f"{schema}.{table}.{name}",
            sql=f"DROP POLICY {quote_ident(name)} ON {qtable};",
            description=(
                f"Drop restrictive policy {name!r} on {schema}.{table} — "
                "its USING (true) AND-combines to a no-op, so it restricts "
                "nothing and dropping it leaves access unchanged. If a real "
                "floor was intended, replace it with the tenant / ownership "
                "predicate instead of dropping."
            ),
        )
