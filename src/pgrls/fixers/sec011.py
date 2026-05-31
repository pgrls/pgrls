"""SEC011 fixer — strip the `OR true` debug bypass from a policy predicate.

SEC011 flags a policy whose `USING` or `WITH CHECK` contains an
`OR true` disjunct: `x = 1 OR true` evaluates to `true` for every
row, so the real `x = 1` half is dead. It's the classic leftover
debug branch ("temporarily let everything through"), and the fix
is mechanical — remove the literal-`true` disjunct and let the
remaining predicate stand:

    owner_id = current_setting('app.user')  OR true
    →  owner_id = current_setting('app.user')

The fixer removes literal-`true` args from each OR `BoolExpr`
reachable from the clause root through AND / OR chains, and
unwraps an OR that collapses to a single remaining arg
(`a OR true` → `a`, not `(a)`). Nested ORs are handled bottom-up.
Both `USING` and `WITH CHECK` are inspected; only the clause(s)
that actually changed are re-emitted in the `ALTER POLICY`, so the
produced migration is the minimal diff. The mutation happens on a
deep-copy of the policy ASTs so the rule's `Schema` view stays
read-only.

Crucially, the fixer only strips `OR true` in **monotone
position** — under AND / OR operators where `P OR true` is
absorbing and removing the `true` can only *narrow* the policy.
It never descends past a `NOT`, a comparison, an `IS FALSE` test,
a function call, or a SubLink, because tightening an OR in a
non-monotone position would *broaden* access: `NOT (a OR true)` is
deny-all, but `NOT a` is not. A security fixer must never widen a
policy. SEC011's rule still flags `OR true` in those positions —
the fixer just declines to auto-rewrite them and leaves the
finding for human review (the same conservative stance it takes on
the degenerate case below).

This fix is opinionated in the same way SEC019's is. Removing
`OR true` assumes the disjunct was a debug bypass, not a
deliberate "admit every row" — the overwhelmingly common case,
and the one SEC011 was written for. If a policy genuinely means
to admit every row, the right move is not `OR true` buried in a
predicate but dropping the policy (or disabling RLS) outright; the
Fix description says so, and an operator who wants to keep the
literal can allowlist the policy in `[lint.rules.SEC011]`.

Degenerate predicates that are *only* literal trues (`true OR
true`) have no real predicate to fall back to once the trues are
removed — there's no safe minimal rewrite, so the fixer skips the
policy and leaves the SEC011 finding for human review rather than
emit an empty `USING ()`.
"""
from __future__ import annotations

import copy
from typing import Any

from pglast.ast import BoolExpr
from pglast.enums import BoolExprType
from pglast.stream import RawStream

from pgrls.ast_utils import is_literal_true
from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist


class _CannotStrip(Exception):
    """Raised when removing `OR true` would leave an OR with no
    remaining args (the predicate was vacuously true). There's no
    minimal predicate to keep, so the fixer skips the policy."""


def _strip_or_true(node: Any) -> tuple[Any, bool]:
    """Remove literal-`true` disjuncts from OR BoolExprs reachable
    from the clause root through AND / OR chains only.

    Returns `(node, changed)`. Recurses through `AND_EXPR` and
    `OR_EXPR` BoolExpr args — and **only** those — stripping
    literal-`true` from the OR nodes. An OR left with a single arg
    is unwrapped (`a OR true` → `a`); an OR left with zero args
    raises `_CannotStrip`.

    **Why AND/OR only — this is a security boundary, not an
    optimization.** `P OR true` is absorbing (≡ `true`) only in
    *monotone* position, where tightening it to `P` can only
    *narrow* the policy. The moment the OR sits under a `NOT`, a
    comparison, an `IS FALSE` test, a function call, or a SubLink,
    monotonicity is gone and removing the `true` can *broaden*
    access — `NOT (a OR true)` is deny-all, but `NOT a` is not. A
    security fixer must never broaden a policy, so anything that
    isn't an AND/OR chain from the root is left untouched. SEC011's
    rule still *flags* `OR true` in those positions; the safe action
    is to leave the finding for human review, not to auto-rewrite.

    Stopping at every non-AND/OR node also subsumes the SubLink
    case: an `OR true` inside a subquery's own WHERE (the
    legitimate `EXISTS (SELECT 1 FROM t WHERE flag OR true)` shape)
    is never reached, so the fixer can't mutate a policy the rule
    calls clean.
    """
    if not isinstance(node, BoolExpr):
        return node, False
    if node.boolop not in (BoolExprType.AND_EXPR, BoolExprType.OR_EXPR):
        # NOT_EXPR (or any future boolop) is non-monotone — do not
        # descend; stripping below a negation could broaden access.
        return node, False

    changed = False
    new_args: list[Any] = []
    for arg in node.args or ():
        new_arg, arg_changed = _strip_or_true(arg)
        new_args.append(new_arg)
        changed = changed or arg_changed

    if node.boolop == BoolExprType.OR_EXPR:
        kept = [a for a in new_args if not is_literal_true(a)]
        if len(kept) != len(new_args):
            if not kept:
                raise _CannotStrip()
            if len(kept) == 1:
                # `a OR true` → `a` — unwrap the now-singleton OR.
                return kept[0], True
            node.args = tuple(kept)
            return node, True

    if changed:
        node.args = tuple(new_args)
    return node, changed


def _strip_clause(ast: Any) -> tuple[Any, bool]:
    """Deep-copy and strip one clause's AST. Returns
    `(new_ast, changed)`; propagates `_CannotStrip`."""
    if ast is None:
        return None, False
    candidate = copy.deepcopy(ast)
    return _strip_or_true(candidate)


class SEC011Fixer:
    rule_id: str = "SEC011"

    def fix(self, schema: Schema, options: dict[str, Any]) -> list[Fix]:
        skip = parse_policy_id_allowlist("SEC011", options)
        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in skip:
                    continue

                try:
                    new_using_ast, using_changed = _strip_clause(
                        policy.using_ast
                    )
                    new_wc_ast, wc_changed = _strip_clause(
                        policy.with_check_ast
                    )
                except _CannotStrip:
                    # A clause is only literal-trues — no minimal
                    # predicate survives. Leave it for human review.
                    continue

                if not (using_changed or wc_changed):
                    continue

                clauses: list[str] = []
                if using_changed:
                    clauses.append(f"    USING ({RawStream()(new_using_ast)})")
                if wc_changed:
                    clauses.append(
                        f"    WITH CHECK ({RawStream()(new_wc_ast)})"
                    )
                stmt = (
                    f"ALTER POLICY {quote_ident(policy.name)} "
                    f"ON {quote_qualified(table.schema, table.name)}\n"
                    + "\n".join(clauses)
                    + ";"
                )

                out.append(
                    Fix(
                        rule_id="SEC011",
                        location=pid,
                        sql=stmt,
                        description=(
                            f"Remove the `OR true` disjunct from policy "
                            f"{policy.name!r} on {table.qualified_name}, "
                            "restoring the real predicate the bypass was "
                            "masking. This assumes the `OR true` was a "
                            "leftover debug branch (the case SEC011 "
                            "targets). If the policy genuinely means to "
                            "admit every row, drop the policy or disable "
                            "RLS on the table instead of burying a "
                            "constant-true in the predicate; allowlist "
                            "the policy in [lint.rules.SEC011] to keep "
                            "the literal as-is."
                        ),
                    )
                )
        return out
