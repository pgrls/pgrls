"""SEC011 fixer — strip the `OR true` debug bypass from a policy predicate.

SEC011 flags a policy whose `USING` or `WITH CHECK` contains an
`OR true` disjunct: `x = 1 OR true` evaluates to `true` for every
row, so the real `x = 1` half is dead. It's the classic leftover
debug branch ("temporarily let everything through"), and the fix
is mechanical — remove the literal-`true` disjunct and let the
remaining predicate stand:

    owner_id = current_setting('app.user')  OR true
    →  owner_id = current_setting('app.user')

The fixer walks the policy AST, removes every literal-`true` arg
from each OR `BoolExpr`, and unwraps an OR that collapses to a
single remaining arg (`a OR true` → `a`, not `(a)`). Nested ORs
are handled bottom-up. Both `USING` and `WITH CHECK` are
inspected; only the clause(s) that actually changed are re-emitted
in the `ALTER POLICY`, so the produced migration is the minimal
diff. The mutation happens on a deep-copy of the policy ASTs so
the rule's `Schema` view stays read-only.

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

from pglast.ast import BoolExpr, Node, SubLink
from pglast.enums import BoolExprType
from pglast.stream import RawStream

from pgrls.ast_utils import is_literal_true
from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist


class _CannotStrip(Exception):
    """Raised when removing `OR true` would leave an OR with no
    remaining args (the predicate was vacuously true). There's no
    minimal predicate to keep, so the fixer skips the policy."""


def _strip_or_true(node: Any) -> tuple[Any, bool]:
    """Walk the tree; remove literal-`true` args from OR BoolExprs.

    Returns `(node, changed)`. Children are processed first so a
    nested OR that unwraps to a single arg is already reduced when
    its parent is examined. An OR left with exactly one arg after
    stripping is unwrapped to that arg; an OR left with zero args
    raises `_CannotStrip`.

    Mirrors the SEC011 rule's `_has_or_true` scope exactly: on a
    `SubLink` only the `testexpr` (the policy's own LHS of an
    `IN` / `ANY` / `ALL`) is in scope; the subquery's own
    `subselect` is NOT descended into. An `OR true` inside a
    subquery's WHERE doesn't make the outer policy admit every row
    — it's the subquery's predicate, which the rule deliberately
    ignores (`EXISTS (SELECT 1 FROM t WHERE flag OR true)` is a
    legitimate shape). Rewriting it would mutate a policy the rule
    calls clean and trip `pgrls fix --check` on zero violations.
    """
    if not isinstance(node, Node):
        return node, False

    if isinstance(node, SubLink):
        new_test, test_changed = _strip_or_true(node.testexpr)
        if test_changed:
            node.testexpr = new_test
        return node, test_changed

    changed = False
    for field_name in node:
        value = getattr(node, field_name, None)
        if isinstance(value, (list, tuple)):
            new_items: list[Any] = []
            list_changed = False
            for item in value:
                new_item, item_changed = _strip_or_true(item)
                new_items.append(new_item)
                list_changed = list_changed or item_changed
            if list_changed:
                setattr(node, field_name, type(value)(new_items))
                changed = True
        elif isinstance(value, Node):
            new_v, v_changed = _strip_or_true(value)
            if v_changed:
                setattr(node, field_name, new_v)
                changed = True

    if isinstance(node, BoolExpr) and node.boolop == BoolExprType.OR_EXPR:
        args = list(node.args or ())
        kept = [a for a in args if not is_literal_true(a)]
        if len(kept) != len(args):
            changed = True
            if not kept:
                raise _CannotStrip()
            if len(kept) == 1:
                # `a OR true` → `a` — unwrap the now-singleton OR.
                return kept[0], True
            node.args = tuple(kept)

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
                policy_id = f"{table.schema}.{table.name}.{policy.name}"
                if policy_id in skip:
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
                        location=policy_id,
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
