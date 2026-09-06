"""SEC019 fixer — add `missing_ok = true` to one-arg current_setting() calls.

SEC019 flags a policy whose `USING` or `WITH CHECK` calls
`current_setting(name)` — the one-argument overload. The
one-argument form raises `ERROR: unrecognized configuration
parameter "name"` when the parameter has not been set in the
session, so every query against the table errors when a request
reaches the database without its context configured. The
two-argument form `current_setting(name, missing_ok)` returns
NULL instead when `missing_ok` is true; in the typical `column =
current_setting(...)` predicate that NULL simply matches no rows.

The fixer rewrites a one-argument call to the two-argument form with
`true` only where it is a direct comparison operand under an AND-only
chain (`_add_missing_ok`); every other position is left for review:

    current_setting('app.tenant')        →  current_setting('app.tenant', true)
    pg_catalog.current_setting('app.x')  →  pg_catalog.current_setting('app.x', true)

and emits the corresponding `ALTER POLICY` statement so writes
to the policy use the safer overload. Both `USING` and `WITH
CHECK` are inspected; only clauses that actually changed are
re-emitted in the `ALTER POLICY` so the produced migration is
the minimal diff.

`pgrls fix` is opinionated about the choice. SEC019 the rule
notes that "neither overload is a security hole — the one-arg
form fails closed" and is **info** severity precisely because
the choice is a judgement call: the loud raise surfaces a
missing-context bug immediately, while the quiet empty result is
friendlier but can mask it. This fixer picks the
quiet-empty-result side (the two-arg form), matching the
overload the rest of a typical policy set converges on; an
operator who genuinely wants raise-on-unset allowlists the
policy in `[lint.rules.SEC019]`. The Fix description spells out
the trade-off so an operator running `pgrls fix --apply` knows
which way the rewrite goes.

The detection set mirrors the SEC019 rule's exactly (bare or
`pg_catalog`-qualified `current_setting`), and the AST mutation
happens on a deep-copy of the policy ASTs so the rule's `Schema`
view is not silently altered for any downstream consumer.
"""
from __future__ import annotations

import copy
from typing import Any

from pglast.ast import (
    A_Const,
    A_Expr,
    BoolExpr,
    Boolean,
    ResTarget,
    SelectStmt,
    String,
    SubLink,
    TypeCast,
)
from pglast.enums import A_Expr_Kind, BoolExprType, SubLinkType

from pgrls.ast_utils import is_builtin_current_setting
from pgrls.fixers import Fix
from pgrls.fixers._idents import alter_policy
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist

_CURRENT_SETTING = "current_setting"


def _is_one_arg_current_setting(node: Any) -> bool:
    """True if `node` is a one-argument `current_setting` FuncCall.

    Matches bare `current_setting(...)` and the pg_catalog-
    qualified form — the same shape SEC019's `find_func_calls`
    detection accepts.
    """
    # Exactly the rule's gate (`is_builtin_current_setting`): a user-defined
    # `myschema.current_setting(...)` is not the builtin, is not flagged by
    # SEC019, and must not be rewritten — under `--apply` a UDF without a
    # two-argument overload would fail the whole batch.
    if not is_builtin_current_setting(node):
        return False
    args = node.args or ()
    return len(args) == 1


_COMPARISON_OPS = frozenset({"=", "<>", "!=", "<", ">", "<=", ">="})


def _comparison_op(node: Any) -> bool:
    if not isinstance(node, A_Expr) or node.kind != A_Expr_Kind.AEXPR_OP:
        return False
    names = list(node.name or ())
    return (
        len(names) == 1
        and isinstance(names[0], String)
        and names[0].sval in _COMPARISON_OPS
    )


def _unwrap_operand(node: Any) -> Any:
    """Strip casts and the PERF001 `(SELECT …)` InitPlan wrapper (a FROM-less,
    single-target scalar sub-select) from a comparison operand."""
    while True:
        if isinstance(node, TypeCast):
            node = node.arg
            continue
        if (
            isinstance(node, SubLink)
            and node.subLinkType == SubLinkType.EXPR_SUBLINK
            and isinstance(node.subselect, SelectStmt)
            and not node.subselect.fromClause
            and not node.subselect.whereClause
            and len(node.subselect.targetList or ()) == 1
            and isinstance(node.subselect.targetList[0], ResTarget)
        ):
            node = node.subselect.targetList[0].val
            continue
        return node


def _add_missing_ok(node: Any) -> tuple[Any, bool]:
    """Rewrite one-arg `current_setting` calls that sit in a PROVABLY
    row-hiding position; leave every other occurrence alone.

    A fixer may never broaden. The one-argument form RAISES when the GUC is
    unset — the statement errors and the caller gets no rows — while the
    two-argument form returns NULL. NULL hides a row only when the whole
    predicate then fails to be TRUE, and that holds in exactly one shape: the
    call is a direct operand of a comparison (`=`, `<>`, `<`, …, through
    casts or the PERF001 `(SELECT …)` wrap) and every connective above that
    comparison is `AND`. Anywhere else a returned NULL can admit a row —
    `IS NULL` / `IS NOT FALSE` make it TRUE, `COALESCE` / `GREATEST` / `NULLIF`
    substitute a value, `IS NOT DISTINCT FROM` matches NULL columns, and under
    `OR` / `IN (…)` / `= ANY(ARRAY[…])` a sibling branch admits rows the
    raising form withheld. Iteration 1 denylisted the constructs it knew; the
    review found three more (BooleanTest, GREATEST/LEAST, `= ANY`) within
    hours — a denylist recurs by construction, so this is an ALLOWLIST: only
    the row-hiding shape is rewritten, and the finding stays open everywhere
    else for human review.

    The tree is mutated in place (the FuncCall gains its `true` arg); returns
    `(node, changed)`.
    """
    changed = False

    def rewrite_operand(operand: Any) -> None:
        nonlocal changed
        target = _unwrap_operand(operand)
        if _is_one_arg_current_setting(target):
            target.args = (*target.args, A_Const(val=Boolean(boolval=True)))
            changed = True

    def walk(n: Any) -> None:
        if isinstance(n, BoolExpr) and n.boolop == BoolExprType.AND_EXPR:
            for arg in n.args or ():
                walk(arg)
            return
        if _comparison_op(n):
            rewrite_operand(n.lexpr)
            rewrite_operand(n.rexpr)
            return
        # OR / NOT / any other construct: not provably row-hiding — abstain.

    walk(node)
    return node, changed


class SEC019Fixer:
    rule_id: str = "SEC019"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        skip = parse_policy_id_allowlist("SEC019", options)
        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in skip:
                    continue

                # Mutate deep-copies so the rule's `Schema` view is
                # untouched — fixer invariant is "read-only over
                # the input Schema", mirroring PERF001Fixer.
                using_changed = False
                new_using_ast: Any = None
                if policy.using_ast is not None:
                    candidate = copy.deepcopy(policy.using_ast)
                    new_using_ast, using_changed = _add_missing_ok(candidate)
                with_check_changed = False
                new_wc_ast: Any = None
                if policy.with_check_ast is not None:
                    candidate = copy.deepcopy(policy.with_check_ast)
                    new_wc_ast, with_check_changed = _add_missing_ok(
                        candidate
                    )

                if not (using_changed or with_check_changed):
                    continue

                # Only re-emit the clause(s) that actually changed, so
                # the migration is the minimal diff. `alter_policy`
                # renders each provided clause through RawStream and
                # orders USING before WITH CHECK.
                stmt = alter_policy(
                    table,
                    policy.name,
                    using_ast=new_using_ast if using_changed else None,
                    with_check_ast=(
                        new_wc_ast if with_check_changed else None
                    ),
                )

                out.append(
                    Fix(
                        rule_id="SEC019",
                        location=pid,
                        sql=stmt,
                        clauses=frozenset(
                            c
                            for c, ch in (
                                ("using", using_changed),
                                ("with_check", with_check_changed),
                            )
                            if ch
                        ),
                        description=(
                            f"Add `, true` (missing_ok = true) to "
                            f"current_setting() in policy "
                            f"{policy.name!r} on "
                            f"{table.qualified_name} so a request "
                            "reaching the database without its "
                            "session context quietly matches no "
                            "rows (the predicate becomes "
                            "`col = NULL`) instead of erroring on "
                            "every query. The raise-on-unset "
                            "behaviour of the one-arg form is a "
                            "valid alternative — allowlist the "
                            "policy in [lint.rules.SEC019] if the "
                            "loud failure is intentional."
                        ),
                    )
                )
        return out
