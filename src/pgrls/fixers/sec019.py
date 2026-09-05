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

The fixer rewrites each one-argument call to the two-argument
form with `true`:

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

from pglast.ast import A_Const, A_Expr, BoolExpr, Boolean, CaseExpr, CoalesceExpr, NullTest
from pglast.enums import A_Expr_Kind, BoolExprType

from pgrls.ast_utils import is_builtin_current_setting, transform_tree
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


def _is_null_tolerant(node: Any) -> bool:
    """Is `node` a construct under which a NULL can admit a row?

    `IS [NOT] NULL`, `COALESCE`, `NULLIF`, `IS [NOT] DISTINCT FROM`, `CASE`
    and `NOT` all give a NULL operand a truth-affecting role — the exact
    positions where turning a raising call into a NULL-returning one widens
    the policy. A plain comparison (`=`, `<`, `IN`) does not: NULL there is
    UNKNOWN and hides the row, so it is left to the normal rewrite.
    """
    if isinstance(node, (NullTest, CoalesceExpr, CaseExpr)):
        return True
    if isinstance(node, A_Expr) and node.kind in (
        A_Expr_Kind.AEXPR_DISTINCT,
        A_Expr_Kind.AEXPR_NOT_DISTINCT,
        A_Expr_Kind.AEXPR_NULLIF,
    ):
        return True
    return isinstance(node, BoolExpr) and node.boolop == BoolExprType.NOT_EXPR


def _add_missing_ok(node: Any) -> tuple[Any, bool]:
    """Walk the tree; append `true` to every one-arg
    `current_setting` call's `args`. Returns `(node, changed)`.

    The boolean `true` is constructed as `A_Const(val=Boolean
    (boolval=True))` — the same shape `ast_utils.is_literal_true`
    matches, so any later check reading the rewritten AST sees a
    literal true exactly as it would have from a hand-written
    two-argument call.

    The recursion is `ast_utils.transform_tree`; the leaf function
    below carries the only SEC019-specific behaviour: a one-arg
    `current_setting` call is mutated in place to append the
    missing_ok arg (a terminal `(node, True)`); every other node
    returns `None` to recurse. Unlike PERF001 there is no
    don't-descend guard for *most* of the tree — but a call sitting in a
    NULL-tolerant position is left alone (see `_is_null_tolerant`).

    Why: the one-argument form RAISES on an unset GUC, which fails
    closed (0 rows). The two-argument form returns NULL. In an ordinary
    `col = current_setting(...)` comparison NULL still hides the row, so
    the rewrite is behaviour-preserving. But under a NULL-*tolerant*
    construct the rewrite can WIDEN access — `current_setting('app.t') IS
    NULL OR …` goes from an error to a TRUE disjunct, `COALESCE(
    current_setting('app.t'), 'x')` to a fallback match, `col IS NOT
    DISTINCT FROM current_setting('app.t')` to a match on NULL columns.
    Verified live on PG16: rewriting the IS NULL shape let an anonymous
    session read every row the raising form had withheld. A fixer may
    never broaden, so those subtrees are skipped: the finding stays open
    there for human review while sibling calls in safe positions are
    still fixed.
    """

    def leaf(n: Any) -> tuple[Any, bool] | None:
        if _is_null_tolerant(n):
            # Terminal, unchanged: do not descend into a subtree where a
            # returned NULL could admit a row.
            return n, False
        if _is_one_arg_current_setting(n):
            # Mutate the FuncCall in place — append the missing_ok
            # arg as a literal `true`.
            new_args = (*n.args, A_Const(val=Boolean(boolval=True)))
            n.args = new_args
            return n, True
        return None

    return transform_tree(node, leaf)


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
