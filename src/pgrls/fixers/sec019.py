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

from pglast.ast import A_Const, Boolean

from pgrls.ast_utils import func_name_parts, transform_tree
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
    qualified, bare = func_name_parts(node)
    if qualified is None:
        return False
    if bare != _CURRENT_SETTING and qualified != f"pg_catalog.{_CURRENT_SETTING}":
        return False
    args = node.args or ()
    return len(args) == 1


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
    don't-descend guard — SEC019 rewrites matching calls anywhere in
    the tree.
    """

    def leaf(n: Any) -> tuple[Any, bool] | None:
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
