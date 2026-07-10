"""Shared caller-binding analysis for auth-table reads.

The question "does this SELECT read a sensitive auth table (``auth.users``)
*without* constraining the read to the calling user" recurs in more than one
rule:

* **SEC036** asks it of a policy's ``EXISTS (SELECT ... FROM auth.users ...)``
  sub-select — an unbound admin-any check.
* **SEC052** asks it of a *view body* that selects from ``auth.users`` and is
  exposed over the API — an unbound read leaks every user's row.

Both need the same two primitives over a ``SelectStmt``:

1. **target detection** — does the FROM clause (through JOINs and derived
   tables, set-op-aware) read one of the target tables? (`from_clause_targets`)
2. **caller-binding detection** — does a qual (WHERE / HAVING / JOIN ``ON``,
   including inside derived tables) bind the row to the caller via a binding
   auth call (``auth.uid()`` etc.), counting the tight ``= (SELECT auth.uid())``
   / ``= ANY (SELECT auth.uid())`` forms but *not* an unrelated auth call buried
   in a nested EXISTS/ANY/ALL body? (`from_clause_binding_quals` + `qual_binds_caller`)

This module is the single source of truth for both so the two rules can never
drift — every FP/FN lesson baked into these comments (JOIN descent, derived-
table symmetry, set-op arms, the nested-sublink exclusion) applies identically
wherever an auth-table read is judged. SEC036's own regression suite (31 cases
spanning review rounds R3–R19) covers this logic.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import (
    JoinExpr,
    Node,
    RangeSubselect,
    RangeVar,
    SelectStmt,
    SubLink,
)
from pglast.enums import SetOperation, SubLinkType

from pgrls.ast_utils import find_func_calls

# The default caller-binding signals: a reference to any of these in a qual
# means the read is constrained to the calling session, not "any row".
DEFAULT_BINDING_FUNCTIONS: frozenset[str] = frozenset({
    "auth.uid",
    "auth.role",
    "auth.jwt",
    "current_user",
    "session_user",
    "current_setting",
})


def select_from_items(sel: Any) -> list[Any]:
    """A SelectStmt's effective FROM-clause items.

    A set operation (UNION / INTERSECT / EXCEPT) leaves `fromClause`
    None and stores the real FROM items in `larg` / `rarg`, so flatten
    those arms' FROM items. This is the single place the set-op split is
    handled, so the target scan (`from_clause_targets` and the derived-
    table descent in `from_item_range_vars`) stays in lockstep with the
    set-op-aware binding scan (`from_clause_binding_quals`). Returns []
    for a non-SelectStmt.
    """
    if not isinstance(sel, SelectStmt):
        return []
    if sel.op != SetOperation.SETOP_NONE:
        return [
            *select_from_items(sel.larg),
            *select_from_items(sel.rarg),
        ]
    return list(sel.fromClause or ())


def from_item_range_vars(from_item: Any) -> list[RangeVar]:
    """RangeVars reachable from a single FROM-clause item.

    A bare `FROM auth.users` is a `RangeVar`; `FROM a JOIN b ON …` is a
    `JoinExpr` whose `larg` / `rarg` hold the (possibly further-nested)
    operands. The original walk inspected only top-level `RangeVar`s,
    so an `auth.users` reached through a JOIN was invisible and the
    binding-free bypass slipped through. Recurse into `JoinExpr`
    arms so the target table is found however it's joined in.
    """
    out: list[RangeVar] = []

    def walk(item: Any) -> None:
        if isinstance(item, RangeVar):
            out.append(item)
        elif isinstance(item, JoinExpr):
            walk(item.larg)
            walk(item.rarg)
        elif isinstance(item, RangeSubselect):
            # `FROM (SELECT ... FROM auth.users) sub` — the target
            # table is one level down in the sub-select's own FROM.
            # Recurse its effective FROM items so a read that reaches
            # the target through a derived table is still detected —
            # including when the derived table is itself a set operation
            # (`FROM (SELECT … FROM auth.users UNION SELECT …) sub`),
            # whose FROM items live in larg/rarg, not fromClause.
            for fc in select_from_items(item.subquery):
                walk(fc)

    walk(from_item)
    return out


def matches_target(rv: RangeVar, target_tables: set[tuple[str, str]]) -> bool:
    # `schemaname` is None for unqualified references (`FROM users`) —
    # those default to whatever's on the caller's `search_path`. We
    # can't statically tell whether an unqualified `users` resolves to
    # `auth.users` or `public.users`, so we require an explicit
    # `auth.users` qualification. (Users who want bare-`users` matching
    # can add `["public.users"]` etc. to target_tables.)
    return (
        rv.schemaname is not None
        and (rv.schemaname.lower(), rv.relname.lower()) in target_tables
    )


def from_clause_targets(
    sel: Any, target_tables: set[tuple[str, str]]
) -> list[RangeVar]:
    """Target RangeVars in a sub-select's FROM clause (JOINs included).

    `select_from_items` flattens a top-level set operation
    (UNION / INTERSECT / EXCEPT) into its arms' FROM items — so a
    `SELECT 1 FROM auth.users … UNION …` is examined — and
    `from_item_range_vars` descends JOINs and derived tables (the latter
    set-op-aware too). The binding scan is set-op-aware in lockstep so a
    correctly-bound set-op read never begins to false-fire.
    """
    out: list[RangeVar] = []
    for from_item in select_from_items(sel):
        for rv in from_item_range_vars(from_item):
            if matches_target(rv, target_tables):
                out.append(rv)
    return out


def from_clause_binding_quals(sel: Any) -> list[Any]:
    """Every qual in `sel`'s FROM clause where a caller binding can live.

    JOIN `ON` clauses (`JOIN auth.users u ON u.id = auth.uid()`), AND —
    because target detection recurses into derived tables
    (`from_item_range_vars` handles RangeSubselect) — the WHERE and JOIN
    ONs of those derived tables too, recursively. Without the
    derived-table descent a read that binds the caller INSIDE a derived
    table (`FROM (SELECT id FROM auth.users WHERE id = auth.uid()) sub`)
    false-fires: the target is found one level down but the binding there
    is never inspected (asymmetry with target detection).
    """
    quals: list[Any] = []

    def walk_select(s: Any) -> None:
        if s is None:
            return
        # Set operation: the binding quals live in the arms, not here.
        if s.op != SetOperation.SETOP_NONE:
            walk_select(s.larg)
            walk_select(s.rarg)
            return
        if s.whereClause is not None:
            quals.append(s.whereClause)
        if s.havingClause is not None:
            quals.append(s.havingClause)
        for from_item in s.fromClause or ():
            walk_item(from_item)

    def walk_item(item: Any) -> None:
        if isinstance(item, JoinExpr):
            if item.quals is not None:
                quals.append(item.quals)
            walk_item(item.larg)
            walk_item(item.rarg)
        elif isinstance(item, RangeSubselect):
            sub = item.subquery
            if isinstance(sub, SelectStmt):
                walk_select(sub)

    if sel is not None:
        if sel.op != SetOperation.SETOP_NONE:
            # Top-level set-op: collect the binding quals of both arms
            # (their WHERE / HAVING / JOIN-ONs) so a set-op read that
            # binds the caller in an arm is recognized, in lockstep with
            # target detection above.
            walk_select(sel.larg)
            walk_select(sel.rarg)
        else:
            for from_item in sel.fromClause or ():
                walk_item(from_item)
    return quals


def scalar_value_subselects(qual: Any) -> list[Any]:
    """Sub-selects of SCALAR (EXPR_SUBLINK) sub-links reachable in
    `qual` without crossing a non-scalar (EXISTS/ANY/ALL) sub-link.

    A scalar `(SELECT auth.uid())` used as a value genuinely binds the
    caller (the PERF001-recommended wrap). A nested EXISTS/ANY/ALL is a
    SEPARATE existence test, not a binding of the outer read, so we
    must not look inside it — else an admin-any bypass whose WHERE
    merely contains an unrelated nested auth call (e.g. a correlated
    audit sub-select) would be treated as caller-bound and the real
    leak suppressed (the SEC036 false negative).
    """
    out: list[Any] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink):
            walk(n.testexpr)
            if (
                n.subLinkType == SubLinkType.EXPR_SUBLINK
                and n.subselect is not None
            ):
                out.append(n.subselect)
                walk(n.subselect)
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(qual)
    return out


def is_single_auth_target_select(
    subselect: Any, binding_functions: set[str]
) -> bool:
    """True if `subselect` is a single-target ``SELECT <auth call>`` whose
    sole target expression is a binding auth call.

    A multi-target select, or one whose lone target is NOT the auth call
    (e.g. a membership lookup ``SELECT user_id FROM m WHERE u = auth.uid()``
    where the auth call lives in the WHERE), returns False — this keeps the
    ANY/IN binding exception below as tight as the scalar form and never
    descends into a body looking for an arbitrary nested auth call.
    """
    if not isinstance(subselect, SelectStmt):
        return False
    targets = subselect.targetList
    if not targets or len(targets) != 1:
        return False
    return bool(
        find_func_calls(
            getattr(targets[0], "val", None),
            binding_functions,
            exclude_sublinks=True,
        )
    )


def any_subselect_binds_caller(
    qual: Any, binding_functions: set[str]
) -> bool:
    """True if `qual` binds the caller via an IN / ``= ANY`` sub-query
    whose sub-select projects EXACTLY a single binding auth call —
    ``<expr> IN (SELECT auth.uid())`` / ``<expr> = ANY (SELECT auth.uid())``.

    Postgres parses BOTH forms as ``ANY_SUBLINK``, which
    `scalar_value_subselects` deliberately does not descend into (so an
    unrelated auth call buried in a nested ANY/ALL/EXISTS body cannot mask
    a real admin-any leak — the SEC036 false negative). This is the
    narrow, sound exception: a single-target sub-select whose sole target
    IS the auth call genuinely constrains the row to the caller, exactly
    like the scalar ``col = (SELECT auth.uid())`` (EXPR_SUBLINK) form. The
    single-target gate keeps the FN-avoidance intact.
    """
    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink):
            # Walk the testexpr (the LHS of IN/ANY) for nested sub-links,
            # but do NOT descend into the sub-select body except for the
            # tight single-target binding check — preserving the
            # FN-avoidance that `scalar_value_subselects` documents.
            walk(n.testexpr)
            if (
                n.subLinkType == SubLinkType.ANY_SUBLINK
                and is_single_auth_target_select(
                    n.subselect, binding_functions
                )
            ):
                found = True
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(qual)
    return found


def qual_binds_caller(qual: Any, binding_functions: set[str]) -> bool:
    """True if a binding auth call in `qual` constrains the read to
    the calling user.

    A binding call counts when it is (1) directly in the qual or in an
    IN/ANY/ALL testexpr — `exclude_sublinks=True` stops the search at
    every sub-select boundary; (2) inside a scalar value sub-select
    (`col = (SELECT auth.uid())`); or (3) the target of a single-target
    IN/ANY sub-query (`col IN (SELECT auth.uid())` / `= ANY (SELECT
    auth.uid())`). A call inside a nested EXISTS/ANY/ALL body that is NOT
    that tight single-target binding form is deliberately NOT counted
    (see `scalar_value_subselects` / `any_subselect_binds_caller`).
    """
    if find_func_calls(qual, binding_functions, exclude_sublinks=True):
        return True
    if any(
        find_func_calls(sub, binding_functions)
        for sub in scalar_value_subselects(qual)
    ):
        return True
    return any_subselect_binds_caller(qual, binding_functions)


def select_binds_caller(sel: Any, binding_functions: set[str]) -> bool:
    """True if the SelectStmt `sel` constrains its rows to the calling user.

    Checks `sel`'s top-level WHERE *and* HAVING, plus every JOIN ``ON`` and
    derived-table qual (`from_clause_binding_quals`, which also descends the
    arms of a top-level set operation). A binding predicate (`id = auth.uid()`)
    in any of these scopes the read to the caller — so the sensitive read is
    the caller's own row(s), not "every row". Set-op safe: a top-level
    UNION leaves `whereClause` None and its arms' WHEREs are collected by
    `from_clause_binding_quals`.

    Used by SEC036 (of a policy EXISTS sub-select) and SEC052 (of a view
    body): both must not fire when the auth-table read is caller-bound.
    """
    if sel is None:
        return False
    candidates = [
        getattr(sel, "whereClause", None),
        getattr(sel, "havingClause", None),
        *from_clause_binding_quals(sel),
    ]
    return any(
        c is not None and qual_binds_caller(c, binding_functions)
        for c in candidates
    )
