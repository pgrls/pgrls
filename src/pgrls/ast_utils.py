"""Pure-function helpers over pglast trees.

Used by AST-based rules (SEC004, HYG001) and by introspection to populate
Policy.using_ast / Policy.with_check_ast.

This module is internal; no API stability promise yet. The plugin
interface (third-party rule packages reaching for these helpers)
stays internal until v1.0.
"""
from __future__ import annotations

import sys
from typing import Any

import pglast
from pglast.ast import A_Star, BoolExpr, ColumnRef, FuncCall, Node, NullTest, RangeVar, SQLValueFunction, String, SubLink
from pglast.enums import BoolExprType, NullTestType, SQLValueFunctionOp


_LINT_AST_RULES_TAIL = (
    "AST-based rules (SEC004, SEC005, SEC008, SEC010, SEC011, "
    "SEC018, SEC019, HYG001, PERF001, PERF002) skipped for this "
    "clause."
)


def parse_expr(
    sql: str | None,
    *,
    location: str | None = None,
    clause: str | None = None,
    fail_message_tail: str | None = None,
) -> Any | None:
    """Parse a USING/WITH CHECK SQL fragment into a pglast AST node.

    Returns the expression node, or None if the input is empty or
    pglast cannot parse it. On parse failure, prints a one-line
    warning to stderr that names which policy and which clause
    couldn't be parsed — without that location, AST-based rules
    silently skip the policy with no signal in the lint output.
    Naming the policy lets the user grep `pg_policy` for the
    actual SQL pglast couldn't handle.

    The `fail_message_tail` kwarg lets the caller customize the
    "what got skipped" suffix on the warning line. Defaults to the
    lint-context message ("AST-based rules (SEC...) skipped...");
    `pgrls.diff` callers pass a diff-context tail so the user
    isn't told about lint rules that don't run during diff.

    Catches `pglast.parser.ParseError` specifically — any other
    exception (MemoryError, AttributeError from pglast shape
    drift, etc.) propagates so genuine bugs aren't swallowed as
    "could not parse" lines per policy.
    """
    if not sql:
        return None
    wrapped = f"SELECT ({sql}) AS _expr"
    try:
        parsed = pglast.parse_sql(wrapped)
    except pglast.parser.ParseError:
        # Compose a message that puts the policy ID first so it
        # grep-finds easily; fall back to the "no location" form
        # if the caller didn't pass one (e.g. a programmatic test
        # parsing a bare SQL fragment).
        if location:
            head = f"could not parse policy {location}"
            if clause:
                head += f" ({clause} clause)"
        else:
            head = "could not parse SQL fragment"
        tail = fail_message_tail if fail_message_tail is not None else _LINT_AST_RULES_TAIL
        print(
            f"pgrls: warning: {head}. {tail} Original SQL: {sql!r}",
            file=sys.stderr,
        )
        return None
    select_stmt = parsed[0].stmt
    target = select_stmt.targetList[0]
    return target.val


def top_level_disjuncts(node: Any) -> list[Any]:
    """If node is a top-level OR expression, return its disjunct children.

    Otherwise return a single-element list containing the node itself.
    """
    if isinstance(node, BoolExpr) and node.boolop == BoolExprType.OR_EXPR:
        return list(node.args or ())
    return [node]


def extract_column_refs(
    node: Any, *, exclude_sublinks: bool = False
) -> set[tuple[str, ...]]:
    """Walk the tree and return the set of ColumnRef name tuples.

    A column referenced as `email` produces `("email",)`. A qualified
    reference `users.email` produces `("users", "email")`. Wildcards (`*`)
    are skipped. When `exclude_sublinks=True`, refs inside SubLink nodes
    are not collected — used by HYG001 to avoid false positives on
    subquery columns from other tables.
    """
    refs: set[tuple[str, ...]] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            # A few pglast Node fields are tuple-of-tuples rather
            # than tuple-of-Node — most notably
            # `RangeFunction.functions` which is
            # `tuple[tuple[FuncCall, None]]` (the inner tuple holds
            # the call plus optional column-list aliasing). The
            # field-iteration loop below handles the outer level,
            # so each *inner* tuple lands here on recursion. Walk
            # every item; the type guards below filter back to
            # actual nodes.
            for item in n:
                walk(item)
            return
        if exclude_sublinks and isinstance(n, SubLink):
            # Walk the test expression (e.g. `tenant_id` in `tenant_id IN (...)`)
            # but skip the inner subquery to avoid collecting refs from other tables.
            walk(n.testexpr)
            return
        if isinstance(n, ColumnRef):
            names: list[str] = []
            for f in n.fields or ():
                if isinstance(f, String):
                    names.append(f.sval)
                elif isinstance(f, A_Star):
                    return  # bail out — wildcard ref like t.* or *
            if names:
                refs.add(tuple(names))
            return
        if isinstance(n, Node):
            for field_name in n:
                value = getattr(n, field_name, None)
                if isinstance(value, (list, tuple)):
                    for item in value:
                        walk(item)
                elif isinstance(value, Node):
                    walk(value)

    walk(node)
    return refs


_SQL_VALUE_FUNCTION_NAMES: dict[Any, str] = {
    SQLValueFunctionOp.SVFOP_CURRENT_USER: "current_user",
    SQLValueFunctionOp.SVFOP_SESSION_USER: "session_user",
    SQLValueFunctionOp.SVFOP_USER: "user",
    SQLValueFunctionOp.SVFOP_CURRENT_ROLE: "current_role",
}


def find_func_calls(
    node: Any, names: set[str], *, exclude_sublinks: bool = False
) -> list[Any]:
    """Find FuncCall and SQLValueFunction nodes whose name matches `names`.

    For FuncCall, both the fully-qualified name (`auth.uid`) and the bare
    name (`uid`) are checked; either match counts. For SQLValueFunction
    (the AST node Postgres emits for grammar-special identifiers like
    `current_user`), the node fires when its op corresponds to a name in
    the set.

    When `exclude_sublinks=True`, calls inside the SubLink's subselect
    are skipped, but the SubLink's `testexpr` (the LHS of `IN`/`ANY`/
    `ALL`) is still walked. PERF001 uses this to detect "unwrapped"
    auth calls: `(SELECT auth.uid())` lives inside the subselect and is
    correctly skipped, while `auth.uid() IN (SELECT ...)` keeps firing
    because the auth call is on the LHS, not in the subselect. Mirrors
    `extract_column_refs`'s shape.
    """
    matches: list[Any] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            # See `extract_column_refs.walk` for the rationale —
            # `RangeFunction.functions` is tuple-of-tuples and the
            # inner tuple lands here on recursion. The set-returning
            # function in `SELECT * FROM f()` lives inside that
            # inner tuple, so without this branch VIEW004 would
            # silently miss SECDEF calls used in FROM clauses.
            for item in n:
                walk(item)
            return
        if exclude_sublinks and isinstance(n, SubLink):
            walk(n.testexpr)
            return
        if isinstance(n, FuncCall):
            parts: list[str] = []
            for f in n.funcname or ():
                if isinstance(f, String):
                    parts.append(f.sval)
            if parts:
                qualified = ".".join(parts)
                bare = parts[-1]
                if qualified in names or bare in names:
                    matches.append(n)
        if isinstance(n, SQLValueFunction):
            name = _SQL_VALUE_FUNCTION_NAMES.get(n.op)
            if name and name in names:
                matches.append(n)
        if isinstance(n, Node):
            for field_name in n:
                value = getattr(n, field_name, None)
                if isinstance(value, (list, tuple)):
                    for item in value:
                        walk(item)
                elif isinstance(value, Node):
                    walk(value)

    walk(node)
    return matches


def extract_range_vars(node: Any) -> list[tuple[str | None, str]]:
    """Walk the tree and return every RangeVar's `(schemaname, relname)`.

    A `FROM public.secret` produces `("public", "secret")`. A bare
    `FROM secret` (no schema prefix) produces `(None, "secret")` —
    the caller is responsible for resolving bare names against a
    known set of qualified table refs (VIEW004 does this against
    its set of RLS-protected tables).

    Covers SELECT/INSERT/UPDATE/DELETE: RangeVar appears in
    `SelectStmt.fromClause`, `InsertStmt.relation`,
    `UpdateStmt.relation`, `DeleteStmt.relation`. Walks Node fields
    and tuple/list containers like `extract_column_refs` and
    `find_func_calls` — same shape, same recursion semantics for
    `RangeFunction.functions`-style nested tuples.
    """
    refs: list[tuple[str | None, str]] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, RangeVar):
            # `relname` is the table name; `schemaname` may be None
            # when the SQL writer didn't qualify it. Don't synthesize
            # a schema here — the caller knows the introspection
            # scope and resolves bare names against it.
            relname = getattr(n, "relname", None)
            if isinstance(relname, str) and relname:
                schemaname = getattr(n, "schemaname", None)
                refs.append((schemaname, relname))
            # Don't return here — a RangeVar can in principle have
            # nested children (e.g. `alias` is a separate field but
            # carries no further range vars). Walking children is
            # safe; just skip the early return.
        if isinstance(n, Node):
            for field_name in n:
                value = getattr(n, field_name, None)
                if isinstance(value, (list, tuple)):
                    for item in value:
                        walk(item)
                elif isinstance(value, Node):
                    walk(value)

    walk(node)
    return refs


def match_is_null(node: Any) -> tuple[Any, bool] | None:
    """If node is `X IS NULL` or `X IS NOT NULL`, return (X, is_null_flag).

    Returns None for any other expression shape.
    """
    if isinstance(node, NullTest):
        is_null = node.nulltesttype == NullTestType.IS_NULL
        return (node.arg, is_null)
    return None
