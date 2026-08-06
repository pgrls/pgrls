"""Pure-function helpers over pglast trees.

Used by AST-based rules (SEC004, HYG001) and by introspection to populate
Policy.using_ast / Policy.with_check_ast.

This module is internal; no API stability promise yet. The plugin
interface (third-party rule packages reaching for these helpers)
stays internal until v1.0.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Callable
from typing import Any

import pglast
from pglast.ast import A_Const, A_Star, BoolExpr, Boolean, ColumnRef, DeleteStmt, FuncCall, InsertStmt, JoinExpr, Node, NullTest, RangeFunction, RangeSubselect, RangeVar, SelectStmt, SQLValueFunction, String, SubLink, TypeCast, UpdateStmt
from pglast.enums import BoolExprType, NullTestType, SetOperation, SQLValueFunctionOp


_LINT_AST_RULES_TAIL = (
    "AST-based rules (SEC004, SEC005, SEC008, SEC010, SEC011, "
    "SEC018, SEC019, SEC020, HYG001, PERF001, PERF002) skipped "
    "for this clause."
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

    def _warn_unparseable() -> None:
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

    wrapped = f"SELECT ({sql}) AS _expr"
    try:
        parsed = pglast.parse_sql(wrapped)
    except pglast.parser.ParseError:
        _warn_unparseable()
        return None
    select_stmt = parsed[0].stmt
    # Unbalanced parens in the fragment can let it escape the
    # `SELECT (...)` wrapper into a set operation (UNION/INTERSECT/
    # EXCEPT) or another non-SELECT shape whose `targetList` is None —
    # `targetList[0]` would then raise TypeError/IndexError. Treat any
    # non-scalar-expression shape as unparseable (same warning + None as
    # a ParseError) so callers' fallbacks engage (diff requires_review,
    # AST rules skip the clause).
    if not isinstance(select_stmt, SelectStmt) or not select_stmt.targetList:
        _warn_unparseable()
        return None
    target = select_stmt.targetList[0]
    return target.val


def flatten_or_disjuncts(node: Any) -> list[Any]:
    """Return every disjunct of a (possibly nested) OR expression.

    Flattens nested OR `BoolExpr` nodes: `A OR (B OR C)` yields
    `[A, B, C]`. OR is associative and
    pglast preserves explicit parenthesization as a nested `BoolExpr`,
    so the natural authoring order `<real check> OR (<other> OR
    auth() IS NULL)` would otherwise hide the trailing disjunct from a
    caller (e.g. SEC004) that only splits the outermost OR.

    Recursion is into OR `BoolExpr` args ONLY. AND / NOT `BoolExpr`s
    and `SubLink`s are returned as opaque single disjuncts — they are
    not part of the same disjunction (an `IS NULL` under an `AND`, a
    `NOT`, or inside a subquery is not a standalone OR-disjunct), so
    the caller handles them atomically. A non-OR `node` yields
    `[node]`.
    """
    if not (
        isinstance(node, BoolExpr) and node.boolop == BoolExprType.OR_EXPR
    ):
        return [node]
    disjuncts: list[Any] = []
    for arg in node.args or ():
        if isinstance(arg, BoolExpr) and arg.boolop == BoolExprType.OR_EXPR:
            disjuncts.extend(flatten_or_disjuncts(arg))
        else:
            disjuncts.append(arg)
    return disjuncts


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


def own_column_ref(ref: tuple[str, ...], table: Any) -> str | None:
    """The column name ``ref`` denotes if it is an own-table column, else None.

    ``ref`` is a column reference as produced by ``extract_column_refs``:
    ``(col,)`` (bare), ``(table, col)``, or ``(schema, table, col)``. A bare
    ref matches against ``table.columns``; qualified refs must also match the
    table's name (and schema). Single source of truth for "is this an own
    column" — previously copy-pasted as the ``_is_own_column_ref`` /
    ``_own_columns`` ladder across SEC005, SEC018, SEC030, SEC035, PERF003.
    Returns the column name (truthy) on a match so callers can use it either
    as a boolean test or to collect matched names.
    """
    if len(ref) == 1:
        return ref[0] if ref[0] in table.columns else None
    if len(ref) == 2:
        return (
            ref[1] if ref[0] == table.name and ref[1] in table.columns else None
        )
    if len(ref) == 3:
        return (
            ref[2]
            if ref[0] == table.schema
            and ref[1] == table.name
            and ref[2] in table.columns
            else None
        )
    return None


def transform_tree(
    node: Any,
    leaf_fn: Callable[[Any], tuple[Any, bool] | None],
) -> tuple[Any, bool]:
    """Recursively rewrite a pglast tree, dispatched by `leaf_fn`.

    `leaf_fn(node)` is consulted for every node, in pre-order, BEFORE
    any descent — matching the hand-written fixer walkers it replaces,
    which test their matcher first. It returns either:

    * `(new_node, changed)` — a TERMINAL result: this node (and its
      subtree) is not descended into; `new_node` takes its place and
      `changed` bubbles up. Use this both to rewrite a matched node
      (`(replacement, True)`) and to deliberately skip a subtree
      without changing it (`(node, False)` — e.g. PERF001 declines to
      descend into an *uncorrelated* `SubLink` subselect, whose calls
      already run once per statement).
    * `None` — not terminal: recurse into this node's children.

    On the recursive path, every `Node`-typed field and every item of
    a list/tuple-typed field is transformed. A container field is only
    rebuilt (and re-`setattr`'d) when at least one of its items
    changed, preserving the original container type
    (`type(value)(new_items)`); a scalar `Node` field is only
    re-`setattr`'d when it changed. The node is mutated in place and
    returned as the SAME object, so callers that need the input
    untouched must pass a deep copy — exactly as the original
    `_wrap_unwrapped_calls` / `_add_missing_ok` required.

    The shared descent body for PERF001's `(SELECT …)` wrapping and
    SEC019's `current_setting(…, true)` rewrite, which were
    byte-identical below the leaf checks. `leaf_fn` carries the only
    per-fixer logic (match test, replacement shape, and — for PERF001
    — the don't-descend-into-SubLink guard).
    """
    result = leaf_fn(node)
    if result is not None:
        return result
    if not isinstance(node, Node):
        return node, False

    changed = False
    for field_name in node:
        value = getattr(node, field_name, None)
        if isinstance(value, (list, tuple)):
            new_items: list[Any] = []
            list_changed = False
            for item in value:
                new_item, item_changed = transform_tree(item, leaf_fn)
                new_items.append(new_item)
                list_changed = list_changed or item_changed
            if list_changed:
                setattr(node, field_name, type(value)(new_items))
                changed = True
        elif isinstance(value, Node):
            new_v, v_changed = transform_tree(value, leaf_fn)
            if v_changed:
                setattr(node, field_name, new_v)
                changed = True
    return node, changed


def func_name_parts(node: Any) -> tuple[str | None, str | None]:
    """Pull the dotted name out of a `FuncCall`, as `(qualified, bare)`.

    `node.funcname` is a tuple of `String` (and, for `*`, `A_Star`)
    nodes. `auth.uid(...)` yields `funcname = (String("auth"),
    String("uid"))` → `("auth.uid", "uid")`; a bare `uid(...)` →
    `("uid", "uid")`. Returns `(None, None)` when `node` is not a
    `FuncCall` or carries no `String` name parts.

    Single source of truth for the "qualified name and bare name of a
    function call" extraction that `find_func_calls` and several
    fixers (PERF001's `_funccall_matches`, SEC019's
    `_is_one_arg_current_setting`) each open-coded — callers test
    `qualified in names or bare in names`.
    """
    if not isinstance(node, FuncCall):
        return None, None
    parts: list[str] = []
    for f in node.funcname or ():
        if isinstance(f, String):
            parts.append(f.sval)
    if not parts:
        return None, None
    return ".".join(parts), parts[-1]


def _from_scope_relations(from_clause: Any, with_clause: Any) -> set[str]:
    """Relation names and aliases bound in a single SELECT's own scope.

    Used to decide whether a qualified column reference points at an
    OUTER query level (correlation). An aliased table contributes ONLY
    its alias: `FROM public.shares s2` binds `s2`, so a later `shares.id`
    is an outer reference, not a self-reference. CTE names from a `WITH`
    clause are in-scope too.
    """
    names: set[str] = set()

    def visit(item: Any) -> None:
        if item is None:
            return
        if isinstance(item, RangeVar):
            if item.alias is not None and item.alias.aliasname:
                names.add(item.alias.aliasname)
            elif item.relname:
                names.add(item.relname)
        elif isinstance(item, (RangeSubselect, RangeFunction)):
            # A subquery / set-returning-function in FROM is a deeper
            # scope; only its alias is visible at this level.
            if item.alias is not None and item.alias.aliasname:
                names.add(item.alias.aliasname)
        elif isinstance(item, JoinExpr):
            visit(item.larg)
            visit(item.rarg)

    for item in from_clause or ():
        visit(item)
    for cte in getattr(with_clause, "ctes", None) or ():
        ctename = getattr(cte, "ctename", None)
        if ctename:
            names.add(ctename)
    return names


def subselect_is_correlated(select_stmt: Any) -> bool:
    """True iff a SubLink subselect references an enclosing query level.

    A correlated subselect is re-executed once per outer row (a
    SubPlan), so a STABLE call like `auth.uid()` inside it is evaluated
    per row — wrapping it in `(SELECT …)` collapses that to one InitPlan
    call, exactly as for a top-level call. An UNCORRELATED subselect runs
    once (its own InitPlan); a call inside it already evaluates once, so
    wrapping buys nothing and PERF001 must stay quiet (e.g.
    `user_id IN (SELECT auth.uid())`).

    Sound heuristic, biased toward *not* correlated on ambiguity: a
    qualified `ColumnRef` (`t.col`, `s.t.col`) whose table-qualifier is
    not a relation, alias, or CTE bound in this select's own scope is an
    outer reference. Bare unqualified refs are taken as in-scope
    (Postgres resolves them to the nearest level that has the column).
    This is exactly the form pgrls lints: `pg_get_expr` qualifies a
    correlated outer reference with the outer relation's name when it
    deparses a stored policy (a bare `id` resolving to the outer table is
    emitted as `teams.id`), so the introspection path — pgrls's real
    input — always presents correlation as a qualified ref. A *hand-
    written* bare-ref fragment (`WHERE tm.fk = outer_col`) parsed
    directly is conservatively treated as uncorrelated.
    Deeper scopes — nested `SubLink` subselects and `RangeSubselect`
    subqueries (including a `LATERAL` subquery in the FROM) — are not
    descended into when collecting evidence for THIS level, so a
    correlation that reaches the outer query *only* through a `LATERAL`
    is conservatively treated as uncorrelated (a sound under-report, not
    a false positive). Set-operation selects (UNION/INTERSECT/EXCEPT),
    where each arm has its own FROM, are likewise treated as
    uncorrelated.
    """
    if not isinstance(select_stmt, SelectStmt):
        return False
    if select_stmt.op != SetOperation.SETOP_NONE:
        return False
    own = _from_scope_relations(
        select_stmt.fromClause, select_stmt.withClause
    )
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
            # Deeper scope — its subselect's refs are relative to its own
            # level; only the testexpr lives in THIS scope.
            walk(n.testexpr)
            return
        if isinstance(n, RangeSubselect):
            return  # deeper scope
        if isinstance(n, ColumnRef):
            parts = [
                f.sval for f in (n.fields or ()) if isinstance(f, String)
            ]
            if len(parts) >= 2 and parts[-2] not in own:
                found = True
            return
        if isinstance(n, Node):
            for field_name in n:
                value = getattr(n, field_name, None)
                if isinstance(value, (list, tuple)):
                    for item in value:
                        walk(item)
                elif isinstance(value, Node):
                    walk(value)

    walk(select_stmt)
    return found


def find_func_calls(
    node: Any,
    names: set[str],
    *,
    exclude_sublinks: bool = False,
    descend_correlated_sublinks: bool = False,
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

    `descend_correlated_sublinks=True` (only meaningful alongside
    `exclude_sublinks=True`) additionally descends into a SubLink's
    subselect when it is CORRELATED (`subselect_is_correlated`): a bare
    auth call inside a correlated `EXISTS (SELECT … WHERE … = t.col)` is
    re-evaluated per outer row, so PERF001 must flag it. An uncorrelated
    subselect runs once and stays skipped.
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
            if descend_correlated_sublinks and subselect_is_correlated(
                n.subselect
            ):
                walk(n.subselect)
            return
        if isinstance(n, FuncCall):
            qualified, bare = func_name_parts(n)
            if qualified is not None and (
                qualified in names or bare in names
            ):
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


def statement_command(stmt: Any) -> str | None:
    """Map a parsed top-level statement node to its RLS command.

    Returns "SELECT" / "INSERT" / "UPDATE" / "DELETE" for the four
    DML statement shapes RLS policies govern, or None for anything
    else (DDL, SET, transaction control, etc.) — the caller skips
    statements with no command. Pass the statement node, i.e.
    `pglast.parse_sql(sql)[i].stmt`.
    """
    if isinstance(stmt, SelectStmt):
        return "SELECT"
    if isinstance(stmt, InsertStmt):
        return "INSERT"
    if isinstance(stmt, UpdateStmt):
        return "UPDATE"
    if isinstance(stmt, DeleteStmt):
        return "DELETE"
    return None


def match_is_null(node: Any) -> tuple[Any, bool] | None:
    """If node is `X IS NULL` or `X IS NOT NULL`, return (X, is_null_flag).

    Returns None for any other expression shape.
    """
    if isinstance(node, NullTest):
        is_null = node.nulltesttype == NullTestType.IS_NULL
        return (node.arg, is_null)
    return None


def _is_literal_bool(node: Any, *, value: bool) -> bool:
    return (
        isinstance(node, A_Const)
        and isinstance(node.val, Boolean)
        and node.val.boolval is value
    )


def is_literal_true(node: Any) -> bool:
    """True iff `node` is the literal boolean constant `true`.

    Deliberately narrow — only the literal `true` matches, not
    `1 = 1` or other semantic tautologies. Shared by SEC008
    (`USING (true)`), SEC011 (`OR true` branch), and SEC020
    (`WITH CHECK (true)`): a real tautology checker is significant
    infrastructure for marginal real-world value, so every
    constant-true rule keeps the same lexical scope.
    """
    return _is_literal_bool(node, value=True)


def is_literal_false(node: Any) -> bool:
    """True iff `node` is the literal boolean constant `false`.

    The mirror of `is_literal_true` — SEC010 (`USING (false)` /
    `WITH CHECK (false)`) uses it. Only the literal `false`
    matches, not `NOT true`, `1 = 0`, or other semantic
    equivalents.
    """
    return _is_literal_bool(node, value=False)


def is_builtin_current_setting(node: Any) -> bool:
    """True iff `node` is a call to the Postgres BUILTIN ``current_setting``
    — unqualified, or ``pg_catalog``-qualified — and NOT a user-defined
    ``<schema>.current_setting``.

    ``find_func_calls(node, {"current_setting"})`` matches on EITHER the
    qualified or the bare name (so it also returns a same-named UDF like
    ``myschema.current_setting``). Every rule that reasons about the
    builtin's GUC semantics — SEC019's ``missing_ok``-less overload,
    SEC024's unqualified-name requirement, and the never-NULL guard below
    — must gate on this, or it false-fires on a user-defined function
    that merely shares the bare name. Single source of truth so those
    gates cannot drift.
    """
    if not isinstance(node, FuncCall):
        return False
    qualified, _bare = func_name_parts(node)
    return qualified in ("current_setting", "pg_catalog.current_setting")


def is_never_null_current_setting(node: Any) -> bool:
    """True iff `node` is a builtin ``current_setting`` call that can
    NEVER return NULL — so an ``IS NULL`` test on it is a dead disjunct,
    not an anonymous-read hole.

    The builtin ``current_setting`` (unqualified or ``pg_catalog``-
    qualified) is never-NULL in two argument forms:

    * one-arg ``current_setting(name)`` — RAISES ``unrecognized
      configuration parameter`` on an unset GUC and otherwise returns a
      non-NULL string (even ``''`` is non-NULL);
    * two-arg ``current_setting(name, false)`` — the ``missing_ok=false``
      form ALSO raises on an unset GUC, so it too is never NULL.

    Only ``current_setting(name, true)`` (``missing_ok=true``) returns
    NULL when the GUC is unset and stays NULLable. A non-literal second
    argument is treated conservatively as NULLable (so the IS-NULL rule
    keeps firing), and a user-defined ``myschema.current_setting`` is a
    DIFFERENT function that is not matched at all.

    Single source of truth shared by SEC004 (`_has_nullable_auth_call`)
    and the SEC038 anon-read encoder (`_is_anon_null_leaf`) so the two
    never-NULL guards cannot drift — they did: R12 fixed only the 1-arg
    case in both, and R13 found the 2-arg-``false`` gap latent in both.
    """
    if not is_builtin_current_setting(node):
        return False
    args = node.args
    if not args:
        return False
    if len(args) == 1:
        return True
    if len(args) == 2:
        # missing_ok=false also raises on an unset GUC → never NULL.
        # Unwrap any TypeCast (`false::bool`) before the literal test;
        # `true` and any non-literal second arg stay NULLable.
        second = args[1]
        while isinstance(second, TypeCast):
            second = second.arg
        return is_literal_false(second)
    return False


def function_body_sql(body: str) -> str:
    """The parseable statement text of a function body.

    A SQL-standard ``BEGIN ATOMIC … END`` body (PG14+) is stored PARSED in
    `pg_proc.prosqlbody`, and `pg_get_function_sqlbody` deparses it back with
    the wrapper intact. pglast cannot parse that wrapper — ``BEGIN`` is a
    transaction command in bare SQL, so it raises ``syntax error at or near
    "ATOMIC"`` — and every caller catches the parse error and analyzes NOTHING.

    Stripping the wrapper leaves the inner statement list, which parses. Only
    the LEADING ``BEGIN ATOMIC`` and the TRAILING ``END`` are removed, so an
    ``END`` closing a ``CASE`` inside the body is untouched. A classic
    (``AS $$ … $$``) body contains no wrapper and is returned unchanged.
    """
    stripped = body.strip()
    opener = re.match(r"(?is)^BEGIN\s+ATOMIC\b", stripped)
    if opener is None:
        return body
    inner = stripped[opener.end():]
    closer = re.search(r"(?is)\bEND\s*;?\s*$", inner)
    if closer is not None:
        inner = inner[: closer.start()]
    return inner
