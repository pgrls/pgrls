"""SEC026 — policy predicate uses pattern matching against an auth context.

A policy whose `USING` or `WITH CHECK` expression compares a value
against an **auth-context function** (`current_setting`, `auth.uid`,
`current_user`, ...) using a **pattern-matching operator** — `LIKE`,
`ILIKE`, `SIMILAR TO`, or a POSIX regex operator (`~`, `~*`, `!~`,
`!~*`) — makes the predicate's tightness depend on the *shape* of
the auth-context value rather than on its identity.

The footgun:

```sql
CREATE POLICY p ON documents
    USING (user_email ILIKE current_setting('app.email'));
```

The author wants case-insensitive email matching. But `LIKE` /
`ILIKE` interpret `%` and `_` as wildcards. If the GUC is ever set
to `%` (the empty pattern, or `'%@example.com'`, or any wildcard
shape), every row matches — total bypass. The same hole opens for
POSIX regex: `current_setting('app.pattern')` set to `.*` matches
every value.

SEC026 fires when a policy predicate combines a pattern operator
with an auth-context value on either operand. The dominant shape is
`column LIKE current_setting(...)`, but the rule also catches
`current_setting(...) ~ column` (the auth value as the pattern
source) and `current_user ILIKE column` (role-identity vs column).

What SEC026 catches:

* **Pattern operators.** `LIKE` / `NOT LIKE` (operator names `~~`
  / `!~~`), `ILIKE` / `NOT ILIKE` (`~~*` / `!~~*`), `SIMILAR TO`,
  and the POSIX regex family (`~`, `~*`, `!~`, `!~*`). pglast
  parses literal `LIKE` / `ILIKE` source as `AEXPR_LIKE` /
  `AEXPR_ILIKE` and the round-tripped deparser-emitted `~~` form
  as `AEXPR_OP`, so SEC026 matches by **operator name** rather
  than by `A_Expr.kind` — a policy introspected from
  `pg_get_expr` (which deparses `LIKE` to `~~`) trips the rule
  the same way as the literal-`LIKE` source. SIMILAR TO is
  emitted as `AEXPR_SIMILAR` with operator name `~`, identical
  to the bare POSIX regex shape — both are pattern matching and
  SEC026 treats them the same.
* **Auth functions.** The default set mirrors PERF001's
  (`auth.uid`, `auth.role`, `auth.jwt`, `current_setting`) plus
  the role-identity grammar-specials (`current_user`,
  `current_role`, `user`, `session_user`). The `auth_functions`
  option replaces the default — list every function you want
  covered, including the stock ones if you still use them.
* **Both operand directions.** `column LIKE current_setting(...)`
  and `current_setting(...) LIKE column` both fire; the
  vulnerability is symmetric — whichever side carries the auth
  value, that side's *shape* now drives the predicate.
* **SubLink-wrapped auth values.**
  `user_email LIKE (SELECT current_setting('app.email', true))` is
  semantically identical to the un-wrapped form — Postgres evaluates
  the scalar SubLink to a value and feeds it to `LIKE` — so SEC026
  treats a FROM-less scalar sub-select (the PERF001 wrap idiom) as the
  pattern operand. A sub-select WITH a from clause is a *lookup*, not
  the pattern: an auth call buried in its WHERE/JOIN (`user_email LIKE
  (SELECT pattern FROM patterns WHERE owner = current_user)`) is a row
  filter, not the value driving the predicate, so SEC026 does NOT fire
  on it (see `_side_has_auth_call`). The same outer walk still reaches
  A_Expr nodes inside a sub-select on its own (e.g. `EXISTS (SELECT 1
  FROM members WHERE m.email LIKE current_setting(...))` fires on the
  inner LIKE), but each policy is reported once — `check`
  short-circuits on the first match.

What SEC026 deliberately does not catch:

* **Pattern operator without an auth context.**
  `email LIKE '%@example.com'` is hard-coded — the predicate
  isolates by a fixed pattern, not by an attacker-controllable
  value. Out of scope.
* **Auth context with non-pattern operator.**
  `tenant_id = current_setting('app.tenant_id')::uuid` is a plain
  `=` comparison; the auth value is interpreted as a UUID, not a
  pattern. SEC026 only fires on pattern operators.

Configuring the auth function set. If your stack uses a custom
helper, replace the default:

```toml
[lint.rules.SEC026]
auth_functions = ["auth.uid", "current_setting", "my.current_user_id"]
```

Allowlisting individual policies. Use the qualified policy ID:

```toml
[lint.rules.SEC026]
allowlist = ["public.tiny_table.policy_name"]
```

The remedy is almost always to switch to `=` (exact match) or to
normalize both sides before comparing — `lower(email) =
lower(current_setting('app.email'))` for case-insensitive equality,
not `ILIKE`. The pattern wildcards have no place in an isolation
predicate.

Severity: warning. No auto-fix — picking the right exact-match
shape is a design choice (case-sensitive `=`, `lower()`-wrapped,
or a different scoping column entirely), not a mechanical rewrite.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import (
    A_Expr,
    FuncCall,
    Node,
    SelectStmt,
    String,
    SubLink,
    TypeCast,
)

from pgrls.ast_utils import find_func_calls
from pgrls.model import Policy, Schema
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

# Default set of auth-context function names. Mirrors PERF001's
# default plus the role-identity SQLValueFunction names — both
# families read auth context from the session and are equally
# dangerous when fed to a pattern operator.
_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset(
    {
        "auth.uid",
        "auth.role",
        "auth.jwt",
        "current_setting",
        "current_user",
        "current_role",
        "user",
        "session_user",
    }
)

# Operator names that denote pattern matching, covering both the
# literal-`LIKE`/`ILIKE` source forms and the deparser-emitted
# operator forms that Postgres round-trips through `pg_get_expr`:
#
#   `~~`   — LIKE
#   `~~*`  — ILIKE
#   `!~~`  — NOT LIKE
#   `!~~*` — NOT ILIKE
#   `~`    — POSIX regex match (also SIMILAR TO's emitted op name)
#   `~*`   — POSIX case-insensitive regex match
#   `!~`   — POSIX negated regex match
#   `!~*`  — POSIX negated case-insensitive regex match
#
# SEC026 matches `A_Expr` nodes by the trailing element of their
# operator name (`A_Expr.name`) regardless of the `kind` field —
# the literal-`LIKE` source parses as `AEXPR_LIKE` with name
# `~~`, while a deparsed policy from `pg_get_expr` lands as
# `AEXPR_OP` with the same name. Name-based detection is
# round-trip-stable; kind-based detection alone misses the
# introspection path.
_PATTERN_OP_NAMES: frozenset[str] = frozenset(
    {"~~", "~~*", "!~~", "!~~*", "~", "~*", "!~", "!~*"}
)


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "SEC026.auth_functions must be a list of strings (e.g. "
            '["auth.uid", "current_setting"]).'
        )
    return set(raw)


def _expr_name(node: A_Expr) -> str | None:
    """Extract the operator name from an `A_Expr`.

    `A_Expr.name` is a list of `String` AST nodes representing the
    schema-qualified operator (`pg_catalog.~` becomes
    `["pg_catalog", "~"]`). Return the trailing element — the bare
    operator — so a schema-qualified pattern operator still matches
    against `_PATTERN_OP_NAMES`. Returns None when the name list is
    empty (defensive; pglast emits at least one element).
    """
    parts: list[str] = []
    for f in node.name or ():
        if isinstance(f, String):
            parts.append(f.sval)
    return parts[-1] if parts else None


def _is_pattern_expr(node: A_Expr) -> bool:
    """True if `node` is a pattern-matching `A_Expr`.

    Matched by operator name (the trailing element of
    `A_Expr.name`) rather than by `A_Expr.kind`, so a literal-`LIKE`
    source (`kind == AEXPR_LIKE`) and a `pg_get_expr`-deparsed
    policy (`kind == AEXPR_OP` with the same `~~` name) trip the
    rule the same way.
    """
    name = _expr_name(node)
    return name is not None and name in _PATTERN_OP_NAMES


# `~` and `!~` are POSIX regex match on text, but they are ALSO the
# geometric "contains" operator and the ltree/lquery match operator.
# When SEC026's auth value is cast to (or constructed as) one of these
# non-text types, the operator is a typed containment/match — not a
# regex pattern — and the rule must not fire (false positive). The LIKE
# family (`~~`/`~~*`/`!~~`/`!~~*`) and case-insensitive regex (`~*`/
# `!~*`) are text-only and never overloaded, so they are not guarded.
_OVERLOADED_REGEX_OPS: frozenset[str] = frozenset({"~", "!~"})
_NON_TEXT_PATTERN_TYPES: frozenset[str] = frozenset({
    "point", "box", "circle", "polygon", "path", "line", "lseg",
    "ltree", "lquery", "ltxtquery",
})


def _is_non_text_typed(side: Any) -> bool:
    """True if `side`'s top node casts to — or constructs — a non-text
    type (geometric / ltree), i.e. the operand of a geometric/ltree
    `~`, not a text regex pattern."""
    if isinstance(side, TypeCast):
        names = [
            s.sval
            for s in (side.typeName.names or ())
            if isinstance(s, String)
        ]
        return bool(names) and names[-1] in _NON_TEXT_PATTERN_TYPES
    if isinstance(side, FuncCall):
        fnames = [
            s.sval for s in (side.funcname or ()) if isinstance(s, String)
        ]
        return bool(fnames) and fnames[-1] in _NON_TEXT_PATTERN_TYPES
    return False


def _fromless_subselects(side: Any) -> list[SelectStmt]:
    """Scalar sub-selects in `side` that have NO from clause.

    A `(SELECT current_setting('app.x'))` — no FROM — carries the
    compared value in its target list; that is the wrapped form
    PERF001 recommends, and it IS the LIKE/regex pattern operand. A
    sub-select WITH a from clause (`(SELECT pattern FROM patterns WHERE
    owner = current_user)`) is a lookup whose internal predicates are
    NOT the pattern the outer column matches against, so it must not be
    treated as the auth operand. Mirrors SEC030's helper of the same
    name. The walk inspects only fromless-ness at this level, not
    sub-select bodies.
    """
    out: list[SelectStmt] = []

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink):
            sub = n.subselect
            if isinstance(sub, SelectStmt) and not sub.fromClause:
                out.append(sub)
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(side)
    return out


def _side_has_auth_call(side: Any, names: set[str]) -> bool:
    """True if the LIKE/regex pattern operand `side` IS an auth value.

    The auth value drives the pattern when it is a *direct* call
    (`col LIKE current_setting(...)`) or lives in the projection of a
    FROM-less scalar sub-select (`col LIKE (SELECT current_setting())`,
    the form PERF001 recommends). `exclude_sublinks=True` on the direct
    pass keeps a sub-select's *internal* predicate out of the operand's
    value; the fromless branch then re-adds the wrapped recommended form.

    A sub-select WITH a from clause is a lookup, not the pattern, so an
    auth call buried in its WHERE/JOIN (`col LIKE (SELECT pattern FROM
    patterns WHERE owner = current_user)`) is NOT counted — avoiding a
    false positive where current_user is merely a row filter. The outer
    `_has_pattern_against_auth` walk still inspects any A_Expr inside the
    sub-select independently, so a genuine inner pattern still fires.
    """
    if find_func_calls(side, names, exclude_sublinks=True):
        return True
    return any(
        find_func_calls(sub.targetList, names, exclude_sublinks=True)
        for sub in _fromless_subselects(side)
    )


def _has_pattern_against_auth(node: Any, names: set[str]) -> bool:
    """Walk the AST and return True if any `A_Expr` is a pattern
    operator with an auth-context function call on either operand.

    Mirrors SEC018's `_compares_role_identity_to_own_column`: walks
    every node (recursing into sub-selects so a nested A_Expr is
    independently inspected) and checks each `A_Expr` whose `kind`
    qualifies as a pattern operator.
    """

    def walk(n: Any) -> bool:
        if n is None:
            return False
        if isinstance(n, (list, tuple)):
            return any(walk(item) for item in n)
        if isinstance(n, A_Expr) and _is_pattern_expr(n):
            overloaded = _expr_name(n) in _OVERLOADED_REGEX_OPS
            for side in (n.lexpr, n.rexpr):
                if not _side_has_auth_call(side, names):
                    continue
                # `~` / `!~` double as geometric "contains" and the
                # ltree/lquery match operator. If the auth value is
                # cast to / built as a non-text type, this isn't a
                # regex pattern match — skip that side (false positive).
                if overloaded and _is_non_text_typed(side):
                    continue
                return True
            # fall through — the A_Expr may have nested A_Expr
            # nodes deeper in its operands.
        if isinstance(n, Node):
            for field_name in n:
                if walk(getattr(n, field_name, None)):
                    return True
        return False

    return walk(node)


def _policy_id(table_schema: str, table_name: str, policy: Policy) -> str:
    return f"{table_schema}.{table_name}.{policy.name}"


class SEC026:
    id: str = "SEC026"
    severity: Severity = "warning"
    title: str = "Policy uses LIKE/regex pattern matching against an auth context"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC026", options)
        names = _parse_auth_functions(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                policy_id = _policy_id(table.schema, table.name, policy)
                if policy_id in allowlist:
                    continue
                fires = False
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None and _has_pattern_against_auth(ast, names):
                        fires = True
                        break
                if not fires:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC026",
                        severity=self.severity,
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} compares a value against "
                            "an auth-context function using a pattern "
                            "operator (LIKE / ILIKE / SIMILAR TO / regex). "
                            "Pattern operators make the predicate depend on "
                            "the shape of the auth value — a GUC set to "
                            "'%' or '.*' would match every row. Use '=' "
                            "(or wrap both sides in lower() for "
                            "case-insensitive equality) or include the "
                            "policy in [lint.rules.SEC026].allowlist if the "
                            "pattern semantics are deliberate."
                        ),
                        location=policy_id,
                    )
                )
        return out
