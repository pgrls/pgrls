"""SEC004 fixer — strip the inverted-auth `IS NULL` disjunct from a policy.

SEC004 flags the Lovable-CVE foot-gun: a policy whose `USING` is shaped
`auth_func() IS NULL OR <real check>`. `auth_func()` (e.g. `auth.uid()`,
`current_setting('app.uid', true)`) returns NULL for an anonymous request,
so the `IS NULL` disjunct is `true`, the `OR` short-circuits, and the real
check never runs — every row leaks to unauthenticated clients. The rule's
documented remedy is mechanical: **remove the `IS NULL` disjunct**, leaving
the real predicate to stand:

    owner_id = auth.uid()  OR  auth.uid() IS NULL
    →  owner_id = auth.uid()

This fixer emits exactly that:

    ALTER POLICY <name> ON <schema>.<table> USING (<real check>);

**Why this never broadens the policy — the security boundary.** SEC004 only
ever fires on a `<nullable-auth>() IS NULL` test that sits as a **top-level
OR disjunct** of the `USING` expression: the rule flattens OR (including
nested-by-parenthesization, since OR is associative) but deliberately does
NOT flatten through `AND` / `NOT` / sub-selects (an `IS NULL` gated by an
`AND` is not a standalone anonymous-read hole, so the rule never flags it).
The fixer mirrors that exactly — it descends **only** through `OR_EXPR`
nodes and removes the offending disjunct(s). Removing a disjunct from an OR
is monotone: it can only *narrow* the set of admitted rows (it deletes a way
to be admitted), which is precisely the leak being closed. The fixer never
descends past an `AND`, `NOT`, comparison, function call, or `SubLink`, so it
can never reach — let alone tighten — an `IS NULL` in a non-monotone position
where removal could broaden access. A security fixer must never widen a
policy; OR-only descent guarantees it.

**Conservative abstentions (leave the SEC004 finding for human review).**
The fixer declines — emits no Fix — when stripping the `IS NULL` disjunct(s)
would not leave a real check to fall back to:

* the disjunct is the *entire* `USING` (`USING (auth.uid() IS NULL)`): there
  is no `<real check>`, only the hole. Auto-rewriting would mean inventing a
  predicate or forcing `USING (false)` (deny-all) — both are intent the fixer
  can't safely assume, so it leaves the finding for the operator.
* what survives is the literal `true` (`auth.uid() IS NULL OR true`): the
  remaining "check" admits every row anyway, so there is no real predicate to
  restore. (SEC011 — `OR true` — owns that rewrite; SEC004 declines rather
  than emit a still-open `USING (true)`.)

**Opinionated, like SEC011 / SEC019.** Removing the disjunct assumes the
`auth_func() IS NULL` branch was the inverted-auth mistake SEC004 targets —
the overwhelmingly common case — not a deliberate "admit anonymous users."
A policy that genuinely means to serve anonymous reads should say so
explicitly (a dedicated `TO anon` policy, or `USING (true)` with the risk
owned), not bury an `IS NULL` in the predicate; `pgrls fix` is dry-run by
default, so the SQL is reviewed before `--apply`. The semantically-disguised
variants of the same leak (`NOT (… IS NOT NULL)`, a `COALESCE` wrapper) are
SEC038's province — proved by the Z3 solver, not pattern-stripped — and are
deliberately out of this fixer's scope: only the canonical, safely-strippable
top-level `IS NULL` disjunct is auto-fixed.

Only `USING` is rewritten (the only clause SEC004 inspects); `WITH CHECK` is
never touched. The mutation happens on a deep copy so the rule's `Schema`
view stays read-only.
"""
from __future__ import annotations

import copy
from typing import Any

from pglast.ast import BoolExpr
from pglast.enums import BoolExprType

from pgrls.ast_utils import is_literal_true, match_is_null
from pgrls.fixers import Fix
from pgrls.fixers._idents import alter_policy
from pgrls.model import Schema, policy_id

# Reuse the rule's auth-function config parsing and nullable-auth test as the
# single source of truth, so the fixer strips exactly the disjuncts the rule
# flags — never more, never fewer (config drift here would be a security bug).
from pgrls.rules.sec004 import _has_nullable_auth_call, _parse_auth_functions


class _CannotStrip(Exception):
    """Raised when removing the `IS NULL` disjunct(s) would leave no real
    check (an empty OR, or only the literal `true`). There is no safe
    minimal rewrite, so the fixer skips the policy and leaves the finding."""


def _is_null_auth_disjunct(node: Any, auth_functions: set[str]) -> bool:
    """True iff `node` is a `<nullable-auth>() IS NULL` test — exactly the
    disjunct shape SEC004 flags (mirrors the rule's per-disjunct check)."""
    matched = match_is_null(node)
    if matched is None:
        return False
    inner, is_null = matched
    if not is_null:
        return False
    return _has_nullable_auth_call(inner, auth_functions)


def _strip_null_auth(node: Any, auth_functions: set[str]) -> tuple[Any, bool]:
    """Remove `<nullable-auth>() IS NULL` disjuncts from OR `BoolExpr`s
    reachable from the clause root through OR chains **only**.

    Returns `(node, changed)`. Recurses through `OR_EXPR` args and nothing
    else — matching SEC004's `flatten_or_disjuncts` (OR-only) and keeping the
    rewrite in monotone position so it can only narrow the policy. An OR left
    with a single arg is unwrapped (`a OR auth() IS NULL` → `a`); an OR left
    with zero args raises `_CannotStrip`.
    """
    if not isinstance(node, BoolExpr):
        return node, False
    if node.boolop != BoolExprType.OR_EXPR:
        # AND_EXPR / NOT_EXPR are non-monotone for disjunct removal, and
        # SEC004 does not flatten through them, so never descend: an
        # `IS NULL` under an AND/NOT is not the hole the rule reported.
        return node, False

    changed = False
    kept: list[Any] = []
    for arg in node.args or ():
        # Recurse into nested ORs first, then test the (possibly rewritten)
        # disjunct so `a OR (auth() IS NULL OR b)` collapses to `a OR b`.
        new_arg, arg_changed = _strip_null_auth(arg, auth_functions)
        changed = changed or arg_changed
        if _is_null_auth_disjunct(new_arg, auth_functions):
            changed = True
            continue  # drop the inverted-auth disjunct
        kept.append(new_arg)

    if not changed:
        return node, False
    if not kept:
        raise _CannotStrip()
    if len(kept) == 1:
        return kept[0], True  # unwrap the now-singleton OR
    node.args = tuple(kept)
    return node, True


def _strip_using(ast: Any, auth_functions: set[str]) -> tuple[Any, bool]:
    """Deep-copy and strip the `USING` AST. Returns `(new_ast, changed)`;
    raises `_CannotStrip` when no real check survives (empty OR, a bare
    `IS NULL` that was the whole clause, or a surviving literal `true`)."""
    if ast is None:
        return None, False
    candidate = copy.deepcopy(ast)
    # A bare `auth() IS NULL` as the whole USING (not wrapped in an OR) is a
    # single disjunct SEC004 flags; `_strip_null_auth` won't touch a non-OR
    # root, so catch it here — there is nothing to fall back to.
    if _is_null_auth_disjunct(candidate, auth_functions):
        raise _CannotStrip()
    new_ast, changed = _strip_null_auth(candidate, auth_functions)
    # If only the literal `true` survives, the policy is still wide open and
    # there is no real predicate to restore — decline (SEC011 owns `OR true`).
    if changed and is_literal_true(new_ast):
        raise _CannotStrip()
    return new_ast, changed


class SEC004Fixer:
    rule_id: str = "SEC004"

    def fix(self, schema: Schema, options: dict[str, Any]) -> list[Fix]:
        # Parse auth_functions exactly as the rule does, so the fixer's
        # detection of strippable disjuncts is identical to what fired.
        auth_functions = _parse_auth_functions(options)
        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                try:
                    new_using, changed = _strip_using(
                        policy.using_ast, auth_functions
                    )
                except _CannotStrip:
                    # No real check survives the strip — leave the SEC004
                    # finding for human review rather than emit a still-open
                    # or empty USING.
                    continue
                if not changed:
                    continue

                stmt = alter_policy(
                    table, policy.name, using_ast=new_using
                )
                out.append(
                    Fix(
                        rule_id="SEC004",
                        location=policy_id(table, policy),
                        sql=stmt,
                        clauses=frozenset({"using"}),
                        description=(
                            f"Remove the `auth_func() IS NULL` disjunct from "
                            f"policy {policy.name!r} on "
                            f"{table.qualified_name}, restoring the real "
                            "USING check the anonymous-read hole was masking. "
                            "This assumes the IS NULL branch was the inverted-"
                            "auth mistake SEC004 targets, not deliberate "
                            "anonymous access; if a policy genuinely means to "
                            "serve anonymous reads, write that explicitly "
                            "instead of an IS NULL disjunct. Disguised "
                            "variants (NOT … IS NOT NULL, COALESCE) are "
                            "SEC038's domain and are not auto-fixed."
                        ),
                    )
                )
        return out
