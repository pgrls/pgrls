"""SEC055 — tenant policy still uses the silent binding form after the
schema adopted the raising one.

`pgrls generate --strict-binding` scaffolds policies that compare against
a helper which RAISES when no tenant is bound on the connection, instead
of a `current_setting(<name>, true)` that quietly returns NULL. The
difference matters because the silent form makes an unbound query
**indistinguishable from an empty result**:

```sql
-- the silent form: no tenant bound -> current_setting -> NULL
--                  tenant_id = NULL -> NULL -> row filtered -> 0 rows
CREATE POLICY p ON leads USING (tenant_id = (SELECT current_setting('app.tenant_id', true)));
```

An application that forgets to bind a tenant does not fail — it reports
"not found". A test suite connected as the table owner cannot see the
difference either, because RLS is not enforced for that role, so a query
that binds a tenant and one that does not are identical to every test.
The failure is silent, total, and arrives the day the application role
stops being the owner.

The danger this rule addresses is **drift**: adopting the raising helper
is only protective if every tenant policy uses it. One policy left on the
silent form is one code path that still 404s instead of failing, and it
is precisely the path nobody converted because nobody remembered it.

## Why the trigger is the schema, not the config

The obvious gate is "`[generate].strict_binding` is set". This rule uses a
stronger signal: it fires only when **this schema already uses the raising
helper somewhere** — at least one policy compares against a
`…require_<label>(…)`-shaped call — and some other tenant policy still
carries the silent `current_setting(…, true)` form (any table — the
check is schema-wide, not per column).

That is deliberate. A config-gated rule is silent when the config is
absent, which is exactly the case when CI lints a database without the
repo's `pgrls.toml` beside it — the drift would go unreported in the
environment most likely to catch it. Keying on the schema makes the
finding self-describing: the evidence that strict binding was adopted is
*in the object being linted*, so the rule travels with the database.

It also cannot flood. A project that never adopted the helper has no
policy referencing it, so the rule never fires — the population is exactly
"schemas that opted in and half-converted".
"""
from __future__ import annotations

from typing import Any

from pglast.ast import FuncCall, Node

from pgrls.ast_utils import (
    find_func_calls,
    func_name_parts,
    is_builtin_current_setting,
    is_literal_true,
)
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

# Detection runs on the AST, not the rendered SQL. `pg_get_expr` normalizes
# a policy into forms a hand-written regex does not survive: the silent call
# comes back as `current_setting('app.tenant_id'::text, true)` — a cast
# between the literal and the comma — and the whole predicate is wrapped
# `( SELECT … AS current_setting )`. Both broke a first regex cut of this
# rule against a live database while passing on hand-typed SQL.

# `require_` names the shape rather than pgrls's exact
# `pgrls_require_<label>`: a hand-rolled `require_tenant()` predates the
# flag and is the population most likely to have half-converted, so it
# should get the drift check too. Substring, not prefix — the generated
# name carries a `pgrls_` prefix, so an anchored match finds nothing.
_RAISING_MARKER = "require_"


def _clause_asts(policy: Any) -> list[Any]:
    return [c for c in (policy.using_ast, policy.with_check_ast) if c is not None]


def _has_raising_call(node: Any) -> bool:
    """A call to a `…require_…`-shaped binding helper anywhere in the tree.

    Walks for FuncCall directly rather than via `find_func_calls`, which
    matches against a fixed name set — the helper's name is chosen by the
    project, so the test is on the *shape* of the name, not membership.
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
        if isinstance(n, FuncCall):
            qualified, bare = func_name_parts(n)
            for candidate in (qualified, bare):
                if candidate and _RAISING_MARKER in candidate.lower():
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

    walk(node)
    return found


def _has_silent_call(node: Any) -> bool:
    """A two-argument `current_setting(name, true)` — returns NULL unset.

    The one-argument form is SEC019's; it RAISES on an unset GUC, which is
    loud already and not what this rule is about.
    """
    for call in find_func_calls(node, {"current_setting"}):
        if not is_builtin_current_setting(call):
            continue
        args: tuple[Any, ...] = tuple(getattr(call, "args", None) or ())
        # Only `missing_ok = true` returns NULL; `(name, false)` raises on an
        # unset GUC exactly like the one-argument form — loud, not silent.
        if len(args) >= 2 and is_literal_true(args[1]):
            return True
    return False


class SEC055:
    id: str = "SEC055"
    severity: Severity = "warning"
    title: str = "Tenant policy uses the silent binding form after the schema adopted the raising one"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC055", options)

        # Adoption evidence: does ANY policy in the schema compare against a
        # raising binding helper? Without that, this schema never opted in
        # and the rule has nothing to say.
        adopted = any(
            _has_raising_call(ast)
            for table in schema.tables
            for policy in table.policies
            for ast in _clause_asts(policy)
        )
        if not adopted:
            return []

        out: list[Violation] = []
        for table in sorted(schema.tables, key=lambda t: t.qualified_name):
            for policy in table.policies:
                clauses = _clause_asts(policy)
                if not clauses:
                    continue
                # A policy that already uses the raising helper is converted,
                # even if it ALSO reads a setting silently for some unrelated
                # purpose — the binding is guarded either way.
                if any(_has_raising_call(a) for a in clauses):
                    continue
                if not any(_has_silent_call(a) for a in clauses):
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC055",
                        severity=self.severity,
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on {table.qualified_name} "
                            "compares against current_setting(…, true), which "
                            "returns NULL when nothing is bound — so a query "
                            "on a connection that never bound a tenant is "
                            "filtered to zero rows and looks exactly like an "
                            "empty result. Other policies in this schema "
                            "already use a raising binding helper, so this "
                            "one is unconverted: it still 404s where the "
                            "others fail loudly. Point it at the same helper "
                            "(pgrls generate --strict-binding scaffolds one), "
                            "or allowlist the qualified policy ID in "
                            "[lint.rules.SEC055] if this policy is "
                            "deliberately readable without a bound tenant — "
                            "a platform table like users or memberships that "
                            "is read before a tenant is chosen."
                        ),
                        location=pid,
                    )
                )
        return out
