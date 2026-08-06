"""SEC046 — a policy calls an ``IMMUTABLE`` function that reads session state.

A function declared ``IMMUTABLE`` promises the planner that it returns the same
result for the same arguments *forever*, so the planner is free to
**constant-fold** the call at plan time — evaluate it once and bake the literal
into the plan. When the body of such a function actually reads *session /
identity state* (``current_setting(...)``, an ``auth.*`` helper,
``current_user`` / ``session_user``) or a *table*, that promise is false: the
value frozen for the connection that first planned the statement is reused for
every later caller of any **reused or cached plan**. Plans are reused all over a
Postgres deployment — a connection pooler reusing a backend (Supavisor /
PgBouncer), PostgREST, a prepared statement, a PL/pgSQL function's plan cache.

Used in a **row-level-security policy**, this is a silent cross-user data leak:

```sql
-- a USER-DEFINED IMMUTABLE wrapper that reads the per-request tenant GUC:
CREATE FUNCTION app.cur_tenant() RETURNS text
    LANGUAGE sql IMMUTABLE              -- WRONG: must be STABLE
    AS $$ SELECT current_setting('app.tenant', true) $$;

CREATE POLICY tenant_iso ON docs FOR SELECT
    USING (tenant = app.cur_tenant());   -- SEC046
```

Once one connection plans ``SELECT ... FROM docs`` under that policy, the
planner folds ``app.cur_tenant()`` to *that connection's* tenant and caches the
plan. A *different* user reusing the same pooled backend then runs the cached
plan and is served the **first user's** rows — RLS silently scopes them to
someone else's tenant. (Verified live: with the function marked ``IMMUTABLE`` a
second connection sees the first connection's rows; marked ``STABLE`` it does
not.) **The fix is to declare the function ``STABLE``** — a STABLE function is
re-evaluated per statement execution, so the per-request value is always fresh.

**Why not a false positive on the obvious-looking cases (all live-validated).**

* **Inline ``current_setting('app.uid', true)`` used directly in a policy is
  SAFE and is NOT flagged.** ``current_setting`` is a built-in marked
  ``STABLE`` by Postgres, so it is *not* constant-folded — the next user gets
  their own value. SEC046 only fires on a **user-defined ``IMMUTABLE`` wrapper**
  (``pg_proc.provolatile='i'`` in a linted schema); the inline built-in never
  appears in ``Schema.immutable_functions``.
* **A pure ``IMMUTABLE`` function** (deterministic on its arguments, no session
  or table read — e.g. ``is_even(int)``) is legitimate and is NOT flagged: its
  body reads no session/identity state and no table, so constant-folding it is
  correct.
* **``STABLE`` and ``VOLATILE`` functions are NOT flagged.** ``STABLE`` is the
  *correct* label and ``VOLATILE`` also defeats folding; only
  ``provolatile='i'`` reaches this rule (introspection captures only IMMUTABLE
  functions).

**Relationship to other rules.** SEC024 surfaces a policy that reads a session
GUC at all; PERF004 flags a *function-wrapped* discriminator that defeats an
index. SEC046 is the orthogonal *correctness* finding: the wrapper is not just a
perf footgun, its ``IMMUTABLE`` marking makes the row filter return the *wrong
user's* rows under plan reuse. It is an ``error``: a cross-tenant data leak.

Configure exemptions with ``[lint.rules.SEC046].allowlist`` as
``schema.function`` ids (an overloaded function is allowlisted once). Remediate
by ``ALTER FUNCTION schema.fn(...) STABLE``.

Severity: error. No auto-fix: ``ALTER FUNCTION ... STABLE`` is the remedy, but
pgrls cannot prove a given function is *meant* to be volatility-downgraded
versus genuinely pure (the author may have intended a different body); the
operator confirms and re-declares it.

Scope / known limits (intentional, fail-closed):

* **Body analysis abstains on the unparseable.** SEC046 parses a ``sql`` body
  (via pglast) to decide whether it reads session/identity state or a table; a
  ``plpgsql`` body (which is not a parseable top-level statement), an empty
  body, or any body pglast cannot parse is **not flagged** (fail-closed) — the
  rule never guesses. A genuinely-dangerous PL/pgSQL ``IMMUTABLE`` wrapper is a
  false negative here, surfaced instead by SEC024 (policy reads a GUC) /
  SEC014.
* **Literal call resolution.** A policy's function call is resolved to a
  captured IMMUTABLE function by its qualified (``schema.fn``) or bare (``fn``)
  name, mirroring the SECDEF-call resolution; a call reached only through
  another function's body is not followed.
* **Cross-scope functions.** A wrapper defined in a schema outside ``--schemas``
  is not captured, the same false-negative path SEC014 / SEC017 document.
* Snapshots predating v19 carry no ``immutable_functions``; SEC046 abstains on
  them (fail-closed) until re-captured against a live database.
"""
from __future__ import annotations

from typing import Any

import pglast
from pglast.ast import CommonTableExpr, Node

from pgrls.ast_utils import (
    function_body_sql,
    extract_range_vars,
    find_func_calls,
    func_name_parts,
)
from pgrls.model import ImmutableFunction, Schema, policy_id
from pgrls.rules._allowlist import parse_qualified_function_allowlist
from pgrls.violations import Severity, Violation

# Session / identity built-ins whose presence in an IMMUTABLE body means the
# body's value depends on the current connection — exactly what makes
# constant-folding it dangerous. `current_user` / `session_user` are
# SQLValueFunction nodes; `find_func_calls` handles both forms. `current_role`
# / `user` are aliases of `current_user`; included for completeness.
# `current_setting` / `set_config` read/write a GUC (the per-request
# `app.tenant` pattern). The `auth.*` set is the Supabase/PostgREST request
# context (`auth.uid()`, `auth.jwt()`, `auth.role()`, `auth.email()`).
_SESSION_FUNCTIONS: frozenset[str] = frozenset(
    {
        "current_setting",
        "set_config",
        "current_user",
        "session_user",
        "current_role",
        "user",
        "auth.uid",
        "auth.jwt",
        "auth.role",
        "auth.email",
    }
)


def _cte_names(node: Any) -> set[str]:
    """Collect every CTE name (``WITH <name> AS …``) defined in ``node``.

    A reference to a CTE parses as an *unqualified* ``RangeVar`` whose relname
    is the CTE name — not a base-table read. ``_body_reads_session_or_table``
    subtracts these so a pure function whose body only reads its own CTE is not
    mistaken for one that reads a table (the VIEW004 / SEC025 CTE-shadow class).
    """
    names: set[str] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, CommonTableExpr):
            ctename = getattr(n, "ctename", None)
            if isinstance(ctename, str) and ctename:
                names.add(ctename)
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(node)
    return names


def _body_reads_session_or_table(body: str, language: str) -> bool:
    """True if a `sql` function body reads session/identity state or a table.

    Returns False (abstain — fail-closed) when the body is empty, is not a
    `sql` language body, or cannot be parsed by pglast. A `sql` body that
    parses is inspected for (a) a call to a session/identity function in
    `_SESSION_FUNCTIONS`, or (b) any table reference (a `RangeVar`, i.e. a
    `FROM`/`UPDATE`/`INSERT`/`DELETE` target) — a table read makes the result
    depend on data the planner must not freeze.
    """
    if language != "sql":
        # PL/pgSQL and other procedural bodies are not parseable as a
        # top-level statement — abstain rather than guess.
        return False
    if not body.strip():
        return False
    try:
        tree = pglast.parse_sql(function_body_sql(body))
    except Exception:
        # Unparseable body (e.g. a multi-statement or dialect pglast rejects).
        # Fail-closed: never fire on a body we cannot analyse.
        return False
    if find_func_calls(tree, set(_SESSION_FUNCTIONS)):
        return True
    # A table read (any RangeVar) likewise makes the body non-immutable — but a
    # CTE name referenced in FROM parses as an unqualified RangeVar too, and
    # reading a same-body CTE is NOT a table read (the VIEW004 / SEC025
    # CTE-vs-table shadow class). Exclude bare RangeVars that name a CTE defined
    # in the body before concluding a real table is read.
    cte_names = _cte_names(tree)
    for schema_name, relname in extract_range_vars(tree):
        if schema_name is None and relname in cte_names:
            continue
        return True
    return False


class SEC046:
    id: str = "SEC046"
    severity: Severity = "error"
    title: str = (
        "Policy calls an IMMUTABLE function that reads session state "
        "(constant-folded, cross-user leak)"
    )

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        allowlist = parse_qualified_function_allowlist("SEC046", options)

        # The dangerous IMMUTABLE functions: those whose body reads session/
        # identity state or a table. Keyed by qualified name; a value is kept
        # for the message. Built once per check() over the captured set.
        # A qualified name with multiple overloads fires if ANY overload's
        # body is dangerous (a policy call is resolved by name, not signature).
        dangerous: dict[str, ImmutableFunction] = {}
        for fn in schema.immutable_functions:
            if fn.qualified_name in dangerous:
                continue
            if _body_reads_session_or_table(fn.body, fn.language):
                dangerous[fn.qualified_name] = fn
        if not dangerous:
            # No dangerous IMMUTABLE function captured (or a pre-v19 snapshot
            # with an empty immutable_functions) → nothing to match against.
            return []

        # Map a bare last-segment to its qualified form so a `cur_tenant()`
        # reference (no schema prefix in a policy expr) resolves to
        # `app.cur_tenant`. Iterate in sorted order so a bare name shared by
        # two schemas maps deterministically (an ambiguous case; the matcher
        # below also accepts a direct qualified match, which is unambiguous).
        bare_to_qualified: dict[str, str] = {}
        for qname in sorted(dangerous):
            bare = qname.rsplit(".", 1)[-1]
            bare_to_qualified.setdefault(bare, qname)
        names_to_match = set(dangerous) | set(bare_to_qualified)

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                trees = [
                    t
                    for t in (policy.using_ast, policy.with_check_ast)
                    if t is not None
                ]
                if not trees:
                    continue
                # Resolve each FuncCall in the policy to a dangerous IMMUTABLE
                # function, deduping per policy (a policy that calls the same
                # wrapper in USING and WITH CHECK fires once).
                matched: set[str] = set()
                for tree in trees:
                    for call in find_func_calls(tree, names_to_match):
                        resolved = self._resolve_call(
                            call, dangerous, bare_to_qualified
                        )
                        if resolved is not None:
                            matched.add(resolved)
                for qname in sorted(matched):
                    if qname in allowlist:
                        continue
                    out.append(
                        self._violation(table, policy, dangerous[qname])
                    )
        return out

    @staticmethod
    def _resolve_call(
        call: Any,
        dangerous: dict[str, ImmutableFunction],
        bare_to_qualified: dict[str, str],
    ) -> str | None:
        """Resolve a policy FuncCall to a dangerous IMMUTABLE function's qname.

        Returns the matched qualified name, or None when the call is not a
        FuncCall (e.g. a ``current_user`` SQLValueFunction node that
        ``find_func_calls`` may surface — it carries no funcname and can never
        name a captured user function) or names no captured dangerous function.
        A direct qualified match wins; otherwise a bare name is resolved via
        ``bare_to_qualified``.
        """
        qualified, bare = func_name_parts(call)
        if qualified is None or bare is None:
            return None
        if qualified in dangerous:
            return qualified
        # Only fall back to bare-name resolution for a GENUINELY UNqualified
        # call (`func_name_parts` returns qualified == bare for `foo()`). A
        # call qualified to a different schema (`other.foo()`, qualified
        # `"other.foo"` != bare `"foo"`) names exactly one function with no
        # search_path ambiguity — never expand it to a same-bare-name function
        # in another schema (the VIEW004 / introspect bare-name misattribution
        # class).
        if qualified == bare:
            return bare_to_qualified.get(bare)
        return None

    def _violation(
        self, table: Any, policy: Any, fn: ImmutableFunction
    ) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} calls "
                f"{fn.qualified_name}(), which is declared IMMUTABLE but whose "
                "body reads session/identity state or a table. Postgres may "
                "constant-fold an IMMUTABLE call at plan time, so under a "
                "reused or cached plan (a connection pooler reusing a backend, "
                "PostgREST, a prepared statement, a PL/pgSQL plan cache) the "
                "value frozen for the connection that first planned the query "
                "is served to every later caller — the policy then returns one "
                "user's rows to another (a cross-user data leak). Declare the "
                f"function STABLE (ALTER FUNCTION {fn.qualified_name}(...) "
                "STABLE) so it is re-evaluated per execution; or allowlist it "
                f"as {fn.qualified_name!r} in [lint.rules.SEC046] if it is "
                "genuinely deterministic."
            ),
            location=policy_id(table, policy),
        )
