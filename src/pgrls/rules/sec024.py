"""SEC024 — policy calls current_setting() with an unqualified parameter name.

An RLS policy reads the per-request tenant/session context from a
**customized** run-time parameter the application sets on every
connection:

    CREATE POLICY p ON documents
        USING (tenant_id = current_setting('app.tenant_id'));

Postgres requires the name of such a customized parameter to be
*qualified* — `prefix.name`, containing a period. The prefix
namespaces application parameters away from the server's own
settings; an unqualified name like `tenant_id` cannot be defined
or `SET` as a customized parameter at all (`SET tenant_id = …`
raises `unrecognized configuration parameter`). The only
unqualified names Postgres accepts are its own built-in settings
(`search_path`, `timezone`, `role`, `application_name`, …).

SEC024 flags a policy whose `current_setting()` call names an
unqualified parameter — a name with no period:

    CREATE POLICY p ON documents
        USING (tenant_id = current_setting('tenant_id', true));
        --                                 ^^^^^^^^^^^ no prefix

This is almost always a dropped prefix — the application sets
`app.tenant_id` but the policy reads `tenant_id`. The failure is
quiet: with the two-argument form the unset parameter yields NULL,
`tenant_id = NULL` matches no rows, and the table simply looks
empty; with the one-argument form every query against the table
errors instead (which SEC019 separately flags). Either way the
policy never sees the context it was written to read.

Detection is structural: SEC024 walks the parsed policy `USING` /
`WITH CHECK` expression for `current_setting` calls (via
`find_func_calls`, so a call wrapped in
`(SELECT current_setting(...))` is found too) and inspects the
first argument. It fires when that argument is a **string literal
with no period**. A call whose
name is built dynamically — a column reference, a concatenation —
is not a literal and is left alone; SEC024 cannot know what it
resolves to.

Severity: info. The discriminator is whether the name is
qualified, not whether it is *correct*: a policy that genuinely
keys off a built-in parameter — `application_name` used as a
coarse tenant tag, say — is unqualified yet intentional. pgrls
cannot tell a dropped prefix from a deliberate built-in read, so
SEC024 surfaces the unqualified name as a review nudge rather
than a hard finding. Allowlist by qualified
policy ID (`schema.table.policy_name`) when the built-in read is
intentional.

Relationship to SEC019: SEC019 flags the *arity* of a
`current_setting` call (the one-argument form, which raises on an
unset parameter); SEC024 flags the *name* (unqualified). They are
orthogonal — a policy reading `current_setting('tenant_id')`
trips both — and a policy can carry one without the other.

Out of scope (intentional):

* **Dynamic parameter names.** `current_setting(<non-literal>)` —
  a name assembled from a column or an expression — is not
  inspected; SEC024 only reads string-literal arguments.
* **Empty parameter names.** `current_setting('')` is a malformed
  call — Postgres raises `invalid configuration parameter name:
  ""` at query time. SEC024's signal is an *unqualified* name (a
  real name that lacks the required prefix), not an absent one.
* **Parameter-value analysis.** SEC024 does not check whether a
  *qualified* name is one the application actually sets, nor what
  the parameter resolves to. It checks the *shape* of the name
  only.
* **`current_setting` outside policies.** A call in a view body,
  a function, or a column `DEFAULT` is not in scope — SEC024
  inspects policy `USING` / `WITH CHECK` clauses only.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import A_Const, String, TypeCast

from pgrls.ast_utils import find_func_calls, is_builtin_current_setting
from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

_CURRENT_SETTING = "current_setting"


def _unqualified_setting_names(node: Any) -> set[str]:
    """Return the unqualified parameter names `current_setting()`
    calls in `node` read — string-literal names containing no `.`.

    `current_setting` is a `FuncCall`; `find_func_calls` matches it
    by name (bare or `pg_catalog`-qualified) and walks sub-selects,
    so a call wrapped in `(SELECT current_setting(...))` is found
    too. Only a literal first argument is inspected — a name built
    from a column or an expression is left alone, since SEC024
    cannot know what it resolves to.
    """
    names: set[str] = set()
    for call in find_func_calls(node, {_CURRENT_SETTING}):
        # SEC024's premise is the Postgres BUILTIN current_setting —
        # whose unqualified parameter names "cannot be SET as a
        # customized parameter at all". `find_func_calls` matches on
        # EITHER the qualified or the bare name, so a user-defined
        # `<schema>.current_setting(...)` (a different function that may
        # legitimately take an unqualified string) would mis-fire. Gate
        # on the builtin via the shared helper (also used by SEC019 and
        # the never-NULL guard). A SQLValueFunction is not a builtin
        # current_setting and is skipped here too.
        if not is_builtin_current_setting(call):
            continue
        # current_setting is always a FuncCall, so it has `args`; guard
        # defensively all the same.
        args = getattr(call, "args", None)
        if not args:
            continue
        first = args[0]
        # Postgres deparses a string-literal argument with an
        # explicit cast — `current_setting('app.x'::text, true)` —
        # so the introspected argument node is a TypeCast wrapping
        # the A_Const. Unwrap it; a hand-written bare literal has
        # no cast and falls straight through.
        while isinstance(first, TypeCast):
            first = first.arg
        if not isinstance(first, A_Const):
            continue
        value = first.val
        if not isinstance(value, String):
            continue
        sval = value.sval
        # An empty name is a malformed call (Postgres raises
        # `invalid configuration parameter name: ""` at query time)
        # — a different class of bug, not SEC024's signal. SEC024
        # flags an *unqualified* name: a real name that lacks the
        # required `prefix.` namespace.
        if not sval:
            continue
        if "." not in sval:
            names.add(sval)
    return names


class SEC024:
    id: str = "SEC024"
    severity: Severity = "info"
    title: str = (
        "Policy calls current_setting() with an unqualified parameter name"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC024", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                names: set[str] = set()
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None:
                        names |= _unqualified_setting_names(ast)
                if not names:
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(
                    self._violation(table, policy, pid, sorted(names))
                )
        return out

    def _violation(
        self,
        table: Table,
        policy: Policy,
        pid: str,
        names: list[str],
    ) -> Violation:
        quoted = ", ".join(repr(n) for n in names)
        noun = "name" if len(names) == 1 else "names"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                f"calls current_setting() with the unqualified "
                f"parameter {noun} {quoted}. A customized run-time "
                "parameter — the per-request context an RLS policy "
                "reads — must have a qualified `prefix.name` (e.g. "
                "current_setting('app.tenant_id')); an unqualified "
                "name cannot be SET as a customized parameter at "
                "all. So this policy reads either a built-in server "
                "setting or a name that can never be set: in the "
                "latter case the predicate quietly matches no rows "
                "(two-argument current_setting) or errors on every "
                "query (one-argument). This is almost always a "
                "dropped prefix — read 'app.tenant_id', not "
                "'tenant_id'. If the policy genuinely keys off a "
                "built-in parameter, allowlist it as "
                f"{pid!r} in [lint.rules.SEC024]."
            ),
            location=pid,
        )
