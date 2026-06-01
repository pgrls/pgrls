"""SEC019 — policy calls current_setting() without the missing_ok argument.

`current_setting(name)` — the one-argument form — raises
`ERROR: unrecognized configuration parameter "name"` when `name` is
a GUC that has never been set in the session. `current_setting(name,
missing_ok)` — the two-argument form — returns NULL instead when
`missing_ok` is true.

RLS policies routinely read the tenant/session context from a
custom GUC the application sets per request:

    CREATE POLICY p ON documents
        USING (tenant_id = current_setting('app.tenant_id'));

With the one-argument form, a request that reaches the database
*without* having run `SET app.tenant_id = …` does not get a quiet,
empty result — the policy expression itself raises, so **every**
query against the table errors until the GUC is set. The two-arg
form `current_setting('app.tenant_id', true)` instead yields NULL;
in the typical `column = current_setting(...)` predicate that NULL
makes the comparison match no rows — the query succeeds and returns
nothing.

Which behaviour is "better" is a genuine judgement call — a loud
error surfaces the missing-context bug immediately, while a quiet
empty result is friendlier but can mask it. SEC019 does not assert
one is wrong. It is an **info**-level rule: it surfaces the
one-argument form so the choice between "raise" and "return NULL on
an unset GUC" is a deliberate one rather than an accident of which
overload the author reached for. The two-argument form is also what
the rest of a typical policy set converges on, so a lone one-arg
call is often just an oversight.

SEC019 fires when a policy's `USING` or `WITH CHECK` expression
contains a `current_setting` call with exactly one argument —
anywhere in the tree, including inside a `(SELECT current_setting
(...))` wrapper. Detection is structural (`find_func_calls` over
the parsed policy AST); it does not inspect the GUC name.

Severity: info. Allowlist by qualified policy ID
(`schema.table.policy_name`) — allowlist a policy when the
raise-on-unset behaviour is the intended, documented choice.

Relationship to SEC004: SEC004 catches the genuinely dangerous
`current_setting(...) IS NULL OR <check>` shape — a *fail-open*
predicate that admits every row when the GUC is unset — and is an
error. SEC019 is unrelated to fail-open: the one-arg form fails
*closed* (it raises). SEC019 only nudges toward the more robust
overload; it is info, not a security finding. A policy can trip
both rules independently.

Out of scope (intentional):

* **No security claim.** The one-argument form fails closed (an
  error, never a silent widening). SEC019 is a robustness/hygiene
  nudge — hence info severity — not a vulnerability report.
* **GUC-name analysis.** SEC019 does not check which GUC is read,
  whether it looks tenant-related, or whether the application
  actually sets it — that is context outside the database.
* **`current_setting` outside policies.** A one-arg call in a view
  body, a function, or a `DEFAULT` expression is not in scope —
  SEC019 inspects policy `USING` / `WITH CHECK` clauses only.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import find_func_calls
from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

_CURRENT_SETTING = "current_setting"


def _has_one_arg_current_setting(node: Any) -> bool:
    """True if the tree contains a one-argument `current_setting` call.

    `current_setting` is a `FuncCall`; `find_func_calls` matches it
    by name (bare or `pg_catalog`-qualified) and walks sub-selects,
    so a call wrapped in `(SELECT current_setting(...))` is found
    too. The one-argument form is the `missing_ok`-less overload
    that raises on an unset GUC.
    """
    for call in find_func_calls(node, {_CURRENT_SETTING}):
        # `find_func_calls` can also return SQLValueFunction nodes
        # (current_user etc.); those have no `args`. current_setting
        # is always a FuncCall — guard defensively all the same.
        args = getattr(call, "args", None)
        if args is not None and len(args) == 1:
            return True
    return False


class SEC019:
    id: str = "SEC019"
    severity: Severity = "info"
    title: str = "Policy calls current_setting() without the missing_ok argument"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC019", options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                fires = False
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None and _has_one_arg_current_setting(ast):
                        fires = True
                        break
                if not fires:
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(self._violation(table, policy, pid))
        return out

    def _violation(
        self, table: Table, policy: Policy, pid: str
    ) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                "calls current_setting() with a single argument. The "
                "one-argument form raises `unrecognized configuration "
                "parameter` if the GUC has not been set in the "
                "session — so every query against the table errors "
                "when a request reaches the database without its "
                "session context configured. The two-argument form, "
                "current_setting('...', true) — passing the "
                "missing_ok argument — returns NULL instead; "
                "in a typical `column = current_setting(...)` "
                "predicate that NULL simply matches no rows (the "
                "query succeeds, empty) rather than erroring. Neither "
                "is a security hole — the one-arg form fails closed — "
                "so this is an info-level robustness nudge: pick the "
                "overload deliberately. If the raise-on-unset "
                "behaviour is intended, allowlist this policy as "
                f"{pid!r} in [lint.rules.SEC019]."
            ),
            location=pid,
        )
