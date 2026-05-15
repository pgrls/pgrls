"""SEC014 — SECURITY DEFINER function audit (free-standing).

A `SECURITY DEFINER` function runs with the privileges of the function
*owner*, not the calling role. Every SELECT/INSERT/UPDATE/DELETE inside
the function body sees the owner's view of the database — RLS bypassed,
GRANT/REVOKE differences flattened, the entire row set readable and
mutable. A function that the application code calls directly via
``SELECT my_secdef(...)`` therefore presents a privilege-escalation
path: any role with EXECUTE permission on the function inherits the
owner's effective reach into RLS-protected tables.

Two existing rules already cover this risk for *indirect* invocation
paths:

* **VIEW004** flags views whose body calls a SECDEF function that reads
  an RLS-protected table — view-mediated bypass.
* **SEC013** flags triggers on RLS-protected tables, which fire as the
  table owner and bypass RLS regardless of the trigger function's
  ``prosecdef`` flag.

SEC014 fills the gap by flagging *every* SECDEF function in the
introspected schemas, regardless of how it's invoked. The intent isn't
to detect free-standing-vs-trigger-vs-view via call-graph analysis
(which would require app-level context pgrls doesn't have) — it's to
surface the full SECDEF surface to the operator so each function gets
an explicit audit decision: either rewrite as ``SECURITY INVOKER`` (so
RLS applies to the caller), or document why the bypass is intentional
and allowlist the function.

Detection is structural: walk ``Schema.security_definer_functions``
(captured by introspection from ``pg_proc.prosecdef = TRUE`` since
snapshot v4). Allowlist entries are qualified function names
(``schema.function``). A bare function name is rejected — two
identically-named functions in different schemas would otherwise both
be silenced, and the cross-schema collision is subtle.

Severity: warning. No auto-fix — the architectural choice (INVOKER vs
audited-DEFINER) needs human intent.

Out of scope (intentional):

* **Argument signatures** are not part of the allowlist shape. A function
  may be overloaded (``public.do_thing(int)`` vs ``public.do_thing(text)``);
  ``pg_proc.proname`` is what introspection captures and what this rule
  matches against. Two overloads of the same qualified name are
  flagged once and allowlisted once. Operators who need per-overload
  granularity should `ALTER FUNCTION` one of them to a different name.
* **Function-body reachability of RLS tables** is not gated here. VIEW004
  already analyses bodies for RLS-table reads; doing it again in SEC014
  would either duplicate the analysis or under-report (e.g. a SECDEF
  function that writes to an RLS table via dynamic SQL pglast can't
  parse). The rule is a "audit every SECDEF surface" prompt, not a
  proof-of-leak.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, SecdefFunction
from pgrls.rules._allowlist import _list_of_strings
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    # `schema.function` form. Reuse the existing shape validator for
    # consistency with VIEW004's `parse_qualified_view_allowlist` —
    # both rules need exactly two non-empty `.`-separated parts.
    # Function names in Postgres can contain `.` only when quoted
    # (`"odd.name"`), which `pg_catalog.pg_proc.proname` introspection
    # already normalizes, so a literal `split('.')` is unambiguous
    # here. The hint string is rule-specific so a typo'd entry's
    # error message names "function" rather than "view".
    raw = options.get("allowlist", [])
    items = _list_of_strings(
        "SEC014",
        raw,
        "of the form 'schema.function'",
    )
    for entry in items:
        parts = entry.split(".")
        if len(parts) != 2 or not all(parts):
            raise TypeError(
                f"[lint.rules.SEC014].allowlist entry {entry!r} is "
                f"not a valid qualified function ID. Expected "
                f"'schema.function' (e.g. 'public.refresh_cache')."
            )
    return set(items)


class SEC014:
    id: str = "SEC014"
    severity: Severity = "warning"
    title: str = "SECURITY DEFINER function bypasses caller's RLS"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        # `security_definer_functions` is captured in alphabetical
        # (schema, name) order at introspection time, so iteration
        # order is deterministic without a `sorted(...)` here.
        for fn in schema.security_definer_functions:
            if fn.qualified_name in allowlist:
                continue
            out.append(self._violation(fn))
        return out

    def _violation(self, fn: SecdefFunction) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Function {fn.qualified_name} is SECURITY DEFINER "
                f"(language={fn.language!r}). It runs with the "
                "function owner's privileges, not the caller's — "
                "any SELECT/INSERT/UPDATE/DELETE inside the body "
                "bypasses the caller's RLS policies, GRANT/REVOKE "
                "differences, and any other privilege check. A "
                "role with EXECUTE on this function effectively "
                "inherits the owner's reach into RLS-protected "
                "tables. Either rewrite as SECURITY INVOKER (RLS "
                "applies to the caller), or audit the function "
                "body to confirm it doesn't expose data the caller "
                "couldn't read directly and allowlist this "
                f"function as {fn.qualified_name!r} in "
                "[lint.rules.SEC014]. VIEW004 covers the view-"
                "mediated path and SEC013 the trigger-mediated "
                "path; SEC014 closes the gap for functions called "
                "directly from application code."
            ),
            location=fn.qualified_name,
        )
