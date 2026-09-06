"""SEC014 — SECURITY DEFINER function audit (free-standing).

A `SECURITY DEFINER` function runs with the privileges of the function
*owner*, not the calling role: the owner's GRANTs and the owner's RLS
policies apply inside the body instead of the caller's.

That is a **bypass** only when the owner is RLS-exempt for the table —
superuser, `BYPASSRLS`, or the table owner while `FORCE` is off
(measured on PG16: 3 of 3 rows). For an ordinary owner it is a
*re-scoping* that can widen or narrow what the caller reaches (measured:
1 of 3, with and without `FORCE`). SEC042 is the sharpened rule for the
provably-exempt owner; SEC014 flags every SECDEF function because it
cannot see which case applies. A function that the application code calls directly via
``SELECT my_secdef(...)`` therefore presents a privilege-escalation
path: any role with EXECUTE permission on the function inherits the
owner's effective reach into RLS-protected tables.

Two existing rules already cover this risk for *indirect* invocation
paths:

* **VIEW004** flags views whose body calls a SECDEF function that reads
  an RLS-protected table — view-mediated bypass.
* **SEC013** flags triggers on RLS-protected tables — a trigger
  function runs as the CALLER unless it is ``SECURITY DEFINER``
  (measured), and the linter cannot read the body to tell which.

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
  parse). The rule is an "audit every SECDEF surface" prompt, not a
  proof-of-leak.
* **Cross-scope SECDEF functions.** A SECDEF function defined in a
  schema outside the introspector's ``--schemas`` set is invisible to
  SEC014 — `Schema.security_definer_functions` only carries what
  introspection captured. Same false-negative path VIEW004 documents
  for cross-scope calls. To audit such functions, expand
  ``--schemas`` to include the function's home schema.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, SecdefFunction
from pgrls.rules._allowlist import parse_qualified_function_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_qualified_function_allowlist("SEC014", options)


class SEC014:
    id: str = "SEC014"
    severity: Severity = "warning"
    title: str = "SECURITY DEFINER function bypasses caller's RLS"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        # Snapshot v12+ captures one `SecdefFunction` entry per
        # overload (the SECDEF SQL query never had a SELECT DISTINCT —
        # this was the case pre-v12 too, just less explicit before the
        # `signature` field landed). The rule reports per qualified
        # name — the message names the function, not a specific
        # overload signature — so dedupe by qualified_name as we walk.
        # Pins the contract the docstring promises ("Two overloads of
        # the same qualified name are flagged once and allowlisted
        # once") which the pre-dedup loop did not enforce.
        #
        # `security_definer_functions` is captured in
        # `(qname, signature)` order at introspection time, so the
        # first-seen overload determines the captured entry's
        # rendered language / body; the order is deterministic
        # without a `sorted(...)` here.
        seen: set[str] = set()
        for fn in schema.security_definer_functions:
            if fn.qualified_name in allowlist:
                continue
            if fn.qualified_name in seen:
                continue
            seen.add(fn.qualified_name)
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
