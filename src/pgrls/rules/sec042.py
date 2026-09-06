"""SEC042 — anonymously-executable SECURITY DEFINER function bypasses RLS.

A ``SECURITY DEFINER`` function runs with the privileges of its **owner**,
not the caller. When the owner is itself **RLS-exempt** — a superuser or a
role carrying ``BYPASSRLS`` — every ``SELECT``/``INSERT``/``UPDATE``/
``DELETE`` inside the body skips row-level security entirely. If that
function is also **executable by an unauthenticated / low-trust role**
(``anon`` or ``PUBLIC``), an attacker who can call it runs owner-privileged,
RLS-exempt code: in a PostgREST/Supabase deployment, a single
``POST /rpc/<function>`` with the anon key reaches into every policy-
protected table the owner can see, reading or mutating rows no RLS policy
would ever release directly.

```sql
-- owned by `postgres` (superuser), so RLS does not apply inside it:
CREATE FUNCTION public.all_orders() RETURNS SETOF orders
    LANGUAGE sql SECURITY DEFINER AS 'SELECT * FROM orders';
-- ...and no `REVOKE EXECUTE ... FROM PUBLIC`, so anon can call it.

-- as the anon role (no row visibility of its own):
SELECT * FROM public.all_orders();   -- every tenant's orders — RLS bypassed
```

**The default is the footgun.** Unlike a table (whose default ACL is
owner-only), a function's **default ``EXECUTE`` privilege is granted to
``PUBLIC``**. A ``SECURITY DEFINER`` function created without an explicit
``REVOKE EXECUTE ... FROM PUBLIC`` is therefore anon-callable *by default* —
the silent mistake this rule exists to catch. Introspection expands that
default (``pg_proc.proacl IS NULL`` → ``execute_roles = ("PUBLIC",)``) so the
rule sees it.

**Both conditions are required — and verified empirically.** SECURITY
DEFINER alone does **not** imply an RLS bypass: if the owner is an *ordinary*
role and the tables it reads have ``FORCE ROW LEVEL SECURITY`` (which pgrls
itself recommends), the owner is still subject to RLS, and the function
returns the owner's policy-scoped rows — not every row. So SEC042 fires only
when ``owner_bypasses_rls`` is true (owner is superuser or BYPASSRLS) **and**
the function is EXECUTE-able by a configured low-trust role. This keeps the
finding high-confidence rather than re-flagging every SECDEF function.

**Relationship to SEC014.** SEC014 surfaces *every* SECURITY DEFINER
function (severity ``warning``) so each gets an audit decision, regardless of
who can call it or whether the owner is RLS-exempt. SEC042 is the sharp,
high-severity subset: the function is provably an *unauthenticated RLS-bypass
endpoint* (RLS-exempt owner × low-trust EXECUTE). The two are complementary —
SEC042 escalates the cases that are exploitable as-is, exactly as SEC039
(anon write policy) sharpens SEC003 (PUBLIC grant). VIEW004 covers the
view-mediated SECDEF path and SEC013 the trigger-mediated path.

Configure the low-trust role set with ``[lint.rules.SEC042].anon_roles``
(default ``["anon", "PUBLIC"]``; the literal ``public`` is matched
case-insensitively to the PUBLIC pseudo-role). Remediate by
``REVOKE EXECUTE ON FUNCTION ... FROM PUBLIC`` (and from ``anon``), granting
EXECUTE only to trusted roles; or rewrite the function as ``SECURITY
INVOKER`` so the caller's RLS applies; or reassign it to a non-RLS-exempt
owner. Allowlist a deliberately-public function as ``schema.function`` in
``[lint.rules.SEC042]``.

Severity: error — an unauthenticated privilege-escalation endpoint. No
auto-fix: whether to REVOKE, re-own, or rewrite is an architectural decision
pgrls cannot make safely.

Scope / known limits (intentional, fail-closed):

* **Owner reach is not enumerated.** SEC042 establishes that the owner is
  RLS-exempt, not *which* RLS tables the body touches (the body may use
  dynamic SQL or PL/pgSQL pglast can't parse). The exposure — anon runs
  RLS-exempt owner code — holds regardless, and the body can change.
* **Ordinary-owner bypass of a non-FORCE table** (the owner bypasses a table
  it owns when ``FORCE`` is off) is *not* flagged here — that is SEC002's
  finding; enable ``FORCE`` and the bypass closes.
* **Cross-scope functions** in a schema outside ``--schemas`` are invisible,
  the same false-negative path SEC014/VIEW004 document.
* **Transitive group grants are not expanded.** ``execute_roles`` lists the
  literal EXECUTE grantees, so EXECUTE granted to a *group* role that a
  low-trust role is merely a member of is not flagged — mirroring SEC003 /
  SEC039, which check ``PUBLIC`` / ``anon`` literally against the policy's
  role list. Grant EXECUTE to the low-trust role directly (or revoke the
  group grant) to surface it; the membership closure exists (SEC029 computes
  it). `verify --mode escalation` DOES expand it — measured, it flags a
  function EXECUTE-able only through `GRANT readers TO anon`, which this
  rule's literal check misses.
* Snapshots predating v16 carry no ``execute_roles`` / ``owner_bypasses_rls``;
  SEC042 abstains on them (fail-closed) until re-captured.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, SecdefFunction
from pgrls.rules._allowlist import parse_qualified_function_allowlist
from pgrls.violations import Severity, Violation

# Default low-trust executors: the Supabase unauthenticated role and the
# PUBLIC pseudo-role (which also covers the no-REVOKE default-EXECUTE case).
# `authenticated` is deliberately excluded — granting a controlled SECDEF
# RPC to signed-in users is a common, often-intentional pattern; add it via
# config if a deployment wants it flagged.
_DEFAULT_ANON_ROLES = ("anon", "PUBLIC")


def _parse_anon_roles(options: dict[str, Any]) -> set[str]:
    raw = options.get("anon_roles")
    if raw is None:
        return set(_DEFAULT_ANON_ROLES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC042].anon_roles must be a list of role-name "
            "strings (e.g. ['anon', 'PUBLIC'])."
        )
    # Normalize the public pseudo-role to the stored "PUBLIC" form so a
    # config entry of "public"/"Public" still matches (real roles are
    # case-sensitive, but PUBLIC is a reserved keyword, never a real role).
    return {"PUBLIC" if s.lower() == "public" else s for s in raw}


class SEC042:
    id: str = "SEC042"
    severity: Severity = "error"
    title: str = "Anonymously-executable SECURITY DEFINER function bypasses RLS"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_qualified_function_allowlist("SEC042", options)
        anon_roles = _parse_anon_roles(options)
        out: list[Violation] = []
        # One `SecdefFunction` entry per overload; report per qualified
        # name (the message names the function, not a signature), so
        # dedupe as we walk. A name fires if ANY overload qualifies — a
        # non-qualifying overload neither reports nor blocks a later
        # qualifying one (it is not added to `seen`).
        seen: set[str] = set()
        for fn in schema.security_definer_functions:
            if fn.qualified_name in seen:
                continue
            if fn.qualified_name in allowlist:
                continue
            if not fn.owner_bypasses_rls:
                # Owner is not RLS-exempt → the SECDEF function is still
                # subject to RLS (e.g. an ordinary owner under FORCE RLS),
                # so calling it is not a bypass. SEC014 still audits it.
                continue
            callers = sorted(anon_roles.intersection(fn.execute_roles))
            if not callers:
                # Not executable by any low-trust role → not an anonymous
                # endpoint. (No row in execute_roles also means a pre-v16
                # snapshot → abstain.)
                continue
            seen.add(fn.qualified_name)
            out.append(self._violation(fn, callers))
        return out

    def _violation(
        self, fn: SecdefFunction, callers: list[str]
    ) -> Violation:
        roles = ", ".join(callers)
        name = fn.function_name or fn.qualified_name
        public_note = (
            " A function's EXECUTE privilege defaults to PUBLIC, so this "
            "applies even with no explicit GRANT — REVOKE it explicitly."
            if "PUBLIC" in callers
            else ""
        )
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Function {fn.qualified_name} is SECURITY DEFINER and runs "
                "as its owner, which bypasses row-level security (the owner "
                "is a superuser or carries BYPASSRLS). Its EXECUTE privilege "
                f"is held by {roles}, so an unauthenticated / low-trust "
                f"caller (e.g. a PostgREST `POST /rpc/{name}` request with "
                "the anon key) runs owner-privileged, RLS-exempt code and "
                "can read or write any data the owner can, bypassing every "
                f"policy.{public_note} Remediate by REVOKE EXECUTE ON "
                f"FUNCTION ... FROM {roles} (granting EXECUTE only to trusted "
                "roles), rewriting the function as SECURITY INVOKER, or "
                "reassigning it to a non-RLS-exempt owner; or allowlist it as "
                f"{fn.qualified_name!r} in [lint.rules.SEC042]."
            ),
            location=fn.qualified_name,
        )
