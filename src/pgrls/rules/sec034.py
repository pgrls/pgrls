"""SEC034 — Policy gates on `auth.email()` (silent denial / lockout).

A policy that scopes rows by email — typically:

    USING (owner_email = auth.email())

— ships with three subtle failure modes that aren't exploits but
*are* footguns. The cumulative behavior is data lockout, not
privilege escalation:

1. **Email change flow.** Supabase auth supports user-initiated
   email change. The new email lands in the JWT after verification;
   rows that were owned by the old email are now invisible to the
   user who owns them. Repair requires a manual UPDATE on every
   email-keyed table.

2. **Case sensitivity.** SQL `=` is case-sensitive; conventional
   email handling is case-insensitive for the local part on most
   mail providers and case-insensitive for the domain part per RFC.
   `User@Example.com` stored vs `user@example.com` in the JWT
   never matches — silent deny.

3. **Plus-addressing / aliasing.** `user+tag@gmail.com` and
   `user@gmail.com` reach the same inbox but compare unequal.
   Combined with apps that normalize one but not the other, rows
   become orphaned from the user who created them.

The hazard class is different from SEC033 / SEC036 (which are
CVE-class privilege escalation): SEC034 is silent denial-of-
service-to-self. Severity is `warning` — surfaced for review,
doesn't fail CI by default the way SEC033 / SEC036 do.

The canonical fix is to scope by `auth.uid()` (immutable per
user, normalized, case-insensitive) and treat email as a display
field. If the policy needs an email lookup, do it via
`(SELECT id FROM auth.users WHERE id = auth.uid())` and key
downstream tables off the resolved `uid`.

Detection: walks policy USING / WITH CHECK ASTs for FuncCall
nodes whose qualified name matches one of the configured
email-context functions (default: `auth.email`). One finding per
policy, regardless of how many `auth.email()` references it
contains. SubLink contents ARE walked — a wrapped
`(SELECT auth.email())` (a PERF001-friendly wrap that the rest of
the catalog tolerates) still trips SEC034 because the underlying
hazard is the same.

Configuration: `[lint.rules.SEC034]` accepts:

  - `email_functions` (list[str]) — function names whose call
    counts as an email-based-authz signal. Replaces the default
    `["auth.email"]`. Add project-specific helpers
    (e.g. `["auth.email", "app.user_email"]`).
  - `allowlist` (list[str]) — `schema.table.policy` IDs to exempt
    (audit trail policies that read email for logging, display-
    only policies, etc.).
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import find_func_calls
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_DEFAULT_EMAIL_FUNCTIONS: frozenset[str] = frozenset({"auth.email"})


def _parse_email_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("email_functions")
    if raw is None:
        return set(_DEFAULT_EMAIL_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC034].email_functions must be a list of "
            "function names (qualified or bare), e.g. "
            '["auth.email", "app.user_email"]'
        )
    return set(raw)


class SEC034:
    id: str = "SEC034"
    severity: Severity = "warning"
    title: str = (
        "Policy gates on auth.email() (mutable per user; case-sensitive)"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        email_functions = _parse_email_functions(options)
        allowlist = parse_policy_id_allowlist("SEC034", options)

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                trees = [
                    t
                    for t in (policy.using_ast, policy.with_check_ast)
                    if t is not None
                ]
                # `find_func_calls` walks into SubLinks by default,
                # so a `(SELECT auth.email())` PERF-friendly wrap is
                # still detected — the underlying hazard (gating on
                # a mutable, case-sensitive, alias-folding field)
                # doesn't go away because of the wrap.
                if not any(
                    find_func_calls(t, email_functions) for t in trees
                ):
                    continue
                out.append(
                    Violation(
                        rule_id="SEC034",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} references "
                            "`auth.email()` in its USING / WITH CHECK "
                            "expression. Email-based row scoping has "
                            "three silent failure modes: (1) email "
                            "change flow leaves the user locked out "
                            "of their own data, (2) SQL `=` is case-"
                            "sensitive while emails conventionally "
                            "aren't, (3) plus-addressing makes "
                            "`x+y@host` and `x@host` compare unequal "
                            "despite reaching the same inbox. None "
                            "are exploits, but each is a silent "
                            "denial-of-service to legitimate users. "
                            "Scope by `auth.uid()` instead (immutable "
                            "per user) and treat email as a display "
                            "field. If the policy needs an email "
                            "lookup, derive it from auth.users via "
                            "auth.uid(). Allowlist this policy if "
                            "the read is intentional (audit log, "
                            "display-only)."
                        ),
                        location=pid,
                    )
                )
        return out
