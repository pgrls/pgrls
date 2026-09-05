"""SEC016 — role with the BYPASSRLS attribute bypasses all RLS.

A Postgres role granted the `BYPASSRLS` attribute skips *every*
row-level security policy on *every* table. RLS is not weakened for
that role — it is simply off. Any session whose current role holds
the attribute reads and writes every row in every RLS-protected
table as if no policy existed.

The danger is that a `BYPASSRLS` role looks ordinary. Nothing in a
table definition, a policy, or a `GRANT` reveals that a particular
role ignores all of them. An application that connects as a
`BYPASSRLS` role gets zero tenant isolation while every policy in
the schema still reads as airtight — the bypass is invisible at
every layer SEC001–SEC015 inspect.

`BYPASSRLS` is unconditional and cluster-wide. Contrast the two
*other* ways a session can end up not subject to RLS:

* A **table owner** implicitly bypasses RLS on its own tables — but
  only until `ALTER TABLE … FORCE ROW LEVEL SECURITY` is set, which
  is exactly what SEC002 flags. `FORCE` does **not** touch a
  `BYPASSRLS` role: it bypasses a FORCE'd table just the same.
* A **superuser** bypasses RLS via `rolsuper`, also unconditionally.
  A superuser additionally carrying `BYPASSRLS` gains nothing — the
  attribute is redundant noise on one. SEC016 therefore **skips
  superuser roles** and flags only the non-superuser roles, where
  an RLS bypass is genuinely surprising.

SEC016 fires on every non-superuser role with `BYPASSRLS`. The fix
is one statement — `ALTER ROLE <name> NOBYPASSRLS` — but it is not
auto-applied: pgrls cannot tell a misconfigured application role
from a backup / logical-replication / ETL role that legitimately
needs the attribute. The operator removes it, or allowlists the
role after confirming the bypass is intentional.

Roles are cluster-global, so SEC016 — unlike the schema-scoped
rules — has no out-of-scope blind spot: it sees every `BYPASSRLS`
role in the cluster regardless of the introspector's ``--schemas``
set.

Severity: warning. Allowlist by role name; a bare name is the only
shape, because Postgres roles have no schema component.

Relationship to the other bypass rules: SEC002 covers the
table-owner bypass (mechanism: ownership; remedy: `FORCE`).
SEC013/SEC014/SEC015 cover code-mediated bypass: `SECURITY DEFINER`
functions run as the function owner, reached directly (SEC014/SEC015)
or through a trigger whose body the linter cannot read (SEC013). SEC016 covers the
attribute-mediated bypass — the role itself is exempt, no code or
ownership involved. It is the bluntest of the family: where the
others need a specific object to be misconfigured, SEC016 needs
only a role attribute to be set.

Out of scope (intentional):

* **Superuser roles.** Skipped — see above. A superuser is a far
  larger finding than "bypasses RLS," and `rolsuper` already makes
  the BYPASSRLS attribute moot.
* **Role membership / `SET ROLE` reachability.** SEC016 flags the
  role that *holds* `BYPASSRLS`, not every role that could reach it.
  `BYPASSRLS` is a role attribute, not an inheritable privilege — a
  member of a `BYPASSRLS` group role does not bypass RLS unless it
  actually `SET ROLE`s to that role. SEC016's surface is deliberately
  just the holder; the `SET ROLE` escalation path that reaches it is
  covered separately by SEC029.
* **The `row_security` session GUC.** `SET row_security = off` is a
  different mechanism, and not a silent one: a query that *would*
  return RLS-filtered rows raises an error instead of quietly
  widening, unless the role already owns the table or holds
  `BYPASSRLS`. SEC016 covers the attribute, not the GUC.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import BypassRlsRole, Schema
from pgrls.rules._allowlist import parse_role_name_allowlist
from pgrls.violations import Severity, Violation


class SEC016:
    id: str = "SEC016"
    severity: Severity = "warning"
    title: str = "Role with BYPASSRLS attribute bypasses all RLS"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_role_name_allowlist("SEC016", options)
        out: list[Violation] = []
        for role in schema.bypassrls_roles:
            if role.name in allowlist:
                continue
            # A superuser bypasses RLS via `rolsuper` regardless of
            # BYPASSRLS — the attribute is redundant noise on one.
            if role.superuser:
                continue
            out.append(self._violation(role))
        return out

    def _violation(self, role: BypassRlsRole) -> Violation:
        if role.can_login:
            reach = (
                "This role can log in directly, so an application "
                "that authenticates as it receives no row-level "
                "isolation at all"
            )
        else:
            reach = (
                "This role cannot log in directly, but any role that "
                "can SET ROLE to it bypasses RLS for as long as that "
                "SET ROLE is in effect"
            )
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Role {role.name} has the BYPASSRLS attribute. A "
                "role with BYPASSRLS skips every row-level security "
                "policy on every table — RLS is effectively disabled "
                "for it, unconditionally and cluster-wide (unlike a "
                "table owner, whose implicit bypass stops once FORCE "
                f"ROW LEVEL SECURITY is set). {reach}. Most "
                "application roles should not carry BYPASSRLS; it is "
                "typically needed only by backup, logical-replication, "
                "or ETL roles. If this role does not genuinely need "
                "to bypass RLS, remove the attribute: "
                f"`ALTER ROLE {role.name} NOBYPASSRLS`. If the bypass "
                f"is intentional, allowlist this role as {role.name!r} "
                "in [lint.rules.SEC016]."
            ),
            location=role.name,
        )
