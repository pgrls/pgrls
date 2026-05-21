"""SEC029 — role can SET ROLE to a BYPASSRLS role (RLS-bypass path).

`BYPASSRLS` is a role *attribute*. Role attributes — unlike object
privileges — are **never inherited** through role membership, even
with `INHERIT`. So being a member of a BYPASSRLS-carrying role does
NOT make you bypass RLS automatically: SEC016 (which flags roles
that hold BYPASSRLS directly) wouldn't list you, and your own
`pg_roles` row looks clean.

But membership grants `SET ROLE`. A role that is a member —
directly or transitively — of a BYPASSRLS role can run
`SET ROLE <that role>` and, from that point in the session, bypass
every row-level security policy on every table. That's an
RLS-bypass *path* that's invisible from the member's attributes:

    CREATE ROLE admin BYPASSRLS NOLOGIN;
    CREATE ROLE app LOGIN;
    GRANT admin TO app;        -- app can `SET ROLE admin`, then bypass RLS

`app` here has no BYPASSRLS of its own (SEC016 stays silent), yet a
single `SET ROLE admin` turns RLS off for the rest of the session.
SEC029 surfaces that route so the membership gets an explicit audit
decision.

SEC029 fires for each role that can reach a BYPASSRLS role through
the transitive `pg_auth_members` closure and does not itself hold
BYPASSRLS (SEC016's surface) and is not a superuser (which bypasses
unconditionally regardless of membership). The finding names the
reachable BYPASSRLS role(s) so the operator can see the escalation
target.

Severity: warning. It is a path, not an automatic bypass — a member
must deliberately `SET ROLE` — so it ranks below SEC016's direct
BYPASSRLS holder, but it is still an RLS-off route that an
application authenticating as a LOGIN member can take. Allowlist the
*member* role by name (roles are unqualified, like SEC016's
allowlist) when the membership is intentional and the member is
trusted not to escalate, e.g. an admin/operator login that is
expected to be able to bypass.

Scope (intentional):

* **Membership = SET ROLE-capable.** Detection treats every
  `pg_auth_members` edge as permitting `SET ROLE`. On PostgreSQL
  16+ a membership granted `WITH SET FALSE` does not permit it, so
  SEC029 can over-report there — a deliberate bias toward surfacing
  a potential bypass route (allowlist a false positive) over
  missing one. The membership graph is captured version-agnostically
  to keep the introspection query identical across PG15-17.
* **No auto-fix.** Whether to revoke the membership, split the
  BYPASSRLS into a narrower grant, or accept the route is an
  operational decision pgrls can't make.

The transitive membership closure is computed at introspection time
(`pgrls.introspect`) and stored on `Schema.bypassrls_escalation_roles`
(snapshot v11+); a pre-v11 snapshot loads it empty and SEC029 finds
nothing until the snapshot is re-captured against a live database.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import parse_role_name_allowlist
from pgrls.violations import Severity, Violation


class SEC029:
    id: str = "SEC029"
    severity: Severity = "warning"
    title: str = "Role can SET ROLE to a BYPASSRLS role (RLS-bypass path)"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_role_name_allowlist("SEC029", options)
        out: list[Violation] = []
        for esc in schema.bypassrls_escalation_roles:
            if esc.member in allowlist:
                continue
            via = ", ".join(repr(r) for r in esc.via)
            login_note = (
                "It is a LOGIN role, so an application that "
                "authenticates as it is one SET ROLE from full RLS "
                "bypass. "
                if esc.member_can_login
                else "It is a NOLOGIN role, reached only by something "
                "that can already become it, but the bypass route "
                "still exists. "
            )
            out.append(
                Violation(
                    rule_id="SEC029",
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Role {esc.member!r} is a member of BYPASSRLS "
                        f"role(s) {via}, so it can SET ROLE to one and "
                        "bypass every row-level security policy. "
                        "BYPASSRLS is a role attribute that is not "
                        "inherited through membership, so this route "
                        "is invisible from the role's own attributes "
                        f"(SEC016 does not flag it). {login_note}"
                        "Revoke the membership, narrow what the "
                        "BYPASSRLS role grants, or allowlist "
                        f"{esc.member!r} in [lint.rules.SEC029] if the "
                        "membership is intentional and the role is "
                        "trusted to bypass."
                    ),
                    location=esc.member,
                )
            )
        return out
