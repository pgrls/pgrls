"""SEC048 — low-trust role can reach an RLS table's owner that is not FORCE'd.

A role that OWNS a table bypasses that table's row-level security
unless ``FORCE ROW LEVEL SECURITY`` is set (the SEC002 boundary). The
BYPASSRLS *attribute* SEC029 covers is never inherited through role
membership, but owner *privileges* ARE: a role that is a member —
directly or transitively — of the owning role inherits its ownership
(with ``INHERIT`` automatically; with ``NOINHERIT`` after a single
``SET ROLE``) and so bypasses RLS on every one of that owner's
enabled-but-not-forced tables. This is the **table-owner analog of
SEC029**:

    CREATE ROLE app_owner NOLOGIN;             -- owns the tables
    CREATE ROLE app LOGIN;                      -- the app's login role
    GRANT app_owner TO app;                     -- app inherits ownership
    -- app_owner owns `orders` with RLS ENABLEd but NOT FORCEd
    --   → `app` reads every tenant's rows of `orders`, RLS notwithstanding

``app`` here holds no BYPASSRLS attribute (SEC016/SEC029 stay silent —
attributes aren't inherited), yet because it is a member of the table
owner it bypasses RLS on the owner's not-forced tables. Live-proven: a
non-superuser/non-BYPASSRLS LOGIN member of the owner read ALL rows of
an ``ENABLE``d-but-not-``FORCE``'d table; ``FORCE ROW LEVEL SECURITY``
is the exact non-leak boundary (the same member then saw zero rows).

SEC048 fires once per reachable member role ``M`` such that ALL hold:

1. there is a table ``T`` in the scanned schemas with RLS enabled and
   FORCE off;
2. ``M`` is in the transitive ``pg_auth_members`` closure of
   ``owner(T)`` (any membership edge — ``INHERIT`` or not, since
   ``NOINHERIT`` still permits ``SET ROLE``, matching SEC029's stance);
3. ``owner(T)`` is NOT superuser and NOT BYPASSRLS (those are
   SEC016/SEC029 territory — excluding them keeps SEC048 disjoint from
   SEC029); and
4. ``M`` is NOT superuser and NOT BYPASSRLS (it already bypasses
   unconditionally — SEC016/SEC029 again).

Conditions 3 and 4 are enforced at introspection time (the
``owner_reachable_members`` closure already excludes superuser/
BYPASSRLS owners and members), so by the time this rule runs every
``OwnerReachableMember`` is a genuine SEC048 finding outside SEC029's
surface. The disjointness is therefore *structural*, not a tie-break:
SEC029's surface is members reaching a BYPASSRLS-attribute role; SEC048's
is members reaching a non-BYPASSRLS owner — no role can be both for the
same path.

Severity: warning. It is a bypass *route*, like SEC029 — a NOINHERIT
member must deliberately ``SET ROLE`` (an INHERIT member bypasses
automatically). It ranks alongside SEC002, which fires ``error`` on the
table itself for the same missing-FORCE misconfiguration; the two are
**mutually independent and co-fire by design** (SEC002 reports the
table, SEC048 reports each reachable role), exactly as
SEC001/SEC032/SEC043 co-fire. SEC048 cedes nothing, so no rule-
interaction cede-gap can open.

Remediation: run ``ALTER TABLE … FORCE ROW LEVEL SECURITY`` on the
owner's tables (re-applies RLS even to the owner and its members),
revoke the membership, or allowlist the member (``allowlist``) /
the owner (``trusted_owner_roles``) when the reach is intentional.
There is no auto-fix — whether to FORCE the tables, revoke the
membership, or accept the route is an operational decision pgrls
cannot make.

The reachable-member closure is computed at introspection time
(`pgrls.introspect`) and stored on `Schema.owner_reachable_members`
(snapshot v21+); a pre-v21 snapshot loads it empty and SEC048 finds
nothing until the snapshot is re-captured against a live database
(fail-closed).
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema
from pgrls.rules._allowlist import _list_of_strings, parse_role_name_allowlist
from pgrls.violations import Severity, Violation


def _parse_trusted_owner_roles(options: dict[str, Any]) -> set[str]:
    """Validate ``trusted_owner_roles`` as a list of bare role names.

    Owning roles whose reachability is expected (a deliberately shared
    owner). Same shape as the member ``allowlist`` (unqualified role
    names — roles are cluster-global with no schema component), but a
    distinct option so an operator can suppress by *owner* without
    listing every member individually. Reuses the shared list-of-strings
    + surrounding-whitespace validator and additionally rejects the
    empty string (an entry that could never match a real role and almost
    always signals a malformed config), mirroring
    ``parse_role_name_allowlist``.
    """
    items = _list_of_strings(
        "SEC048", options.get("trusted_owner_roles", []), "role names"
    )
    for entry in items:
        if not entry:
            raise TypeError(
                "[lint.rules.SEC048].trusted_owner_roles entry "
                f"{entry!r} is not a valid role name. Expected a "
                "non-empty role name (e.g. 'app_owner')."
            )
    return set(items)


class SEC048:
    id: str = "SEC048"
    severity: Severity = "warning"
    title: str = (
        "Low-trust role can reach an RLS table's owner that is not FORCE'd"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_role_name_allowlist("SEC048", options)
        trusted_owners = _parse_trusted_owner_roles(options)
        out: list[Violation] = []
        # Surface an example exposed table once for the message: the first
        # owned, enabled-not-forced table per owner. Built lazily only if a
        # finding survives the allowlists. The introspection closure already
        # guarantees each `via_owner` owns at least one such table.
        example_by_owner = _example_tables_by_owner(schema)
        for member in schema.owner_reachable_members:
            if member.member in allowlist:
                continue
            # Drop owners the operator marked trusted; if every reachable
            # owner is trusted, the member has no untrusted route → no finding.
            owners = tuple(
                o for o in member.via_owners if o not in trusted_owners
            )
            if not owners:
                continue
            via = ", ".join(repr(o) for o in owners)
            example = next(
                (
                    example_by_owner[o]
                    for o in owners
                    if o in example_by_owner
                ),
                None,
            )
            example_note = (
                f" (for example {example})" if example is not None else ""
            )
            login_note = (
                "It is a LOGIN role, so an application authenticating as it "
                "bypasses RLS directly. "
                if member.member_can_login
                else "It is a NOLOGIN role, reached only by something that "
                "can already become it, but the bypass route still exists. "
            )
            out.append(
                Violation(
                    rule_id="SEC048",
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Role {member.member!r} is a member of role(s) "
                        f"{via} that OWN an RLS-enabled table without FORCE "
                        f"ROW LEVEL SECURITY{example_note}, so it inherits "
                        "the owner's RLS bypass (with INHERIT automatically; "
                        "with NOINHERIT after a SET ROLE) and reads every "
                        "row regardless of policy. The table owner bypasses "
                        "RLS until the table is FORCE'd, and that bypass is "
                        "reachable through membership even though the owner "
                        "holds no BYPASSRLS attribute (SEC016/SEC029 do not "
                        f"flag it). {login_note}Run ALTER TABLE … FORCE ROW "
                        "LEVEL SECURITY on the owner's tables, revoke the "
                        f"membership, or allowlist {member.member!r} in "
                        "[lint.rules.SEC048] (or the owner via "
                        "trusted_owner_roles) if the membership is "
                        "intentional and the role is trusted to bypass."
                    ),
                    location=member.member,
                )
            )
        return out


def _example_tables_by_owner(schema: Schema) -> dict[str, str]:
    """Map each owner → an example enabled-not-forced table it owns.

    Used only to enrich the message ("for example public.orders"). Tables
    are iterated in `Schema.tables` order (introspection sorts by schema
    then name), so the example is deterministic. Owners with no such table
    in scope are absent — the message then omits the example clause rather
    than naming a forced or non-RLS table.
    """
    out: dict[str, str] = {}
    for t in schema.tables:
        if not t.rls_enabled or t.force_rls or not t.owner:
            continue
        out.setdefault(t.owner, t.qualified_name)
    return out
