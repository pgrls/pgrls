"""SEC049 — PostgREST-exposed table readable by a low-trust role.

In a PostgREST / Supabase deployment, *table grant + schema exposure = HTTP
endpoint*: a table in an API-exposed schema (PostgREST's default is ``public``),
granted a row-reading privilege to a low-trust role (``anon`` / ``authenticated``
/ ``PUBLIC``), is reachable at ``GET /rest/v1/<table>``. RLS is then the only
thing between that request and the rows — so a table that is exposed, granted,
**and** has no effective row filter is directly readable by an unauthenticated
(or any-authenticated) caller.

"No effective row filter" means one of:

* **RLS is disabled** — every granted row is returned (policies, if any, are
  dormant while RLS is off; that dormancy is SEC032's domain).
* **RLS is enabled but unrestricted for the granted role** — a *permissive*
  ``SELECT`` / ``ALL`` policy **that applies to the granted low-trust role**
  (it lists the role, or is ``TO PUBLIC``) and whose ``USING`` is the literal
  ``true`` admits every row, and no *restrictive* policy applying to that role
  constrains them. The determination is per grantee: a ``USING (true)`` policy
  scoped ``TO`` some *other* role (the common ``TO service_role`` backend
  bypass) leaves the granted role at default-deny and is **not** treated as
  exposing it. (A restrictive policy with anything other than a provably-
  ``true`` ``USING`` is assumed to filter rows, so the table is treated as
  protected and **not** flagged — soundness over recall.)

```sql
CREATE TABLE public.invoices (id bigint, tenant_id bigint, amount numeric);
GRANT SELECT ON public.invoices TO anon;        -- exposed + granted …
-- … and no RLS:  GET /rest/v1/invoices  returns every tenant's invoices.
```

This is the single most common Supabase data-exposure incident, and pgrls
already has the ingredients separately — SEC001 flags RLS being off, SEC003 a
``PUBLIC`` policy, SEC008 a permissive ``USING (true)``, SEC044 a default-ACL
grant. SEC049 is the *conjunction*: it fires once, naming the actual
HTTP-reachable consequence ("readable at ``GET /rest/v1/<table>``"), where those
rules each report a precondition in isolation. It deliberately co-fires with
those error-level findings (it is a ``warning`` — the connecting consequence,
not a new precondition).

Severity: warning. Configurable via ``[lint.rules.SEC049]``:

* ``schemas`` — the PostgREST-exposed schema list (default ``["public"]``; set
  it to match ``PGRST_DB_SCHEMAS`` when the API exposes more than ``public``).
* ``grantees`` — the low-trust role set (default ``["anon", "authenticated",
  "PUBLIC"]``; ``"public"`` is normalised to the ``PUBLIC`` pseudo-role).
* ``allowlist`` — table ids (unqualified ``table`` or ``schema.table``) that are
  intentionally public (e.g. a reference table of countries), exempted from the
  rule.

Scope / known limits (intentional):

* **Transitive group grants are not expanded** — a grant to a *group* role that
  a low-trust role merely belongs to is not flagged, mirroring SEC003 / SEC044.
  Grant to the low-trust role directly (or list the group in ``grantees``).
  By the same token a bare ``GRANT … TO PUBLIC`` is evaluated as the ``PUBLIC``
  grantee against ``TO PUBLIC`` policies; the rarer combination of a
  ``PUBLIC`` grant with a ``USING (true)`` policy scoped only to a concrete
  low-trust role is a conservative miss.
* **Schema exposure is assumed, not verified.** pgrls does not read
  ``PGRST_DB_SCHEMAS`` or check the role's ``USAGE`` on the schema; the
  ``schemas`` option is the user's declaration of the API surface.
* Pure rule logic over already-captured data (grants + RLS state + policies) —
  no introspection or snapshot change.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_true
from pgrls.model import Policy, Schema, Table
from pgrls.rules._allowlist import (
    _list_of_strings,
    parse_table_ref_allowlist,
    table_in_allowlist,
)
from pgrls.violations import Severity, Violation

# PostgREST exposes a configured set of schemas; its default is `public`.
_DEFAULT_EXPOSED_SCHEMAS = ("public",)

# The low-trust grantees whose SELECT access means "reachable over the API":
# the unauthenticated `anon` role, the any-logged-in `authenticated` role, and
# the `PUBLIC` pseudo-role (everyone). All three are exposure surfaces; the
# conjunction with "no effective row filter" keeps this from firing on the
# normal RLS-gated Supabase pattern (grant to anon/authenticated + a real
# policy → not flagged).
_DEFAULT_GRANTEES = ("anon", "authenticated", "PUBLIC")

# A policy applies to SELECT-time row visibility when its command is SELECT or
# ALL (ALL covers every command, SELECT included).
_SELECT_COMMANDS: frozenset[str] = frozenset({"SELECT", "ALL"})


def _parse_exposed_schemas(options: dict[str, Any]) -> set[str]:
    raw = options.get("schemas")
    if raw is None:
        return set(_DEFAULT_EXPOSED_SCHEMAS)
    return set(
        _list_of_strings("SEC049", raw, "schema names", option="schemas")
    )


def _parse_grantees(options: dict[str, Any]) -> set[str]:
    raw = options.get("grantees")
    if raw is None:
        return set(_DEFAULT_GRANTEES)
    # Validate via the shared helper (rejects non-strings and stray whitespace
    # that would silently never match an introspected role name), then
    # normalize the public pseudo-role to the stored "PUBLIC" form — mirrors
    # SEC044.
    items = _list_of_strings("SEC049", raw, "role names", option="grantees")
    return {"PUBLIC" if s.lower() == "public" else s for s in items}


def _select_grantees(table: Table, grantees: set[str]) -> set[str]:
    """Roles in `grantees` that hold SELECT on `table` — table- or column-level.

    A column-level ``GRANT SELECT (col)`` still exposes those columns over the
    REST API, so it counts as a read grant.
    """
    out: set[str] = set()
    for g in table.grants:
        if g.role in grantees and "SELECT" in g.privileges:
            out.add(g.role)
    for cg in table.column_grants:
        if cg.role in grantees and "SELECT" in cg.privileges:
            out.add(cg.role)
    return out


def _policy_applies_to(policy: Policy, role: str) -> bool:
    """Does `policy` apply to a session running as `role`?

    Postgres applies a policy only when the current role is in the policy's
    ``TO`` list, or the policy is ``TO PUBLIC`` (which covers every role).
    ``Policy.roles`` stores the sentinel ``"PUBLIC"`` for a ``TO PUBLIC`` (or
    no-``TO``) policy.
    """
    return "PUBLIC" in policy.roles or role in policy.roles


def _unrestricted_for(table: Table, role: str) -> bool:
    """Does the table's SELECT row-access admit *every* row to `role`?

    A permissive ``USING (true)`` policy only admits rows to the roles it
    applies to, so the determination is **per grantee**: a ``USING (true)``
    policy scoped to some *other* role (the common ``TO service_role`` backend
    bypass) leaves `role` at default-deny and must not be read as "unrestricted".

    * RLS off → yes (every granted row is returned; policies are dormant).
    * RLS on → only when a permissive SELECT/ALL policy that **applies to
      `role`** is literal-``true`` AND no restrictive SELECT/ALL policy applying
      to `role` could filter rows. A restrictive policy whose ``USING`` is not
      provably ``true`` (a real predicate, or one that didn't parse) is assumed
      to constrain rows, so the table is treated as protected — the
      conservative, soundness-over-recall direction.
    """
    if not table.rls_enabled:
        return True
    applicable = [
        p
        for p in table.policies
        if p.command in _SELECT_COMMANDS and _policy_applies_to(p, role)
    ]
    permissive_admits_all = any(
        p.permissive and is_literal_true(p.using_ast) for p in applicable
    )
    if not permissive_admits_all:
        return False
    restrictive_filters = any(
        (not p.permissive) and not is_literal_true(p.using_ast)
        for p in applicable
    )
    return not restrictive_filters


class SEC049:
    id: str = "SEC049"
    severity: Severity = "warning"
    title: str = "PostgREST-exposed table readable by a low-trust role"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        exposed = _parse_exposed_schemas(options)
        grantees = _parse_grantees(options)
        allowlist = parse_table_ref_allowlist("SEC049", options)
        out: list[Violation] = []
        for table in schema.tables:
            if table.schema not in exposed:
                continue
            if table_in_allowlist(table, allowlist):
                continue
            granted = _select_grantees(table, grantees)
            # A granted role is only exposed if it can actually read every row:
            # its SELECT grant must meet a policy set that is unrestricted *for
            # that role* (a USING(true) policy scoped to some other role does
            # not expose it).
            exposed_roles = sorted(
                g for g in granted if _unrestricted_for(table, g)
            )
            if exposed_roles:
                out.append(self._violation(table, exposed_roles))
        return out

    def _violation(self, table: Table, roles: list[str]) -> Violation:
        reason = (
            "RLS is disabled"
            if not table.rls_enabled
            else "RLS is enabled but only a permissive USING (true) policy, "
            "which admits every row"
        )
        grant_list = ", ".join(roles)
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Table {table.qualified_name} is in the PostgREST-exposed "
                f"schema {table.schema}, grants SELECT to {grant_list}, and "
                f"has no effective row filter ({reason}) — it is directly "
                f"readable at GET /rest/v1/{table.name} by an unauthenticated "
                "or any-authenticated request. Enable RLS with a row-scoping "
                "policy (or restrict/REVOKE the grant); if the table is "
                f"intentionally public, allowlist {table.qualified_name!r} in "
                "[lint.rules.SEC049]. (SEC001/SEC003/SEC008 each flag a "
                "precondition of this in isolation; SEC049 is the conjunction.)"
            ),
            location=table.qualified_name,
        )
