"""SEC047 — FOREIGN KEY to an RLS parent is a cross-tenant existence oracle.

A foreign key is validated by Postgres as a **system integrity check**: when a
row is written to the child (referencing) table, the existence of the matching
parent row is probed with row-level security *suspended* — the check runs with
the privileges of the integrity machinery, not as the invoking role. So when
the **parent** table has RLS enabled and a **low-trust role can write the
child**, that role learns whether a *guessed* parent key exists by simply
trying to reference it:

* referencing an existing parent row → the write **succeeds**, and
* referencing a non-existent one → a **foreign-key-violation error**,

*even though RLS hides that parent row from the role's own ``SELECT``*. The
caller cannot read the other tenant's row, but it can enumerate which parent
keys exist across the isolation boundary — a cross-tenant **existence covert
channel** (verified live on PG16, via both ``INSERT`` and ``UPDATE`` of the
child).

This completes SEC035's arc. SEC035 is the **UNIQUE-index** existence oracle —
inserting a value already taken by an invisible tenant raises a duplicate-key
error, leaking existence on the *same* table. SEC047 is the **FK-validation**
existence oracle — the same mechanism (an integrity check that bypasses RLS
leaks cross-tenant existence), on a *different* catalog object and *across*
tables (child → parent). ``UNIQUE`` leaks existence on the table you write;
the foreign key leaks existence on the table you *reference*.

```sql
-- parent has RLS; anon sees only its own tenant's rows
ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON public.accounts FOR SELECT TO anon USING (tenant_id = ...);

-- child references it, and anon can INSERT the child
CREATE TABLE public.events (id bigint PRIMARY KEY,
                            account_id bigint REFERENCES public.accounts(id));
GRANT INSERT ON public.events TO anon;

-- anon, probing a parent key it cannot SELECT:
INSERT INTO public.events VALUES (1, 5000);  -- SUCCESS  → account 5000 exists
INSERT INTO public.events VALUES (2, 5001);  -- FK ERROR → account 5001 does not
```

Detection — the narrow core (the false-positive boundary is the whole point)
----------------------------------------------------------------------------

Foreign keys to RLS-protected parents are *ubiquitous* in a multi-tenant
schema; flagging every one of them would bury the signal. SEC047 fires only
when **all** of:

1. the FK's **parent** (referenced) table, resolved in the snapshot, has
   ``rls_enabled`` (plain ENABLE — ``FORCE`` is *not* required; plain ENABLE
   already scopes a non-owner low-trust role, live-confirmed), **and**
2. the **child** table is **writable by a configured low-trust role**
   (default ``{"anon", "PUBLIC"}``), determined entirely from the snapshot as:

   * the child has a *table-level* ``GRANT`` of ``INSERT`` / ``UPDATE`` /
     ``ALL`` to that role (or ``PUBLIC``), **and**
   * the child either has ``rls_enabled == False`` (no RLS gates the write at
     all) **or** has a *permissive* ``INSERT`` / ``UPDATE`` / ``ALL`` policy
     whose ``roles`` literally include that low-trust role (the SEC003
     literal-role idiom — no group/membership expansion, no ``WITH CHECK``
     satisfiability proof), **and**

3. the FK is not allowlisted.

**Deliberate posture over-approximation (unsound by design, like SEC044 /
SEC045).** SEC047 does **not** try to prove the low-trust role's RLS visibility
on the *parent* is narrower than all rows. That proof is unsound: a role that
holds plain table ``SELECT`` on the parent still has its reads RLS-scoped, so
it can still distinguish "exists in another tenant" from "does not exist" via
the FK even though it cannot ``SELECT`` that row (live-proven — the role sees
only its own tenant's ids yet the FK check admits a reference to a hidden
existing id). Attempting to narrow the rule by the role's parent-visibility
would therefore *miss* real oracles. So SEC047 fires on the *structural*
condition (RLS parent + low-trust-writable child) and accepts that some
findings are on FKs the operator considers acceptable — allowlist those.

**Fail-closed on an unresolvable parent.** If the parent table cannot be
resolved in the snapshot — typically because it lives in a schema outside
``--schemas`` — SEC047 cannot read its ``rls_enabled`` and **abstains** for
that FK (the same out-of-scope blind spot the other schema-scoped rules
document). A pre-v20 snapshot carries no ``foreign_keys`` at all, so SEC047
finds nothing to flag until it is re-captured.

Configuration
-------------

```toml
[lint.rules.SEC047]
# Roles whose child-write access makes the FK an oracle. Default
# ["anon", "PUBLIC"]; "public" (any case) normalizes to the PUBLIC pseudo-role.
low_trust_roles = ["anon", "PUBLIC"]
# Allowlist a deliberate FK by the child table (`schema.table`) — silences all
# its FKs — or by a specific FK constraint name. (FK constraint names are unique
# per table, not globally, so a bare name silences that name on EVERY child;
# prefer the `schema.table` form when a name is shared across tables.)
allowlist = ["public.events", "events_account_id_fkey"]
```

Severity: **warning** — a covert *existence* leak (metadata, not row contents),
the same posture class as SEC035 and the other "RLS can be bypassed via X"
rules. **No auto-fix:** the remedies (drop the FK, move the parent behind a
SECURITY DEFINER existence-check function, or accept the leak) are design
decisions pgrls cannot make safely.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import ForeignKey, Schema, Table
from pgrls.rules._allowlist import _list_of_strings
from pgrls.violations import Severity, Violation

# A child write that can probe the FK: INSERT or UPDATE supplies the
# referencing value the integrity check validates. ALL covers both. A
# SELECT/DELETE/REFERENCES/TRIGGER grant never writes a referencing value, so
# it cannot drive the oracle.
_WRITE_PRIVILEGES: frozenset[str] = frozenset({"INSERT", "UPDATE", "ALL"})

# Policy commands whose WITH CHECK gates a referencing write: a permissive
# INSERT / UPDATE / ALL policy admitting the low-trust role lets that role
# write the child even under RLS. SELECT/DELETE policies don't gate a
# referencing write.
_WRITE_POLICY_COMMANDS: frozenset[str] = frozenset({"INSERT", "UPDATE", "ALL"})

# Default low-trust set: the named `anon` role (the PostgREST/Supabase
# unauthenticated role) and the PUBLIC pseudo-role (every role, incl. anon).
_DEFAULT_LOW_TRUST_ROLES = ("anon", "PUBLIC")


def _parse_low_trust_roles(options: dict[str, Any]) -> set[str]:
    raw = options.get("low_trust_roles")
    if raw is None:
        return set(_DEFAULT_LOW_TRUST_ROLES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC047].low_trust_roles must be a list of role-name "
            'strings (e.g. ["anon", "PUBLIC"]).'
        )
    # Normalize the public pseudo-role to the stored "PUBLIC" form so a config
    # entry of "public"/"Public" still matches (real roles are case-sensitive,
    # but PUBLIC is a reserved keyword, never a real role) — mirrors SEC044.
    return {"PUBLIC" if s.lower() == "public" else s for s in raw}


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    # Two accepted shapes, matched by membership in `check`: a child table
    # reference (`schema.table`, silences all of that table's FKs) or a bare
    # FK constraint name. Both are bare strings, so reuse the shared
    # list-of-strings shape validator (rejects non-list / non-str /
    # surrounding-whitespace) rather than the dotted-shape parsers.
    return set(
        _list_of_strings(
            "SEC047",
            options.get("allowlist", []),
            "child 'schema.table' references or FK constraint names",
        )
    )


def _child_writable_by(table: Table, low_trust_roles: set[str]) -> str | None:
    """Return a low-trust role that can WRITE `table`, or None.

    The child is low-trust-writable when a low-trust role holds an INSERT /
    UPDATE / ALL *table* grant AND the write is not blocked by RLS — i.e. the
    child has RLS off, or a permissive INSERT/UPDATE/ALL policy literally
    listing that role. Returns the first such role (for the message); None if
    no low-trust role can write the child.
    """
    # Roles holding a table-level write grant on the child. A grant to PUBLIC
    # subsumes every role, so it covers any low-trust role too.
    grant_roles = {
        g.role
        for g in table.grants
        if any(p.upper() in _WRITE_PRIVILEGES for p in g.privileges)
    }
    public_granted = "PUBLIC" in grant_roles
    granted_writers = {
        r for r in low_trust_roles if r in grant_roles or public_granted
    }
    if not granted_writers:
        return None

    # RLS off → any granted write lands unconditionally.
    if not table.rls_enabled:
        return sorted(granted_writers)[0]

    # RLS on → the write must also be admitted by a permissive write-side
    # policy. A policy naming PUBLIC (including a `CREATE POLICY … WITH CHECK`
    # with no `TO` clause, which Postgres stores as PUBLIC) admits every role,
    # so it covers any low-trust writer; otherwise the policy must literally
    # name the role (no group/membership expansion, no WITH CHECK satisfiability
    # proof — over-approximate toward firing).
    policy_roles = {
        role
        for policy in table.policies
        if policy.permissive and policy.command in _WRITE_POLICY_COMMANDS
        for role in policy.roles
    }
    public_policy = "PUBLIC" in policy_roles
    eligible = {
        r for r in granted_writers if r in policy_roles or public_policy
    }
    return sorted(eligible)[0] if eligible else None


class SEC047:
    id: str = "SEC047"
    severity: Severity = "warning"
    title: str = (
        "Foreign key to an RLS-protected parent is a cross-tenant "
        "existence oracle"
    )

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        low_trust_roles = _parse_low_trust_roles(options)
        allowlist = _parse_allowlist(options)
        by_qname = {t.qualified_name: t for t in schema.tables}
        out: list[Violation] = []
        for child in schema.tables:
            if not child.foreign_keys:
                continue
            if child.qualified_name in allowlist or child.name in allowlist:
                continue
            writer = _child_writable_by(child, low_trust_roles)
            if writer is None:
                continue  # child not low-trust-writable → no oracle handle
            for fk in child.foreign_keys:
                if fk.name in allowlist:
                    continue
                parent_qname = f"{fk.ref_schema}.{fk.ref_table}"
                parent = by_qname.get(parent_qname)
                if parent is None:
                    # Parent outside --schemas → cannot read its rls_enabled.
                    # Abstain (fail-closed) rather than guess.
                    continue
                if not parent.rls_enabled:
                    continue
                out.append(self._violation(child, fk, parent_qname, writer))
        return out

    def _violation(
        self, child: Table, fk: ForeignKey, parent_qname: str, writer: str
    ) -> Violation:
        child_cols = ", ".join(fk.columns)
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Foreign key {fk.name!r} on {child.qualified_name} "
                f"({child_cols}) references {parent_qname}, which has RLS "
                f"enabled, and {writer!r} can write {child.qualified_name}. "
                "Foreign-key validation runs as a system integrity check that "
                "bypasses RLS, so a low-trust caller can probe whether a "
                f"guessed {parent_qname} row exists — the write succeeds when "
                "it does and raises a foreign-key-violation error when it "
                "does not — even though RLS hides that row from the caller's "
                "own SELECT. That is a cross-tenant existence oracle (the "
                "FK-validation analog of SEC035's UNIQUE-index oracle). Drop "
                "the foreign key, mediate parent existence through a SECURITY "
                "DEFINER function that enforces the tenant scope, or allowlist "
                f"{child.qualified_name!r} (or {fk.name!r}) in "
                "[lint.rules.SEC047] if the leak is acceptable."
            ),
            location=f"{child.qualified_name} ({fk.name})",
        )
