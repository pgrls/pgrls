"""SEC044 — default privileges grant future tables to a low-trust role.

``ALTER DEFAULT PRIVILEGES [IN SCHEMA s] [FOR ROLE r] GRANT <priv> ON TABLES
TO PUBLIC`` does not touch any existing table — it records a standing rule in
``pg_default_acl`` that **every table created after it** (in scope) is
automatically granted ``<priv>``. When that grantee is ``PUBLIC`` and the
privilege is a row-access one (``SELECT``/``INSERT``/``UPDATE``/``DELETE``),
the default becomes a defense-in-depth footgun: a developer who later adds a
table and forgets ``ENABLE ROW LEVEL SECURITY`` has silently exposed it to
every role — including ``anon`` in a PostgREST/Supabase deployment — without
writing a single ``GRANT``.

```sql
-- a standing config decision, made once:
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC;

-- weeks later, a new table — RLS forgotten:
CREATE TABLE public.invoices (tenant_id int, amount numeric, ...);
-- no GRANT here, yet:
SELECT * FROM public.invoices;   -- readable by anon via the PUBLIC default
```

This is verified Postgres behaviour, not a theory: the new table's ``relacl``
carries ``=r/owner`` (PUBLIC SELECT) the moment it is created, and a low-trust
role reads it through the PUBLIC grant. Default privileges are **not
retroactive** — they affect only future tables — so SEC044 fires on the
``pg_default_acl`` entry itself, regardless of whether any table has been
created under it yet. It is the *standing posture* that is unsafe.

**Why ``PUBLIC`` only by default — and why ``anon`` / ``authenticated`` are
excluded.** ``PUBLIC`` is the genuine footgun: it is every role, including
ones that do not exist yet, broader than any single application role. Granting
future tables to the named ``anon`` / ``authenticated`` roles, by contrast, is
the **deliberate, RLS-gated Supabase pattern** — Supabase ships default
privileges to those roles precisely so PostgREST can see new tables, and RLS
(not the grant) is what scopes access. Flagging that would fire on essentially
every Supabase project, so the default low-trust set is ``{"PUBLIC"}`` only.
Widen it with ``[lint.rules.SEC044].grantees`` (e.g. ``["PUBLIC", "anon"]``)
where a project genuinely wants ``anon`` defaults flagged; a config entry of
``"public"`` is normalized case-insensitively to the ``PUBLIC`` pseudo-role,
mirroring SEC042's ``anon_roles``.

**Relationship to SEC003 and SEC001.** SEC003 flags a *policy* that lists
``PUBLIC`` and SEC001 flags an *existing* table with RLS off — both are
after-the-fact findings on a table that already exists. SEC044 is the
*standing config* finding that makes the SEC001 case **happen by default**:
the PUBLIC grant is already in place before the table is created, so the only
thing standing between a new table and exposure is the author remembering
RLS. SEC044 catches the posture so the per-table mistake never lands;
remediate by scoping default privileges to specific roles and relying on RLS:

```sql
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM PUBLIC;
```

Allowlist a deliberate default by its schema name (or ``(cluster-wide)`` for a
cluster-wide entry) in ``[lint.rules.SEC044]``:

```toml
[lint.rules.SEC044]
allowlist = ["reporting"]
```

Severity: warning — a least-privilege / defense-in-depth posture, like the
other "RLS can be bypassed via X" rules; the exposure only lands if a future
table also forgets RLS. No auto-fix: whether to REVOKE the default or keep it
(scoping to a role) is a deployment decision pgrls cannot make safely.

Scope / known limits (intentional):

* **Only TABLES defaults are inspected** (``pg_default_acl.defaclobjtype =
  'r'``). Default privileges on sequences / functions / types / schemas are a
  different surface and out of scope for an RLS linter.
* **Transitive group grants are not expanded.** The grantee is matched
  literally against the configured low-trust set, mirroring SEC003 / SEC039 /
  SEC042: a default granted to a *group* role that a low-trust role merely
  belongs to is not flagged. Grant to the low-trust role directly (or list the
  group in ``grantees``) to surface it.
* **Schema-scoped entries outside ``--schemas`` are invisible**, the same
  out-of-scope blind spot the other schema-scoped rules document; cluster-wide
  defaults are always captured because they affect every schema.
* Snapshots predating v18 carry no ``default_privileges``; SEC044 abstains on
  them (fail-closed) until re-captured.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import DefaultPrivilege, Schema
from pgrls.rules._allowlist import _list_of_strings
from pgrls.violations import Severity, Violation

# RLS governs only these commands, so a default grant of one of them to a
# low-trust role is what silently exposes a future table: a SELECT default
# leaks its rows, and INSERT/UPDATE/DELETE defaults let a low-trust role write
# rows no RLS policy would admit. A default of only REFERENCES / TRIGGER /
# TRUNCATE neither reads nor writes row contents, so it is not a row-exposure
# (same row-access concept SEC041/SEC042/SEC043 use).
_ROW_ACCESS_PRIVILEGES: frozenset[str] = frozenset(
    {"SELECT", "INSERT", "UPDATE", "DELETE"}
)

# Default low-trust grantee set: the PUBLIC pseudo-role only. `anon` /
# `authenticated` are deliberately excluded — granting future tables to those
# is the deliberate, RLS-gated Supabase pattern (flagging it would fire on
# every Supabase project). Widen via [lint.rules.SEC044].grantees.
_DEFAULT_GRANTEES = ("PUBLIC",)

# Display/allowlist location for a cluster-wide entry (ALTER DEFAULT PRIVILEGES
# with no IN SCHEMA, schema is None). This is a *rendering* choice for output
# and allowlist matching only — dedup keys on the raw `schema` (None vs str),
# never this string, so a cluster-wide entry and a real (if pathological) schema
# quoted into existence as "(cluster-wide)" stay distinct findings. (Postgres
# does accept CREATE SCHEMA "(cluster-wide)" via a quoted identifier; the
# sentinel is not relied on as an impossible name.) The only residual ambiguity
# is cosmetic: a user who allowlists the literal "(cluster-wide)" while such a
# schema exists would suppress both — an accepted edge for a name no real
# deployment uses.
_CLUSTER_WIDE_LOCATION = "(cluster-wide)"


def _parse_grantees(options: dict[str, Any]) -> set[str]:
    raw = options.get("grantees")
    if raw is None:
        return set(_DEFAULT_GRANTEES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC044].grantees must be a list of role-name "
            "strings (e.g. ['PUBLIC', 'anon'])."
        )
    # Normalize the public pseudo-role to the stored "PUBLIC" form so a config
    # entry of "public"/"Public" still matches (real roles are case-sensitive,
    # but PUBLIC is a reserved keyword, never a real role) — mirrors SEC042.
    return {"PUBLIC" if s.lower() == "public" else s for s in raw}


def _location(entry: DefaultPrivilege) -> str:
    """The Violation location for a default-privilege entry.

    A schema-scoped entry locates to its schema name (e.g. ``public``); a
    cluster-wide entry (``schema is None``) locates to the
    ``(cluster-wide)`` sentinel.
    """
    return entry.schema if entry.schema is not None else _CLUSTER_WIDE_LOCATION


class SEC044:
    id: str = "SEC044"
    severity: Severity = "warning"
    title: str = (
        "Default privileges grant future tables to a low-trust role"
    )

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        grantees = _parse_grantees(options)
        # Allowlist is a list of schema-name strings (or `(cluster-wide)`),
        # matched against the entry's location. No existing _allowlist helper
        # fits a bare schema name, so reuse the shared list-of-strings shape
        # validator (rejects non-list / non-str / surrounding-whitespace) the
        # same way sibling rules do, then match by location string.
        allowlist = set(
            _list_of_strings(
                "SEC044", options.get("allowlist", []), "schema names"
            )
        )
        out: list[Violation] = []
        # One finding per (schema, grantee): a single ALTER DEFAULT PRIVILEGES
        # produces one pg_default_acl row per (scope, grantee) already, and
        # introspection folds privileges into one DefaultPrivilege per pair,
        # but dedupe defensively so a hand-built Schema with two records for
        # the same pair still reports once. Key on the raw `schema` (str | None,
        # not the rendered location) so a cluster-wide entry never aliases a
        # real schema that happens to render to the same sentinel string.
        seen: set[tuple[str | None, str]] = set()
        for entry in schema.default_privileges:
            if entry.grantee not in grantees:
                continue
            if not any(
                p.upper() in _ROW_ACCESS_PRIVILEGES for p in entry.privileges
            ):
                # Only non-row-access privileges (REFERENCES/TRIGGER/TRUNCATE)
                # — granting those by default neither reads nor writes a future
                # table's rows, so it is not a row-exposure.
                continue
            location = _location(entry)
            if location in allowlist:
                continue
            key = (entry.schema, entry.grantee)
            if key in seen:
                continue
            seen.add(key)
            out.append(self._violation(entry, location))
        return out

    def _violation(
        self, entry: DefaultPrivilege, location: str
    ) -> Violation:
        privs = ", ".join(
            p for p in entry.privileges if p.upper() in _ROW_ACCESS_PRIVILEGES
        )
        scope = (
            f"in schema {entry.schema}"
            if entry.schema is not None
            else "cluster-wide (set without IN SCHEMA, so it applies in "
            "every schema)"
        )
        revoke_scope = (
            f"IN SCHEMA {entry.schema} "
            if entry.schema is not None
            else ""
        )
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Default privileges {scope} auto-grant {privs} on every "
                f"future table to {entry.grantee}, so any new table created "
                "without ENABLE ROW LEVEL SECURITY is immediately exposed to "
                f"{entry.grantee} — Postgres applies this grant the moment the "
                "table is created, with no per-table GRANT and nothing but the "
                "author remembering RLS standing in the way. Scope default "
                "privileges to specific roles and rely on RLS, and run "
                f"ALTER DEFAULT PRIVILEGES {revoke_scope}REVOKE {privs} ON "
                f"TABLES FROM {entry.grantee}; or allowlist {location!r} in "
                "[lint.rules.SEC044]. (Complements SEC003, which flags a "
                "PUBLIC policy, and SEC001, which flags an RLS-off table after "
                "the fact — SEC044 is the standing config posture that makes "
                "that exposure the default.)"
            ),
            location=location,
        )
