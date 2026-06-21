"""SEC044 fixer — REVOKE a default-privilege grant of future-table row access.

SEC044 flags ``ALTER DEFAULT PRIVILEGES … GRANT <row-access> ON TABLES TO
<low-trust>`` — a standing ``pg_default_acl`` rule that auto-grants every
*future* table to a low-trust grantee (PUBLIC by default). The remedy is the
matching REVOKE, which strictly **narrows** (it removes a future-facing grant
and never widens access) and — because default privileges are not retroactive —
does not even change any *existing* table's access:

    ALTER DEFAULT PRIVILEGES [FOR ROLE <grantor>] [IN SCHEMA <s>]
        REVOKE <row-access privs> ON TABLES FROM <grantee>;

Only the row-access privileges SEC044 flags (SELECT / INSERT / UPDATE / DELETE)
are revoked; a co-granted REFERENCES / TRIGGER / TRUNCATE default is left alone
(the rule never flagged it, and revoking it could remove access the operator
wants). The ``FOR ROLE <grantor>`` clause is load-bearing: ``pg_default_acl`` is
keyed on the grantor, so a bare REVOKE clears only the *running* role's own
default and silently no-ops against another role's — the fixer always emits it
when the grantor is known (it is ``None`` only for a hand-built model or a
pre-v18 snapshot, where the clause is omitted and the REVOKE must be run as the
grantor).

The fixer fires on exactly what the rule reports — it reuses the rule's
``_parse_grantees`` / ``_ROW_ACCESS_PRIVILEGES`` / ``_location`` and the same
allowlist parse, so the fixed set is the flagged set (parity-guaranteed).

Like every fixer this is dry-run by default — review before ``--apply``. The
REVOKE re-emits no policy clause (``clauses`` is empty), so the clause-clobber
resolver leaves it untouched; it targets a ``pg_default_acl`` standing rule —
not a table or policy — so it shares no location with any other fixer and needs
no entry in ``_DROP_FIXER_IDS``.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident
from pgrls.model import DefaultPrivilege, Schema
from pgrls.rules._allowlist import _list_of_strings
from pgrls.rules.sec044 import (
    _ROW_ACCESS_PRIVILEGES,
    _location,
    _parse_grantees,
)


def _grantee_sql(grantee: str) -> str:
    """Render a grantee for the REVOKE target list. ``PUBLIC`` is the SQL
    keyword (never quoted); a real role name is identifier-quoted."""
    return "PUBLIC" if grantee == "PUBLIC" else quote_ident(grantee)


class SEC044Fixer:
    rule_id: str = "SEC044"

    def fix(self, schema: Schema, options: dict[str, Any]) -> list[Fix]:
        grantees = _parse_grantees(options)
        # Same allowlist shape the rule validates (schema names / the
        # `(cluster-wide)` sentinel); a malformed allowlist raises, surfaced by
        # the `fix` CLI.
        allowlist = set(
            _list_of_strings(
                "SEC044", options.get("allowlist", []), "schema names"
            )
        )
        out: list[Fix] = []
        # Mirror the rule's dedupe: one fix per (schema, grantee, grantor) — the
        # grantor is part of the pg_default_acl identity, and each distinct entry
        # needs its own `FOR ROLE` REVOKE. Key on the raw `schema` (str | None),
        # never the rendered location, so a cluster-wide entry never aliases a
        # same-named real schema.
        seen: set[tuple[str | None, str, str | None]] = set()
        for entry in schema.default_privileges:
            if entry.grantee not in grantees:
                continue
            row_privs = [
                p
                for p in entry.privileges
                if p.upper() in _ROW_ACCESS_PRIVILEGES
            ]
            if not row_privs:
                continue
            location = _location(entry)
            if location in allowlist:
                continue
            key = (entry.schema, entry.grantee, entry.grantor)
            if key in seen:
                continue
            seen.add(key)
            out.append(self._fix(entry, location, row_privs))
        return out

    @staticmethod
    def _fix(
        entry: DefaultPrivilege, location: str, row_privs: list[str]
    ) -> Fix:
        privs = ", ".join(p.upper() for p in row_privs)
        # `FOR ROLE <grantor>` must precede `IN SCHEMA` (Postgres grammar).
        for_role = (
            f"FOR ROLE {quote_ident(entry.grantor)} "
            if entry.grantor is not None
            else ""
        )
        in_schema = (
            f"IN SCHEMA {quote_ident(entry.schema)} "
            if entry.schema is not None
            else ""
        )
        scope = (
            f"in schema {entry.schema}"
            if entry.schema is not None
            else "cluster-wide"
        )
        grantor_note = (
            ""
            if entry.grantor is not None
            else " Run this as the role that created the default (its grantor "
            "is unknown to pgrls, so the FOR ROLE clause is omitted)."
        )
        return Fix(
            rule_id="SEC044",
            location=location,
            sql=(
                f"ALTER DEFAULT PRIVILEGES {for_role}{in_schema}"
                f"REVOKE {privs} ON TABLES FROM {_grantee_sql(entry.grantee)};"
            ),
            description=(
                f"Revoke the default-privilege grant of {privs} on future "
                f"tables to {entry.grantee} ({scope}) — it auto-exposes every "
                f"future table to {entry.grantee} the moment it is created. "
                "Default privileges are not retroactive, so this removes only "
                "the standing future-facing grant and changes no existing "
                f"table. Scope default privileges to specific roles and rely "
                f"on RLS instead.{grantor_note}"
            ),
        )
