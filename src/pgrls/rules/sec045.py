"""SEC045 — a sensitive/PII column is column-GRANTed to a low-trust role.

A **column-level** grant — ``GRANT SELECT (ssn) ON users TO anon`` — exposes
exactly one column to the grantee, independent of the table's general access.
Unlike a table grant (the broad ``GRANT SELECT ON users``), a column grant is a
deliberate, targeted act: nobody column-grants by accident. When the grantee is
a **low-trust** role (``PUBLIC`` / ``anon``) and the column holds sensitive data
— ``email``, ``ssn``, ``phone``, ``date_of_birth``, ``credit_card``,
``password``, ``api_key`` … — that targeted grant is almost always an
over-share: the most sensitive field in the table has been handed to the role
with the least trust.

```sql
-- the whole table is owner-scoped by RLS, but someone exposed one column:
GRANT SELECT (email, ssn) ON public.users TO anon;   -- SEC045
```

**Why a distinct rule (not SEC003 / SEC001 / SEC004).** SEC003 flags a
*policy* that lists ``PUBLIC``; SEC001 flags a table with RLS *off*; SEC004 /
SEC038 prove an *anonymous-readable policy*. None of them inspect column-level
``GRANT``s (``pg_attribute.attacl`` → ``Table.column_grants``), and none weigh
the *sensitivity of the exposed column*. SEC045 is the column-grant +
PII-sensitivity finding the others miss — the same "least-privilege posture"
family as SEC044 (default privileges) and SEC042 (anon-EXECUTE SECDEF).

**Posture, like SEC044.** SEC045 fires on the *grant itself*, regardless of
whether RLS further gates which rows the grantee can reach: a column grant to a
low-trust role is a standing over-share worth review even when a row policy
currently blocks every row (policies change; the grant outlives them). It is a
``warning`` (defense-in-depth), not an ``error``.

**False-positive controls.** Only **column** grants are inspected (table grants
are SEC003/SEC001's domain), and column grants are rare and intentional, so the
finding is high-signal. Only **content** privileges count — ``SELECT`` /
``INSERT`` / ``UPDATE`` (a column-level ``REFERENCES`` exposes no content). The
default low-trust grantee set is ``{PUBLIC, anon}`` (a column grant to ``anon``
is *not* a standard Supabase pattern, unlike SEC044's default-privilege case —
Supabase scopes via table grants + RLS, never column grants — so ``anon`` is
included by default here). The PII match is a curated, case-insensitive set
matched on **token boundaries** (the column name split on non-alphanumerics),
so a pattern matches a whole name segment — ``phone`` hits ``phone_number`` but
not ``headphone``, ``secret`` hits ``mfa_secret`` but not ``secretary``. Extend
it with ``patterns`` and silence a deliberate exposure by its
``schema.table.column`` id in ``allowlist``:

```toml
[lint.rules.SEC045]
grantees = ["PUBLIC", "anon", "authenticated"]   # widen the low-trust set
patterns = ["mrn", "policy_number"]               # extra PII tokens (added to defaults)
allowlist = ["public.profiles.email"]             # a deliberate public-email column
```

Severity: warning. No auto-fix — whether to ``REVOKE`` the column or keep it
(an intentional public field) is a product decision pgrls cannot make safely;
the remediation is ``REVOKE <priv> (<column>) ON <table> FROM <role>``.

Scope / known limits (intentional):

* **Column grants only.** A PII column exposed via a *table* grant to PUBLIC on
  a no-RLS table is SEC003/SEC001's case; SEC045 does not duplicate it.
* **Literal grantee match.** The grantee is matched literally against the
  low-trust set (mirrors SEC003/SEC039/SEC042/SEC044): a column granted to a
  *group* role a low-trust role merely belongs to is not expanded.
* **Name heuristic.** Sensitivity is inferred from the column *name*; a
  sensitively-typed column with an opaque name is not detected. Token-boundary
  matching avoids unrelated-word collisions, but a benign column that shares a
  whole token with a pattern (e.g. ``email_verified`` → token ``email``) still
  matches — allowlist it. The curated default set favors precision.
* Snapshots predating column-grant capture carry no ``column_grants``; SEC045
  abstains on them (fail-closed) until re-captured.
"""
from __future__ import annotations

import re
from typing import Any

from pgrls.model import Schema
from pgrls.violations import Severity, Violation

# Split a column name into alphanumeric tokens (snake_case, digits, any
# non-alphanumeric separator). Used for token-boundary PII matching so a
# pattern matches a whole name segment, not an incidental substring.
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

# Content privileges grantable at column granularity (DELETE/TRUNCATE are not
# column-grantable). A column-level REFERENCES exposes no row content, so it is
# not an over-share of the data — excluded, mirroring the row-access concept in
# SEC041/SEC042/SEC044.
_CONTENT_PRIVILEGES: frozenset[str] = frozenset({"SELECT", "INSERT", "UPDATE"})

# Default low-trust grantee set. PUBLIC is every role; anon is the
# unauthenticated PostgREST/Supabase role. Both are included by default — unlike
# SEC044, a *column* grant to anon is not a standard Supabase pattern. Widen
# (e.g. to add "authenticated") via [lint.rules.SEC045].grantees.
_DEFAULT_GRANTEES = ("PUBLIC", "anon")

# Curated, high-precision PII / secret column-name substrings (case-insensitive).
# Favors precision over recall: specific tokens (ssn, credit_card, api_key)
# rather than broad ones (no bare "address"/"token"/"name") to keep the
# name-heuristic quiet. Extend per-project via [lint.rules.SEC045].patterns.
_DEFAULT_PATTERNS: frozenset[str] = frozenset(
    {
        "email",
        "ssn",
        "social_security",
        "phone",
        "date_of_birth",
        "birth_date",
        "birthdate",
        "dob",
        "credit_card",
        "card_number",
        "cardnumber",
        "cvv",
        "bank_account",
        "account_number",
        "iban",
        "routing_number",
        "salary",
        "compensation",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "tax_id",
        "passport",
        "national_id",
        "drivers_license",
        "license_number",
        "mfa_secret",
        "totp_secret",
    }
)


def _parse_grantees(options: dict[str, Any]) -> set[str]:
    raw = options.get("grantees")
    if raw is None:
        return set(_DEFAULT_GRANTEES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC045].grantees must be a list of role-name "
            "strings (e.g. ['PUBLIC', 'anon'])."
        )
    # Normalize the public pseudo-role so "public"/"Public" still matches the
    # stored "PUBLIC" form (mirrors SEC042/SEC044).
    return {"PUBLIC" if s.lower() == "public" else s for s in raw}


def _parse_patterns(options: dict[str, Any]) -> frozenset[str]:
    raw = options.get("patterns")
    if raw is None:
        return _DEFAULT_PATTERNS
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC045].patterns must be a list of substring "
            "strings (e.g. ['mrn', 'policy_number'])."
        )
    # Additive: project patterns extend the curated defaults, lowercased.
    return _DEFAULT_PATTERNS | {s.lower() for s in raw if s.strip()}


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    raw = options.get("allowlist")
    if raw is None:
        return set()
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC045].allowlist must be a list of "
            "'schema.table.column' id strings."
        )
    return set(raw)


def _is_pii(column_name: str, patterns: frozenset[str]) -> bool:
    """Match a column name against the PII pattern set on TOKEN boundaries.

    The name is split into alphanumeric tokens and re-joined with ``_`` into a
    ``_<tokens>_`` form; a pattern matches iff ``_<pattern>_`` is a substring.
    So ``phone`` matches ``phone_number`` / ``user_phone`` but NOT
    ``headphone`` / ``saxophone``; ``secret`` matches ``mfa_secret`` but not
    ``secretary``; multi-word patterns (``credit_card``, ``date_of_birth``)
    match a run of consecutive tokens but not an incidental substring
    (``tax_id`` matches ``applicant_tax_id`` but not ``syntax_idea``). This is
    what keeps the curated substring set from firing on unrelated words.
    """
    tokens = [t for t in _TOKEN_SPLIT.split(column_name.lower()) if t]
    norm = "_" + "_".join(tokens) + "_"
    return any(f"_{p}_" in norm for p in patterns)


class SEC045:
    id: str = "SEC045"
    severity: Severity = "warning"
    title: str = "Sensitive column granted to a low-trust role"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        grantees = _parse_grantees(options)
        patterns = _parse_patterns(options)
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for cgrant in table.column_grants:
                if cgrant.role not in grantees:
                    continue
                if not _is_pii(cgrant.column, patterns):
                    continue
                exposed = sorted(
                    p for p in cgrant.privileges if p in _CONTENT_PRIVILEGES
                )
                if not exposed:
                    continue
                location = f"{table.qualified_name}.{cgrant.column}"
                if location in allowlist:
                    continue
                priv_list = ", ".join(exposed)
                out.append(
                    Violation(
                        rule_id="SEC045",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Column {cgrant.column!r} on "
                            f"{table.qualified_name} looks sensitive (PII / "
                            f"secret) and is GRANTed {priv_list} to the "
                            f"low-trust role {cgrant.role!r}. A column-level "
                            "grant to PUBLIC/anon exposes that field to the "
                            "least-trusted role; confirm it is meant to be "
                            f"public, or REVOKE {priv_list} ({cgrant.column}) "
                            f"ON {table.qualified_name} FROM {cgrant.role}. "
                            "Allowlist a deliberate public column by its "
                            "schema.table.column id."
                        ),
                        location=location,
                    )
                )
        return out
