"""SEC033 — Policy scopes by user-modifiable JWT claim.

In the Supabase auth model (which PostgREST + GoTrue projects inherit),
the JWT's `raw_user_meta_data` / `user_metadata` object is **end-user
writable** via the standard auth API:

    supabase.auth.updateUser({ data: { role: "admin" } })

So any RLS policy that gates access on a value pulled out of
`user_metadata` can be bypassed by the authenticated user themselves —
they set the field, the next JWT carries it, the policy sees it. This
is a direct privilege-escalation footgun, not a theoretical one.

The safe counterpart is `app_metadata` / `raw_app_meta_data`, which is
modifiable only via the service role.

Detection: any reference inside a policy's USING / WITH CHECK
expression to either:

  1. A string constant equal to `user_metadata` (the JSON-key name
     used in arrow/path operators against `auth.jwt()`,
     `auth.users.raw_user_meta_data`, or the
     `request.jwt.claim.user_metadata` GUC), OR
  2. A column reference whose last name component is
     `raw_user_meta_data`.

Both patterns capture the realistic shapes:

    USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin')
    USING ((auth.jwt() #>> '{user_metadata,role}') = 'admin')
    USING (raw_user_meta_data ->> 'role' = 'admin')
    USING (current_setting('request.jwt.claim.user_metadata')...)

The string-const path catches the JSON-key form regardless of which
JSON operator was used; the column-ref path catches the direct
`raw_user_meta_data` column reference (typically via a SELECT
sub-link against `auth.users`).

The rule is `error` severity because the bypass is deterministic and
exploitable by any authenticated user — same hazard class as SEC004
(inverted auth check / anonymous access).

Configuration: `[lint.rules.SEC033]` accepts:

  - `string_keys` (list[str]) — JSON-key names to flag. Replaces the
    default `["user_metadata"]`. Add project-specific user-writable
    claim names here, e.g. `["user_metadata", "raw_user_meta_data"]`
    if your auth layer exposes both.
  - `column_names` (list[str]) — case-insensitive bare column names
    whose last-component reference flags. Replaces the default
    `["raw_user_meta_data"]`.
  - `allowlist` (list[str]) — `schema.table.policy` IDs to exempt
    (e.g. an audit-write policy that genuinely needs to read the
    user-supplied metadata for a side-effect, not for authorization).
"""
from __future__ import annotations

from typing import Any

from pglast.ast import A_Const, Node, String

from pgrls.ast_utils import extract_column_refs
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_DEFAULT_STRING_KEYS: frozenset[str] = frozenset({"user_metadata"})

_DEFAULT_COLUMN_NAMES: frozenset[str] = frozenset({"raw_user_meta_data"})


def _parse_string_keys(options: dict[str, Any]) -> set[str]:
    raw = options.get("string_keys")
    if raw is None:
        return set(_DEFAULT_STRING_KEYS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC033].string_keys must be a list of JSON-key "
            'strings, e.g. ["user_metadata", "raw_user_meta_data"]'
        )
    # String-const matching is case-SENSITIVE — Postgres JSON keys are
    # case-sensitive (unlike unquoted SQL identifiers). Don't lowercase.
    return set(raw)


def _parse_column_names(options: dict[str, Any]) -> set[str]:
    raw = options.get("column_names")
    if raw is None:
        return set(_DEFAULT_COLUMN_NAMES)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC033].column_names must be a list of bare "
            'column names, e.g. ["raw_user_meta_data"]'
        )
    # Column-name matching is case-insensitive — Postgres lowercases
    # unquoted identifiers (matches how extract_column_refs returns them).
    return {s.lower() for s in raw}


def _array_literal_keys(sval: str) -> list[str]:
    """Parse a Postgres text-array literal into its element names.

    pglast represents the `#> '{user_metadata,role}'` and
    `#>> '{user_metadata,role}'` path operators' RHS as a single
    `A_Const(String) sval='{user_metadata,role}'` — the `{…}` syntax
    is a Postgres array literal, NOT a JSON object. We need to crack
    it open to check whether any element is one of our keys.

    Returns `[]` for any string that doesn't look like an array
    literal (`{a,b,c}`); the caller treats that as "not a path-op
    target."
    """
    if len(sval) < 2 or sval[0] != "{" or sval[-1] != "}":
        return []
    inner = sval[1:-1]
    if not inner:
        return []
    # Array elements may be unquoted (`{a,b}`) or double-quoted
    # (`{"a","b with space"}`). Postgres allows either; the
    # user_metadata case is always unquoted. Strip surrounding
    # double quotes if present so `"user_metadata"` matches
    # `user_metadata`.
    return [
        elem.strip().strip('"')
        for elem in inner.split(",")
    ]


def _contains_string_const(node: Any, keys: set[str]) -> bool:
    """True if any A_Const(String) node in the tree matches one of `keys`.

    Two match shapes:
      1. Exact equality — `auth.jwt() -> 'user_metadata' ...` produces
         an `A_Const(String) sval='user_metadata'`.
      2. Array-element membership — `auth.jwt() #> '{user_metadata,...}'`
         produces a single `A_Const(String) sval='{user_metadata,...}'`
         (Postgres `text[]` literal syntax, NOT a JSON object). We
         crack the array open and check each element. The parser
         doesn't unescape backslash sequences like `{"a\\"b"}` — the
         realistic claim-key set doesn't contain quotes or backslashes,
         so the omission is harmless here.
    """

    def walk(n: Any) -> bool:
        if n is None:
            return False
        if isinstance(n, (list, tuple)):
            return any(walk(item) for item in n)
        if isinstance(n, A_Const):
            val = n.val
            if isinstance(val, String):
                if val.sval in keys:
                    return True
                # Array-literal form (path operators)
                for elem in _array_literal_keys(val.sval):
                    if elem in keys:
                        return True
            # A_Const wraps a single scalar (String/Integer/Float/etc.) —
            # nothing more to walk inside, return early so we don't
            # iterate the Node fields below pointlessly.
            return False
        if isinstance(n, Node):
            for field_name in n:
                if walk(getattr(n, field_name, None)):
                    return True
        return False

    return walk(node)


def _references_column(node: Any, column_names: set[str]) -> bool:
    """True if the tree references a column whose last name matches.

    Captures bare `raw_user_meta_data`, table-qualified
    `auth.users.raw_user_meta_data`, and any depth of qualification.
    """
    for ref in extract_column_refs(node):
        if ref and ref[-1].lower() in column_names:
            return True
    return False


class SEC033:
    id: str = "SEC033"
    severity: Severity = "error"
    title: str = "Policy scopes by user-modifiable JWT claim (user_metadata)"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        string_keys = _parse_string_keys(options)
        column_names = _parse_column_names(options)
        allowlist = parse_policy_id_allowlist("SEC033", options)

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                # Walk both USING and WITH CHECK — WITH CHECK governs
                # writes and is the more common privilege-escalation
                # surface ("am I allowed to insert a row claiming
                # role=admin?").
                trees = [
                    t
                    for t in (policy.using_ast, policy.with_check_ast)
                    if t is not None
                ]
                if not trees:
                    continue
                hit_string = any(
                    _contains_string_const(t, string_keys) for t in trees
                )
                hit_column = any(
                    _references_column(t, column_names) for t in trees
                )
                if not (hit_string or hit_column):
                    continue
                # Compose a finding message that names the specific
                # vector — operators reading the output can immediately
                # see whether to add the policy to `allowlist` (rare:
                # the metadata read is intentional and not load-bearing
                # for authorization) or rewrite to use `app_metadata`.
                vector_bits: list[str] = []
                if hit_string:
                    vector_bits.append(
                        "references a `user_metadata`-shaped JSON key"
                    )
                if hit_column:
                    vector_bits.append(
                        "references the `raw_user_meta_data` column"
                    )
                vectors = " and ".join(vector_bits)
                out.append(
                    Violation(
                        rule_id="SEC033",
                        severity="error",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} {vectors}. "
                            "In the Supabase / PostgREST auth model "
                            "`user_metadata` (a.k.a. "
                            "`raw_user_meta_data`) is end-user "
                            "writable via the auth API, so the "
                            "authenticated user can set any value the "
                            "policy reads, bypassing the check. Use "
                            "`app_metadata` / `raw_app_meta_data` "
                            "(service-role-only) instead, or "
                            "allowlist this policy in "
                            "[lint.rules.SEC033]."
                        ),
                        location=pid,
                    )
                )
        return out
