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

A `user_metadata` key nested under the service-role-only `app_metadata`
root is deliberately NOT flagged — the end user cannot write inside
`app_metadata`, so the value is trustworthy:

    USING (auth.jwt() -> 'app_metadata' -> 'user_metadata' ->> 'role' …)
    USING ((auth.jwt() #>> '{app_metadata,user_metadata,role}') = 'admin')

Detection is root-aware: the arrow form inspects the left-operand chain
and the path form inspects element order, so only a `user_metadata` read
that roots at the top-level JWT claim (not under `app_metadata` /
`raw_app_meta_data`) fires.

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

from pglast.ast import A_Const, A_Expr, Node, String, TypeCast

from pgrls.ast_utils import extract_column_refs
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_DEFAULT_STRING_KEYS: frozenset[str] = frozenset({"user_metadata"})

_DEFAULT_COLUMN_NAMES: frozenset[str] = frozenset({"raw_user_meta_data"})

# Server-controlled metadata roots. In the Supabase / PostgREST model the
# service role (never the end user) writes `app_metadata` /
# `raw_app_meta_data`, so a `user_metadata` key read *nested under* one of
# these lives inside the service-role object and is NOT the self-bypass
# hazard. SEC033 exempts those reads (see `_unrooted_user_key`).
_SAFE_ROOT_KEYS: frozenset[str] = frozenset(
    {"app_metadata", "raw_app_meta_data"}
)
_SAFE_ROOT_COLUMNS: frozenset[str] = frozenset({"raw_app_meta_data"})


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


_JSON_EXTRACT_OPS: frozenset[str] = frozenset({"->", "->>", "#>", "#>>"})


def _expr_op_name(node: A_Expr) -> str | None:
    """The bare operator name of an `A_Expr` (last element of `name`)."""
    parts = [f.sval for f in (node.name or ()) if isinstance(f, String)]
    return parts[-1] if parts else None


def _extract_key_sval(rexpr: Any) -> str | None:
    """The string value of a JSON arrow/path key operand, or None.

    `pg_get_expr` (introspection) renders a string literal as
    `'user_metadata'::text` — a TypeCast around the A_Const — so unwrap
    any casts to reach the constant. (Source SQL parses to a bare
    A_Const; this handles both forms.)
    """
    node = rexpr
    while isinstance(node, TypeCast):
        node = node.arg
    if isinstance(node, A_Const) and isinstance(node.val, String):
        sval = node.val.sval
        return sval if isinstance(sval, str) else None
    return None


def _key_operand_matches(rexpr: Any, keys: frozenset[str] | set[str]) -> bool:
    """True if the key operand of a JSON arrow/path operator names a
    configured key — exact for `->`/`->>`, array-element membership for
    the `#>`/`#>>` `{a,b}` path literal.
    """
    sval = _extract_key_sval(rexpr)
    if sval is None:
        return False
    if sval in keys:
        return True
    return any(elem in keys for elem in _array_literal_keys(sval))


def _has_key_in_extract_position(
    node: Any, keys: frozenset[str] | set[str]
) -> bool:
    """True if any of `keys` appears as the KEY operand of a JSON
    extraction operator (`->` / `->>` / `#>` / `#>>`) anywhere in `node`.

    Root-blind primitive: used to test whether a left (root-ward) operand
    chain already selects a server-controlled key such as `app_metadata`.
    """
    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, A_Expr) and _expr_op_name(n) in _JSON_EXTRACT_OPS:
            if _key_operand_matches(n.rexpr, keys):
                found = True
                return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(node)
    return found


def _unrooted_user_key(node: A_Expr, keys: set[str]) -> bool:
    """For a single JSON extraction `A_Expr`, True if it reads a configured
    user-writable key as a TOP-LEVEL claim — i.e. NOT nested under a
    server-controlled root such as `app_metadata`.

      ``auth.jwt() -> 'user_metadata' ->> 'role'``           → True  (hazard)
      ``auth.jwt() -> 'app_metadata' -> 'user_metadata' …``  → False (safe)
      ``… #>> '{user_metadata,role}'``                       → True  (hazard)
      ``… #>> '{app_metadata,user_metadata,role}'``          → False (safe)

    Both forms also consult the LEFT operand chain: a `user_metadata` read
    whose left side already selects `app_metadata` (or the
    `raw_app_meta_data` column) lives inside the service-role object and
    isn't user-writable. For the path-literal form the element ORDER within
    the `{…}` literal ALSO decides the root — a user-writable key is
    hazardous only if no server-controlled key precedes it AND the left
    operand doesn't already root in a server-controlled source:

      ``auth.jwt() -> 'user_metadata' ->> 'role'``           → True  (hazard)
      ``auth.jwt() -> 'app_metadata' -> 'user_metadata' …``  → False (safe)
      ``… #>> '{user_metadata,role}'``                       → True  (hazard)
      ``… #>> '{app_metadata,user_metadata,role}'``          → False (safe)
      ``raw_app_meta_data #>> '{user_metadata,role}'``       → False (safe)
      ``(jwt -> 'app_metadata') #>> '{user_metadata,role}'`` → False (safe)
    """
    sval = _extract_key_sval(node.rexpr)
    if sval is None:
        return False

    path = _array_literal_keys(sval)
    if path:
        # The left operand chain is root-ward of every path element, so a
        # server-controlled root on the left makes the whole read safe —
        # `raw_app_meta_data #>> '{user_metadata,…}'` or
        # `(jwt -> 'app_metadata') #>> '{user_metadata,…}'`. (A user_metadata
        # ROOT in the left chain is caught by the arrow node for it, so this
        # never hides a genuine hazard.) Otherwise the intra-literal order
        # decides: a user key is hazardous unless a safe-root key precedes
        # it within the same literal.
        if _is_server_controlled_root(node.lexpr):
            return False
        for i, elem in enumerate(path):
            if elem in keys and not any(
                e in _SAFE_ROOT_KEYS for e in path[:i]
            ):
                return True
        return False

    if sval in keys:
        return not _is_server_controlled_root(node.lexpr)
    return False


def _string_key_via_json_op(node: Any, keys: set[str]) -> bool:
    """True if a configured user-writable key is read as a TOP-LEVEL JWT
    claim — in JSON key-operand position and NOT rooted under a
    server-controlled key such as `app_metadata`.

    Scoped deliberately to unrooted key-operand reads. A data-value
    comparison like `event_type = 'user_metadata'`, a JSON *value* equal to
    a key name (`… ->> 'role' = 'user_metadata'`), and a `user_metadata`
    sub-object nested inside the service-role-only `app_metadata` all
    fail to select the end-user-writable claim, so none fire.
    """
    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, A_Expr) and _expr_op_name(n) in _JSON_EXTRACT_OPS:
            if _unrooted_user_key(n, keys):
                found = True
                return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(node)
    return found


def _references_column(
    node: Any, column_names: frozenset[str] | set[str]
) -> bool:
    """True if the tree references a column whose last name matches.

    Captures bare `raw_user_meta_data`, table-qualified
    `auth.users.raw_user_meta_data`, and any depth of qualification.
    """
    for ref in extract_column_refs(node):
        if ref and ref[-1].lower() in column_names:
            return True
    return False


def _is_server_controlled_root(lexpr: Any) -> bool:
    """True if a JSON extraction's left (root-ward) operand selects a
    server-controlled metadata root: the `app_metadata` JSON key or the
    `raw_app_meta_data` column. A `user_metadata` key read layered on top
    of such a root is part of the service-role object, not the
    end-user-writable claim.
    """
    return _has_key_in_extract_position(
        lexpr, _SAFE_ROOT_KEYS
    ) or _references_column(lexpr, _SAFE_ROOT_COLUMNS)


def _column_via_json_op(node: Any, column_names: set[str]) -> bool:
    """True if a configured metadata column is the SOURCE (left operand)
    of a JSON extraction operator — `raw_user_meta_data ->> 'role'`.

    A bare reference (e.g. `raw_user_meta_data IS NOT NULL`, or the
    column selected for an unrelated reason) is not the self-bypass
    hazard and must not fire.
    """
    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, A_Expr) and _expr_op_name(n) in _JSON_EXTRACT_OPS:
            if _references_column(n.lexpr, column_names):
                found = True
                return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(node)
    return found


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
                    _string_key_via_json_op(t, string_keys) for t in trees
                )
                hit_column = any(
                    _column_via_json_op(t, column_names) for t in trees
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
