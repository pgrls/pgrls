"""Shared allowlist parsers for rule options.

Allowlist entries fall into six shapes:

* **Policy ID** (`schema.table.policy_name`) — used by every per-policy
  rule (SEC003, SEC005, SEC006, SEC008, SEC010, SEC011, PERF001,
  PERF002, HYG002). Exactly two `.` separators and three non-empty
  parts.

* **Table reference** (`name` OR `schema.name`) — used by table-scoped
  rules that allow either form (SEC001, SEC002, SEC009, SEC012, SEC022).

* **Qualified table ID** (`schema.table` only) — used by rules whose
  scope is the qualified table object specifically (SEC007).

* **Qualified view ID** (`schema.view` only) — used by view-scoped
  rules (VIEW001-VIEW004).

* **Qualified function ID** (`schema.function` only) — used by
  function-scoped rules (SEC014, SEC015, SEC017).

* **Role name** (bare `name` only) — used by role-scoped rules
  (SEC016). Postgres roles are cluster-global and have no schema
  component, so the entry is an unqualified role name.

Earlier versions had every rule do the bare list-of-strings check
(`isinstance(raw, list) and all(isinstance(s, str))`) and accepted any
shape silently. A user copy-pasting an unqualified `users` into
`[lint.rules.SEC003].allowlist` got no error and no exemption — the
mismatch was invisible. Centralizing the shape validation here closes
that footgun for every per-policy rule.

The `pgrls fix` fixers reuse these same parsers, so a malformed
allowlist fails `pgrls fix` with the same clear error it raises for
`pgrls lint` — neither command silently treats bad config as
"nothing exempt".
"""
from __future__ import annotations

from typing import Any


def _list_of_strings(rule_id: str, raw: Any, shape_hint: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            f"[lint.rules.{rule_id}].allowlist must be a list of "
            f"strings ({shape_hint})"
        )
    # Surface accidental leading/trailing whitespace early. Postgres
    # allows whitespace inside quoted identifiers, but in pgrls.toml
    # an entry like `" public.users.evil "` is almost always a typo
    # (copy-paste from a wider list, trailing newline, etc.). The
    # silent-fail-open behavior — entry never matches any built
    # location, rule fires forever — is exactly the footgun the
    # validators here exist to close. Raise loudly with the stripped
    # form in the message so the fix is one keystroke.
    for entry in raw:
        if entry != entry.strip():
            raise TypeError(
                f"[lint.rules.{rule_id}].allowlist entry {entry!r} "
                "has leading or trailing whitespace. pgrls compares "
                "entries with byte-exact equality against built "
                "location strings, which never carry surrounding "
                "whitespace — the entry would silently fail to match. "
                f"Use {entry.strip()!r} instead."
            )
    return raw


def parse_policy_id_allowlist(
    rule_id: str, options: dict[str, Any]
) -> set[str]:
    """Validate that every entry is `schema.table.policy_name`.

    Raises TypeError on the first malformed entry with the rule_id
    and the offending value in the message — a typo'd entry no
    longer silently fails to match.

    Splits right-to-left: `schema.table.weird.name` resolves as
    `schema=schema, table=table, policy="weird.name"`. Schema and
    table names cannot contain `.` from `pg_catalog` introspection
    (`pg_namespace.nspname` and `pg_class.relname` reject `.` at
    CREATE time), so the rightmost two `.`-separators are
    unambiguous. Policy names CAN contain `.` (rare but legal —
    Postgres allows `"weird.name"`); right-anchoring lets a user
    allowlist them. Without this, the only way to silence such a
    finding was to disable the rule globally.
    """
    raw = options.get("allowlist", [])
    items = _list_of_strings(
        rule_id,
        raw,
        "of the form 'schema.table.policy_name'",
    )
    for entry in items:
        parts = entry.rsplit(".", 2)
        if len(parts) != 3 or not all(parts):
            raise TypeError(
                f"[lint.rules.{rule_id}].allowlist entry {entry!r} is "
                f"not a valid policy ID. Expected "
                f"'schema.table.policy_name' (e.g. "
                f"'public.users.tenant_isolation')."
            )
    return set(items)


def parse_table_ref_allowlist(
    rule_id: str, options: dict[str, Any]
) -> set[str]:
    """Validate that every entry is `name` or `schema.name`.

    Used by rules that accept both unqualified and qualified table
    references (SEC001, SEC002, SEC009, SEC012, SEC022). Schema and table names
    cannot contain `.` from `pg_catalog`, so a literal `split('.')`
    is unambiguous here.
    """
    raw = options.get("allowlist", [])
    items = _list_of_strings(
        rule_id,
        raw,
        "table names (unqualified or 'schema.table')",
    )
    for entry in items:
        parts = entry.split(".")
        if not (1 <= len(parts) <= 2) or not all(parts):
            raise TypeError(
                f"[lint.rules.{rule_id}].allowlist entry {entry!r} is "
                f"not a valid table reference. Expected an "
                f"unqualified table name (e.g. 'users') or "
                f"'schema.table' (e.g. 'public.users')."
            )
    return set(items)


def parse_qualified_table_allowlist(
    rule_id: str, options: dict[str, Any]
) -> set[str]:
    """Validate that every entry is `schema.table` (exactly two parts).

    Used by SEC007 (and any future rule whose scope is the qualified
    table object specifically).
    """
    raw = options.get("allowlist", [])
    items = _list_of_strings(
        rule_id,
        raw,
        "of the form 'schema.table'",
    )
    for entry in items:
        parts = entry.split(".")
        if len(parts) != 2 or not all(parts):
            raise TypeError(
                f"[lint.rules.{rule_id}].allowlist entry {entry!r} is "
                f"not a valid qualified table ID. Expected "
                f"'schema.table' (e.g. 'public.users')."
            )
    return set(items)


def parse_qualified_view_allowlist(
    rule_id: str, options: dict[str, Any]
) -> set[str]:
    """Validate that every entry is `schema.view` (exactly two parts).

    Used by VIEW001-VIEW004 — the rule scope is the qualified view
    object, and an exempt entry is meaningless without a schema
    qualifier (two views with the same name in different schemas
    would otherwise both be silenced by a bare-name allowlist).
    """
    raw = options.get("allowlist", [])
    items = _list_of_strings(
        rule_id,
        raw,
        "of the form 'schema.view'",
    )
    for entry in items:
        parts = entry.split(".")
        if len(parts) != 2 or not all(parts):
            raise TypeError(
                f"[lint.rules.{rule_id}].allowlist entry {entry!r} is "
                f"not a valid qualified view ID. Expected "
                f"'schema.view' (e.g. 'public.user_summary')."
            )
    return set(items)


def parse_qualified_function_allowlist(
    rule_id: str, options: dict[str, Any]
) -> set[str]:
    """Validate that every entry is `schema.function` (exactly two parts).

    Used by SEC014, SEC015, and SEC017 — the rule scope is the
    qualified function object.
    Argument signatures are deliberately not part of the shape: an
    overloaded function (same `schema.function` qname, different
    arg types) is flagged once and allowlisted once; introspection
    captures `pg_proc.proname` without signature.

    Bare function name is rejected for the same reason
    `parse_qualified_view_allowlist` rejects bare view names — two
    same-named functions in different schemas would otherwise both
    be silenced by a name-only entry.
    """
    raw = options.get("allowlist", [])
    items = _list_of_strings(
        rule_id,
        raw,
        "of the form 'schema.function'",
    )
    for entry in items:
        parts = entry.split(".")
        if len(parts) != 2 or not all(parts):
            raise TypeError(
                f"[lint.rules.{rule_id}].allowlist entry {entry!r} is "
                f"not a valid qualified function ID. Expected "
                f"'schema.function' (e.g. 'public.refresh_cache')."
            )
    return set(items)


def parse_role_name_allowlist(
    rule_id: str, options: dict[str, Any]
) -> set[str]:
    """Validate that every entry is a non-empty role name.

    Used by SEC016. Postgres roles are cluster-global and
    unqualified — there is no schema component — so an allowlist
    entry is a bare role name, matched byte-exactly against
    ``pg_roles.rolname``.

    Unlike the schema-qualified shapes, a role name is not split on
    ``.``: Postgres permits a literal dot inside a quoted role name
    (``CREATE ROLE "my.role"``), and with no schema component there
    is nothing to disambiguate. Beyond the shared list-of-strings
    and surrounding-whitespace checks in ``_list_of_strings``, the
    only shape this validator additionally rejects is the empty
    string — an entry that could never match a real role and almost
    always signals a malformed config (a stray comma, a blank line
    copy-pasted into the list).
    """
    raw = options.get("allowlist", [])
    items = _list_of_strings(rule_id, raw, "role names")
    for entry in items:
        if not entry:
            raise TypeError(
                f"[lint.rules.{rule_id}].allowlist entry {entry!r} is "
                f"not a valid role name. Expected a non-empty role "
                f"name (e.g. 'replication_worker')."
            )
    return set(items)
