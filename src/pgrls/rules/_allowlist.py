"""Shared allowlist parsers for rule options.

Allowlist entries fall into three shapes:

* **Policy ID** (`schema.table.policy_name`) — used by every per-policy
  rule (SEC003, SEC005, SEC006, SEC008, SEC010, SEC011, PERF001,
  PERF002, HYG002). Exactly two `.` separators and three non-empty
  parts.

* **Table reference** (`name` OR `schema.name`) — used by table-scoped
  rules that allow either form (SEC001, SEC002, SEC009).

* **Qualified table ID** (`schema.table` only) — used by rules whose
  scope is the qualified table object specifically (SEC007).

Until Round 21, every rule did the bare list-of-strings check
(`isinstance(raw, list) and all(isinstance(s, str))`) and accepted any
shape silently. A user copy-pasting an unqualified `users` into
`[lint.rules.SEC003].allowlist` got no error and no exemption — the
mismatch was invisible. Centralizing the shape validation here closes
that footgun for every per-policy rule.
"""
from __future__ import annotations

from typing import Any


def _list_of_strings(rule_id: str, raw: Any, shape_hint: str) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            f"[lint.rules.{rule_id}].allowlist must be a list of "
            f"strings ({shape_hint})"
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
    references (SEC001, SEC002, SEC009). Schema and table names
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
