"""Extension auto-detect for `pgrls diff --apply migration.sql` (Phase 3).

When a migration starts with ``CREATE EXTENSION pgcrypto;`` (or any
other extension), the ephemeral Postgres testcontainer needs the
extension already installed before applying the rest of the
migration — otherwise ``CREATE EXTENSION`` itself would succeed
but a subsequent column type using ``pgcrypto.gen_random_uuid()``
might fail mid-migration.

The simplest and most reliable signal is the migration's own
``CREATE EXTENSION`` statements. We parse the SQL with pglast,
walk for ``CreateExtensionStmt`` nodes, and pre-create each named
extension via ``CREATE EXTENSION IF NOT EXISTS`` before the
baseline DDL. The user can supplement detection with one or more
``--extension`` flags for cases where the migration assumes an
extension is already present (e.g. baseline used ``citext`` but
the migration only references citext columns, never declares
the extension).

Out of scope (v0.5.x): inferring extensions from column types
(e.g. seeing ``citext`` columns and inferring extension ``citext``
must be installed). That requires a type-name → extension lookup
table that's brittle (extensions can rename types, ship multiple
types, etc.) — explicit ``--extension`` is more honest about
the trade-off.
"""
from __future__ import annotations

import pglast


def detect_extensions(migration_sql: str) -> list[str]:
    """Parse `migration_sql` and return the deduplicated, sorted list
    of extension names referenced via ``CREATE EXTENSION`` statements.

    Returns an empty list if the migration has no extensions or
    fails to parse — the caller is expected to surface a clean
    parse error from `psycopg.execute(migration_sql)` later if the
    SQL is genuinely broken; this helper degrades gracefully so a
    typo in the migration doesn't crash with a pglast traceback
    before the user sees Postgres's own error message.
    """
    try:
        parsed = pglast.parse_sql(migration_sql)
    except Exception:
        # Migration may have psql backslash commands or SQL
        # constructs pglast doesn't model — that's fine, return
        # empty and let psycopg surface the real error if any.
        return []

    seen: set[str] = set()
    for stmt in parsed:
        node = stmt.stmt
        if isinstance(node, pglast.ast.CreateExtensionStmt):
            name = node.extname
            if name:
                seen.add(name)
    return sorted(seen)
