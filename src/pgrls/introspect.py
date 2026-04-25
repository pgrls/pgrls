"""Read RLS-relevant state from `pg_catalog` into a normalized Schema."""
from __future__ import annotations

from collections import defaultdict
from typing import cast

import psycopg
from psycopg.rows import dict_row

from pgrls.model import Policy, Schema, Table

_POLICY_CMD_MAP: dict[str, str] = {
    "*": "ALL",
    "r": "SELECT",
    "a": "INSERT",
    "w": "UPDATE",
    "d": "DELETE",
}


_SCHEMA_EXISTS_SQL = """
SELECT nspname
FROM pg_catalog.pg_namespace
WHERE nspname = ANY(%s)
"""

_TABLES_SQL = """
SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    c.relrowsecurity AS rls_enabled,
    c.relforcerowsecurity AS force_rls,
    c.oid AS table_oid
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname = ANY(%s)
ORDER BY n.nspname, c.relname
"""

_POLICIES_SQL = """
SELECT
    p.polrelid AS table_oid,
    p.polname AS policy_name,
    p.polcmd AS cmd,
    p.polpermissive AS permissive,
    COALESCE(
        (
            SELECT array_agg(
                CASE WHEN ro.oid = 0 THEN 'PUBLIC' ELSE r.rolname END
                ORDER BY CASE WHEN ro.oid = 0 THEN 0 ELSE 1 END, r.rolname
            )
            FROM (SELECT unnest(p.polroles) AS oid) ro
            LEFT JOIN pg_catalog.pg_roles r ON r.oid = ro.oid
        ),
        ARRAY[]::TEXT[]
    ) AS roles,
    pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS using_sql,
    pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) AS with_check_sql
FROM pg_catalog.pg_policy p
WHERE p.polrelid = ANY(%s)
ORDER BY p.polrelid, p.polname
"""


def introspect(conn: psycopg.Connection, schemas: list[str]) -> Schema:
    """Build a Schema from `pg_catalog` for the given schema list.

    Raises ValueError if any requested schema does not exist on the connection.
    """
    if not schemas:
        return Schema(tables=())

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(_SCHEMA_EXISTS_SQL, (schemas,))
        existing = {row["nspname"] for row in cur.fetchall()}
        missing = [s for s in schemas if s not in existing]
        if missing:
            raise ValueError(
                f"Schemas not found in database: {', '.join(missing)}"
            )

        cur.execute(_TABLES_SQL, (schemas,))
        table_rows = cur.fetchall()
        if not table_rows:
            return Schema(tables=())

        oids = [row["table_oid"] for row in table_rows]
        cur.execute(_POLICIES_SQL, (oids,))
        policy_rows = cur.fetchall()

    by_oid: dict[int, list[Policy]] = defaultdict(list)
    for row in policy_rows:
        cmd_letter = cast(str, row["cmd"])
        command = _POLICY_CMD_MAP.get(cmd_letter)
        if command is None:
            raise RuntimeError(
                f"Unknown pg_policy.polcmd value {cmd_letter!r} for "
                f"policy {row['policy_name']!r}"
            )
        by_oid[row["table_oid"]].append(
            Policy(
                name=row["policy_name"],
                command=command,  # type: ignore[arg-type]
                permissive=row["permissive"],
                roles=tuple(row["roles"]),
                using_sql=row["using_sql"],
                with_check_sql=row["with_check_sql"],
            )
        )

    tables = [
        Table(
            schema=row["schema_name"],
            name=row["table_name"],
            rls_enabled=row["rls_enabled"],
            force_rls=row["force_rls"],
            policies=tuple(by_oid.get(row["table_oid"], [])),
        )
        for row in table_rows
    ]

    return Schema(tables=tuple(tables))
