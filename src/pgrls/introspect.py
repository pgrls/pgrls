"""Read RLS-relevant state from `pg_catalog` into a normalized Schema."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, cast

import psycopg
from psycopg.rows import dict_row

from pgrls.ast_utils import parse_expr
from pgrls.model import Grant, Policy, Schema, Table, View

_POLICY_CMD_MAP: dict[str, str] = {
    "*": "ALL",
    "r": "SELECT",
    "a": "INSERT",
    "w": "UPDATE",
    "d": "DELETE",
}

# pg_catalog, information_schema, pg_toast and the per-session
# pg_temp_*/pg_toast_temp_* schemas are reserved by Postgres for
# system metadata, ephemeral state, or TOAST out-of-line storage.
# Linting them is never the user's intent: pg_catalog has thousands
# of system tables that swamp output and there is nothing the user
# can change about them. Treat as a hard error so a typo in `--
# schemas` surfaces clearly instead of producing an unreadable
# 10MB report.
_RESERVED_SCHEMAS: frozenset[str] = frozenset(
    ("pg_catalog", "information_schema", "pg_toast")
)


def _is_reserved_schema(name: str) -> bool:
    if name in _RESERVED_SCHEMAS:
        return True
    return name.startswith("pg_temp_") or name.startswith("pg_toast_temp_")


def _list_user_schemas(cur: Any) -> list[str]:
    """Return the user-managed schemas visible to the connection.

    Used to enrich the "Schemas not found" error message with what
    the user *could* have asked for. Filters reserved/system
    schemas using the same rules as `_is_reserved_schema`.
    """
    cur.execute(
        """
        SELECT nspname
        FROM pg_catalog.pg_namespace
        WHERE nspname NOT IN (
            'pg_catalog', 'information_schema', 'pg_toast'
        )
          AND nspname NOT LIKE 'pg_temp_%'
          AND nspname NOT LIKE 'pg_toast_temp_%'
        ORDER BY nspname
        """
    )
    return [row["nspname"] for row in cur.fetchall()]


def _missing_schema_message(missing: list[str], available: list[str]) -> str:
    """Compose a clear error message for missing schemas.

    Adds "Did you mean: X" for each missing entry that has a close
    match in `available` (difflib cutoff 0.7), and lists all
    user-managed schemas so the user can see what's actually
    there. Without these hints the user has to drop into psql and
    `\\dn` to debug a typo.
    """
    import difflib

    parts = [f"Schemas not found in database: {', '.join(missing)}."]
    for name in missing:
        suggestion = difflib.get_close_matches(
            name, available, n=1, cutoff=0.7
        )
        if suggestion:
            parts.append(f"Did you mean {suggestion[0]!r}?")
    if available:
        parts.append(f"Available user schemas: {', '.join(available)}.")
    return " ".join(parts)


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
WHERE c.relkind IN ('r', 'p')
  AND n.nspname = ANY(%s)
ORDER BY n.nspname, c.relname
"""

# Map declarative-partition children to their immediate parent. We filter
# on `c.relispartition` so classic `INHERITS` children (which also go
# through pg_inherits but are not declarative partitions) don't get a
# partition_of set.
_PARTITION_PARENTS_SQL = """
SELECT
    inh.inhrelid AS child_oid,
    pn.nspname AS parent_schema,
    pc.relname AS parent_name
FROM pg_catalog.pg_inherits inh
JOIN pg_catalog.pg_class cc ON cc.oid = inh.inhrelid
JOIN pg_catalog.pg_class pc ON pc.oid = inh.inhparent
JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
WHERE cc.relispartition = true
  AND inh.inhrelid = ANY(%s)
"""

# Role-name resolution layers three concerns into one subquery:
#   * `polroles` may contain duplicates — Postgres stores `TO r1, r1`
#     verbatim. DISTINCT collapses them so `Policy.roles` is a set in
#     tuple form, not a multiset.
#   * OID 0 is the special PUBLIC bucket; it has no row in `pg_authid`,
#     so the LEFT JOIN's `r.rolname` would be NULL there.
#   * For non-zero OIDs that DON'T resolve (e.g. running pgrls as an
#     unprivileged role that lacks SELECT on `pg_authid`, or a race
#     against `DROP ROLE`), `r.rolname` is also NULL. A NULL leaking
#     into `Policy.roles` violates the `tuple[str, ...]` annotation
#     and breaks downstream `sorted(p.roles)`. Substitute a stable
#     `oid:N` sentinel so the type contract holds and the operator
#     can still see what role was referenced.
_POLICIES_SQL = """
SELECT
    p.polrelid AS table_oid,
    p.polname AS policy_name,
    p.polcmd AS cmd,
    p.polpermissive AS permissive,
    COALESCE(
        (
            SELECT array_agg(rolname_resolved ORDER BY ord_key, rolname_resolved)
            FROM (
                SELECT DISTINCT
                    CASE WHEN ro.oid = 0 THEN 'PUBLIC'
                         ELSE COALESCE(r.rolname, 'oid:' || ro.oid::text)
                    END AS rolname_resolved,
                    CASE WHEN ro.oid = 0 THEN 0 ELSE 1 END AS ord_key
                FROM unnest(p.polroles) AS ro(oid)
                LEFT JOIN pg_catalog.pg_roles r ON r.oid = ro.oid
            ) sub
        ),
        ARRAY[]::TEXT[]
    ) AS roles,
    pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS using_sql,
    pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) AS with_check_sql
FROM pg_catalog.pg_policy p
WHERE p.polrelid = ANY(%s)
ORDER BY p.polrelid, p.polname
"""

_COLUMNS_SQL = """
SELECT
    a.attrelid AS table_oid,
    a.attname AS column_name
FROM pg_catalog.pg_attribute a
WHERE a.attrelid = ANY(%s)
  AND a.attnum > 0
  AND NOT a.attisdropped
ORDER BY a.attrelid, a.attnum
"""

# Per-table grants from `pg_class.relacl`. `aclexplode` expands
# the ACL array into one row per (grantor, grantee, privilege,
# is_grantable) tuple. The CASE on `ax.grantee = 0` resolves the
# special PUBLIC pseudo-role to the literal string "PUBLIC",
# mirroring the convention already used for `Policy.roles`.
#
# Role-name resolution mirrors the `polroles` handling above: a
# non-superuser pgrls run may not be able to SELECT from
# `pg_authid` (RLS, missing permissions, race against `DROP
# ROLE`), leaving `ar.rolname` NULL even when the grantee OID
# exists. A NULL leaking into `Grant.role` violates the `str`
# annotation and breaks downstream JSON serialization and
# `sorted()` calls. COALESCE to a stable `oid:N` sentinel so the
# type contract holds and the operator can still see what role
# was referenced.
#
# `c.relacl IS NOT NULL` short-circuits before the LATERAL: for
# tables with the default ACL (no explicit GRANT), `aclexplode`
# returns zero rows, but Postgres still evaluates the LATERAL
# per row. Filtering these out lets the planner skip the entire
# evaluation. Pure performance — same correctness as the
# original.
#
# Sort: role name first (alphabetical, with PUBLIC sorting
# before user roles per ASCII), then privilege type. Postgres's
# native privilege order is implementation-defined; sorting
# here so two introspections of the same DB produce byte-
# identical Schema (downstream snapshot determinism).
_GRANTS_SQL = """
SELECT
    c.oid AS table_oid,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
         ELSE COALESCE(ar.rolname, 'oid:' || ax.grantee::text)
    END AS role_name,
    ax.privilege_type
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN LATERAL aclexplode(c.relacl) ax ON true
LEFT JOIN pg_catalog.pg_authid ar ON ar.oid = ax.grantee
WHERE c.relkind IN ('r', 'p')
  AND n.nspname = ANY(%s)
  AND c.relacl IS NOT NULL
  AND ax.grantee IS NOT NULL
ORDER BY c.oid, role_name, ax.privilege_type
"""

_VIEWS_SQL = """
SELECT
    n.nspname AS schema_name,
    c.relname AS view_name,
    c.relkind = 'm' AS is_materialized,
    -- pg_class.reloptions is text[] like {security_invoker=on, security_barrier=on}.
    -- We accept both 'on' and 'true' since both are valid in PG syntax.
    COALESCE(
        (SELECT TRUE
         FROM unnest(c.reloptions) AS o(opt)
         WHERE o.opt = 'security_invoker=on' OR o.opt = 'security_invoker=true'),
        FALSE
    ) AS security_invoker,
    COALESCE(
        (SELECT TRUE
         FROM unnest(c.reloptions) AS o(opt)
         WHERE o.opt = 'security_barrier=on' OR o.opt = 'security_barrier=true'),
        FALSE
    ) AS security_barrier,
    pg_get_viewdef(c.oid, true) AS definition
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('v', 'm')
  AND n.nspname = ANY(%s)
ORDER BY n.nspname, c.relname
"""

_VIEW_DEPS_SQL = """
SELECT
    vn.nspname AS view_schema,
    v.relname AS view_name,
    tn.nspname AS ref_schema,
    t.relname AS ref_name
FROM pg_catalog.pg_rewrite r
JOIN pg_catalog.pg_class v ON v.oid = r.ev_class
JOIN pg_catalog.pg_namespace vn ON vn.oid = v.relnamespace
JOIN pg_catalog.pg_depend d
  ON d.objid = r.oid
 AND d.classid = 'pg_rewrite'::regclass
JOIN pg_catalog.pg_class t ON t.oid = d.refobjid
JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
WHERE v.relkind IN ('v', 'm')
  AND t.relkind IN ('r', 'p')   -- regular tables + partitioned tables
  AND vn.nspname = ANY(%s)
  AND v.oid != t.oid             -- exclude self-rule rows
ORDER BY vn.nspname, v.relname, tn.nspname, t.relname
"""


def introspect(conn: psycopg.Connection, schemas: list[str]) -> Schema:
    """Build a Schema from `pg_catalog` for the given schema list.

    Raises ValueError if any requested schema does not exist on the
    connection, or if any requested schema is a Postgres-reserved
    schema (`pg_catalog`, `information_schema`, `pg_toast`,
    `pg_temp_*`, `pg_toast_temp_*`).
    """
    if not schemas:
        return Schema(tables=(), views=())

    reserved = sorted({s for s in schemas if _is_reserved_schema(s)})
    if reserved:
        raise ValueError(
            f"Cannot lint Postgres-reserved schemas: "
            f"{', '.join(reserved)}. These hold system catalogs / "
            "ephemeral state and are not user-managed. Pass "
            "user-defined schemas only — typically 'public', or "
            "your application's tenant schemas."
        )

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(_SCHEMA_EXISTS_SQL, (schemas,))
        existing = {row["nspname"] for row in cur.fetchall()}
        missing = [s for s in schemas if s not in existing]
        if missing:
            available = _list_user_schemas(cur)
            raise ValueError(_missing_schema_message(missing, available))

        cur.execute(_TABLES_SQL, (schemas,))
        table_rows = cur.fetchall()
        if not table_rows:
            # No tables, but we still need to check for views.
            cur.execute(_VIEWS_SQL, (schemas,))
            view_rows_early = cur.fetchall()
            deps_index_early: dict[tuple[str, str], set[tuple[str, str]]] = {}
            cur.execute(_VIEW_DEPS_SQL, [list(schemas)])
            for row in cur.fetchall():
                key = (row["view_schema"], row["view_name"])
                deps_index_early.setdefault(key, set()).add(
                    (row["ref_schema"], row["ref_name"])
                )
            views_early = tuple(
                View(
                    schema=row["schema_name"],
                    name=row["view_name"],
                    is_materialized=row["is_materialized"],
                    security_invoker=row["security_invoker"],
                    security_barrier=row["security_barrier"],
                    definition=row["definition"],
                    references=tuple(sorted(
                        deps_index_early.get(
                            (row["schema_name"], row["view_name"]), set()
                        )
                    )),
                    security_definer_calls=(),  # Task 5 populates this
                )
                for row in view_rows_early
            )
            return Schema(tables=(), views=views_early)

        oids = [row["table_oid"] for row in table_rows]
        cur.execute(_COLUMNS_SQL, (oids,))
        column_rows = cur.fetchall()
        cur.execute(_POLICIES_SQL, (oids,))
        policy_rows = cur.fetchall()
        cur.execute(_PARTITION_PARENTS_SQL, (oids,))
        partition_rows = cur.fetchall()
        cur.execute(_GRANTS_SQL, (schemas,))
        grants_by_oid: dict[int, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for row in cur.fetchall():
            grants_by_oid[row["table_oid"]][row["role_name"]].append(
                row["privilege_type"]
            )

        cur.execute(_VIEWS_SQL, (schemas,))
        view_rows = cur.fetchall()
        deps_index: dict[tuple[str, str], set[tuple[str, str]]] = {}
        cur.execute(_VIEW_DEPS_SQL, [list(schemas)])
        for row in cur.fetchall():
            key = (row["view_schema"], row["view_name"])
            deps_index.setdefault(key, set()).add(
                (row["ref_schema"], row["ref_name"])
            )

    columns_by_oid: dict[int, list[str]] = defaultdict(list)
    for row in column_rows:
        columns_by_oid[row["table_oid"]].append(row["column_name"])

    partition_parent_by_oid: dict[int, tuple[str, str]] = {
        row["child_oid"]: (row["parent_schema"], row["parent_name"])
        for row in partition_rows
    }

    # Build a per-OID schema/name lookup so the parse-error warning
    # can report the policy's qualified location (`schema.table.policy`)
    # instead of an anonymous "could not parse" line.
    table_qname_by_oid: dict[int, str] = {
        row["table_oid"]: f"{row['schema_name']}.{row['table_name']}"
        for row in table_rows
    }

    by_oid: dict[int, list[Policy]] = defaultdict(list)
    for row in policy_rows:
        cmd_letter = cast(str, row["cmd"])
        command = _POLICY_CMD_MAP.get(cmd_letter)
        if command is None:
            raise RuntimeError(
                f"Unknown pg_policy.polcmd value {cmd_letter!r} for "
                f"policy {row['policy_name']!r}"
            )
        using_sql = row["using_sql"]
        with_check_sql = row["with_check_sql"]
        policy_loc = (
            f"{table_qname_by_oid[row['table_oid']]}.{row['policy_name']}"
        )
        by_oid[row["table_oid"]].append(
            Policy(
                name=row["policy_name"],
                command=command,  # type: ignore[arg-type]
                permissive=row["permissive"],
                roles=tuple(row["roles"]),
                using_sql=using_sql,
                with_check_sql=with_check_sql,
                using_ast=parse_expr(
                    using_sql, location=policy_loc, clause="USING"
                ),
                with_check_ast=parse_expr(
                    with_check_sql,
                    location=policy_loc,
                    clause="WITH CHECK",
                ),
            )
        )

    tables = [
        Table(
            schema=row["schema_name"],
            name=row["table_name"],
            rls_enabled=row["rls_enabled"],
            force_rls=row["force_rls"],
            policies=tuple(by_oid.get(row["table_oid"], [])),
            columns=tuple(columns_by_oid.get(row["table_oid"], [])),
            partition_of=partition_parent_by_oid.get(row["table_oid"]),
            grants=tuple(
                Grant(role=role, privileges=tuple(privileges))
                for role, privileges in sorted(
                    grants_by_oid.get(row["table_oid"], {}).items()
                )
            ),
        )
        for row in table_rows
    ]

    views = tuple(
        View(
            schema=row["schema_name"],
            name=row["view_name"],
            is_materialized=row["is_materialized"],
            security_invoker=row["security_invoker"],
            security_barrier=row["security_barrier"],
            definition=row["definition"],
            references=tuple(sorted(
                deps_index.get((row["schema_name"], row["view_name"]), set())
            )),
            security_definer_calls=(),  # Task 5 populates this
        )
        for row in view_rows
    )

    return Schema(tables=tuple(tables), views=views)
