"""Read RLS-relevant state from `pg_catalog` into a normalized Schema."""
from __future__ import annotations

import sys
from collections import defaultdict
from typing import Any, cast

import pglast
import psycopg
from psycopg.rows import dict_row

from pgrls.ast_utils import find_func_calls, parse_expr
from pgrls.model import (
    BypassRlsEscalation,
    BypassRlsRole,
    Column,
    ColumnGrant,
    DefaultPrivilege,
    ForeignKey,
    ForeignTable,
    Grant,
    ImmutableFunction,
    Index,
    LeakproofFunction,
    OwnerReachableMember,
    RoleMembership,
    Policy,
    Schema,
    SecdefFunction,
    Table,
    Trigger,
    View,
)

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
    pg_catalog.pg_get_userbyid(c.relowner) AS owner_name,
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

# Classic-`INHERITS` parents — the complement of `_PARTITION_PARENTS_SQL`
# (which filters `relispartition = true`). `pg_inherits` records BOTH a
# declarative partition's parent and a legacy `CREATE TABLE child ()
# INHERITS (parent)` edge; the child's `pg_class.relispartition` is the
# discriminator (`false` for classic inheritance). A classic-inheritance
# child may inherit from MULTIPLE parents (a DAG), so one child OID can
# appear in several rows here — unlike a partition child, which has exactly
# one parent. SEC043 reads these: a direct query on a classic-inheritance
# child whose own RLS is off bypasses an RLS-enforcing ancestor's policy,
# exactly as SEC041 covers for partitions.
_INHERITANCE_PARENTS_SQL = """
SELECT
    inh.inhrelid AS child_oid,
    pn.nspname AS parent_schema,
    pc.relname AS parent_name
FROM pg_catalog.pg_inherits inh
JOIN pg_catalog.pg_class cc ON cc.oid = inh.inhrelid
JOIN pg_catalog.pg_class pc ON pc.oid = inh.inhparent
JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
WHERE cc.relispartition = false
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
    a.attname AS column_name,
    -- `format_type(atttypid, atttypmod)` produces the canonical SQL type
    -- the way Postgres itself formats CREATE TABLE: `numeric(10,2)`,
    -- `timestamp with time zone`, `text`, etc. This is what we want
    -- to round-trip through Schema.to_sql() in v0.5+.
    pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
    NOT a.attnotnull AS is_nullable
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
# Role-name resolution mirrors the `polroles` handling above,
# joining the world-readable `pg_roles` view — NOT `pg_authid`,
# which a non-superuser cannot SELECT (a LEFT JOIN to it raises
# `permission denied for table pg_authid` mid-introspection, not
# a NULL row). `ar.rolname` can still be NULL (a race against
# `DROP ROLE`, or a grantee OID with no matching row). A NULL
# leaking into `Grant.role` violates the `str` annotation and
# breaks downstream JSON serialization and `sorted()` calls.
# COALESCE to a stable `oid:N` sentinel so the type contract
# holds and the operator can still see what role was referenced.
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
-- DISTINCT drops aclexplode's per-grantor multiplicity: a privilege
-- re-granted to the same grantee by two grantors (the normal WITH GRANT
-- OPTION case) yields one row per grantor, which would otherwise append
-- a duplicate into Grant.privileges. Mirrors the polroles SELECT DISTINCT.
SELECT DISTINCT
    c.oid AS table_oid,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
         ELSE COALESCE(ar.rolname, 'oid:' || ax.grantee::text)
    END AS role_name,
    ax.privilege_type
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN LATERAL aclexplode(c.relacl) ax ON true
LEFT JOIN pg_catalog.pg_roles ar ON ar.oid = ax.grantee
WHERE c.relkind IN ('r', 'p')
  AND n.nspname = ANY(%s)
  AND c.relacl IS NOT NULL
  AND ax.grantee IS NOT NULL
  -- Exclude the table owner's own ACL row. A default-ACL table has
  -- relacl=NULL and aclexplode yields nothing, so the owner's
  -- always-implicit privileges are invisible. But the moment ANY explicit
  -- GRANT is added, Postgres materializes the FULL ACL including the
  -- owner's self-grant — which would then surface as a phantom
  -- DIFF_GRANT_ADDED on the owner (and to_sql() would re-emit GRANT … TO
  -- owner for diff --apply). The owner always holds these privileges, so
  -- it is never a real delta; drop the row so capture is independent of
  -- whether other grants exist.
  AND ax.grantee <> c.relowner
ORDER BY c.oid, role_name, ax.privilege_type
"""

# Column-level grants from `pg_attribute.attacl` (`GRANT SELECT (col) ON
# t TO role`). Stored separately from table-level `relacl`, so a PUBLIC
# column grant on a no-RLS table is otherwise invisible to the diff's
# GRANT_PUBLIC_NO_RLS detection. Mirrors `_GRANTS_SQL`: real columns only
# (`attnum > 0 AND NOT attisdropped`), the owner self-grant excluded
# (same phantom-delta rationale as the table-grant query — the owner
# always holds the privilege), grantee 0 rendered as PUBLIC.
_COLUMN_GRANTS_SQL = """
-- DISTINCT drops aclexplode's per-grantor multiplicity (see _GRANTS_SQL).
SELECT DISTINCT
    c.oid AS table_oid,
    a.attname AS column_name,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
         ELSE COALESCE(ar.rolname, 'oid:' || ax.grantee::text)
    END AS role_name,
    ax.privilege_type
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
LEFT JOIN LATERAL aclexplode(a.attacl) ax ON true
LEFT JOIN pg_catalog.pg_roles ar ON ar.oid = ax.grantee
WHERE c.relkind IN ('r', 'p')
  AND n.nspname = ANY(%s)
  AND a.attnum > 0
  AND NOT a.attisdropped
  AND a.attacl IS NOT NULL
  AND ax.grantee IS NOT NULL
  AND ax.grantee <> c.relowner
ORDER BY c.oid, column_name, role_name, ax.privilege_type
"""

_VIEWS_SQL = """
SELECT
    n.nspname AS schema_name,
    c.relname AS view_name,
    c.relkind = 'm' AS is_materialized,
    -- pg_class.reloptions is text[] like {security_invoker=on, security_barrier=on}.
    -- Parse the option VALUE as a Postgres boolean rather than matching two
    -- literal spellings: PG accepts on/off, true/false, yes/no, 1/0, t/f, y/n
    -- (case-insensitive) for boolean reloptions and may store the value as
    -- typed, so a view created `WITH (security_invoker=1)` (or yes/t/y) must
    -- still read as TRUE. split on the first '=' into name/value.
    COALESCE(
        (SELECT lower(split_part(o.opt, '=', 2)) IN ('on', 'true', 'yes', '1', 't', 'y')
         FROM unnest(c.reloptions) AS o(opt)
         WHERE split_part(o.opt, '=', 1) = 'security_invoker'),
        FALSE
    ) AS security_invoker,
    COALESCE(
        (SELECT lower(split_part(o.opt, '=', 2)) IN ('on', 'true', 'yes', '1', 't', 'y')
         FROM unnest(c.reloptions) AS o(opt)
         WHERE split_part(o.opt, '=', 1) = 'security_barrier'),
        FALSE
    ) AS security_barrier,
    pg_get_viewdef(c.oid, true) AS definition,
    -- A `security_invoker = false` view executes as its OWNER, so the RLS of
    -- the tables it reads is evaluated against the owner rather than the
    -- caller. Whether that is a *bypass* depends on the owner being exempt —
    -- either it owns the table and the table is not FORCE'd, or it is
    -- superuser / BYPASSRLS. `verify --mode reachability` needs both to tell
    -- an exempt owner from an ordinary one; same shape as the SECDEF-function
    -- query above.
    pg_catalog.pg_get_userbyid(c.relowner) AS owner_name,
    (vo.rolsuper OR vo.rolbypassrls) AS owner_bypasses_rls,
    vo.rolsuper AS owner_is_superuser,
    c.oid AS view_oid
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_roles vo ON vo.oid = c.relowner
WHERE c.relkind IN ('v', 'm')
  AND n.nspname = ANY(%s)
ORDER BY n.nspname, c.relname
"""

# View/matview privilege grants from `pg_class.relacl` — the parallel of
# `_GRANTS_SQL` for relkind 'v'/'m' (kept separate so the table-grant query
# stays untouched). SEC052 reads these to confirm a low-trust role can
# actually reach the view over the API before flagging an auth.users
# exposure. Same shape and hardening as `_GRANTS_SQL`: SELECT DISTINCT drops
# aclexplode's per-grantor multiplicity, grantee 0 renders as PUBLIC, and the
# owner's own self-grant is excluded (it always holds the privilege).
# Column-level grants on views / matviews (`pg_attribute.attacl`), the twin
# of `_COLUMN_GRANTS_SQL` for relkind v/m. A `GRANT SELECT (id, body) ON v TO
# anon` opens the view to anon just as a table-level grant does (measured),
# while `relacl` stays NULL — so `verify --mode reachability` must see it.
_VIEW_COLUMN_GRANTS_SQL = """
SELECT DISTINCT
    c.oid AS view_oid,
    a.attname AS column_name,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
         ELSE COALESCE(ar.rolname, 'oid:' || ax.grantee::text)
    END AS role_name,
    ax.privilege_type
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
LEFT JOIN LATERAL aclexplode(a.attacl) ax ON true
LEFT JOIN pg_catalog.pg_roles ar ON ar.oid = ax.grantee
WHERE c.relkind IN ('v', 'm')
  AND n.nspname = ANY(%s)
  AND a.attnum > 0
  AND NOT a.attisdropped
  AND a.attacl IS NOT NULL
  AND ax.grantee IS NOT NULL
  AND ax.grantee <> c.relowner
ORDER BY c.oid, column_name, role_name, ax.privilege_type
"""

_VIEW_GRANTS_SQL = """
SELECT DISTINCT
    c.oid AS view_oid,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
         ELSE COALESCE(ar.rolname, 'oid:' || ax.grantee::text)
    END AS role_name,
    ax.privilege_type
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN LATERAL aclexplode(c.relacl) ax ON true
LEFT JOIN pg_catalog.pg_roles ar ON ar.oid = ax.grantee
WHERE c.relkind IN ('v', 'm')
  AND n.nspname = ANY(%s)
  AND c.relacl IS NOT NULL
  AND ax.grantee IS NOT NULL
  AND ax.grantee <> c.relowner
ORDER BY c.oid, role_name, ax.privilege_type
"""

# Foreign tables (relkind 'f') in the scanned schemas — read by SEC053. A
# foreign table cannot carry RLS, so one exposed over the API with a low-trust
# grant is an unfilterable read.
_FOREIGN_TABLES_SQL = """
SELECT c.oid AS ft_oid, n.nspname AS schema_name, c.relname AS ft_name
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'f'
  AND n.nspname = ANY(%s)
ORDER BY n.nspname, c.relname
"""

# Foreign-table relacl grants — the parallel of `_GRANTS_SQL`/`_VIEW_GRANTS_SQL`
# for relkind 'f'. Same hardening: SELECT DISTINCT dedups per-grantor
# multiplicity, grantee 0 renders as PUBLIC, owner self-grant excluded.
_FOREIGN_TABLE_GRANTS_SQL = """
SELECT DISTINCT
    c.oid AS ft_oid,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
         ELSE COALESCE(ar.rolname, 'oid:' || ax.grantee::text)
    END AS role_name,
    ax.privilege_type
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN LATERAL aclexplode(c.relacl) ax ON true
LEFT JOIN pg_catalog.pg_roles ar ON ar.oid = ax.grantee
WHERE c.relkind = 'f'
  AND n.nspname = ANY(%s)
  AND c.relacl IS NOT NULL
  AND ax.grantee IS NOT NULL
  AND ax.grantee <> c.relowner
ORDER BY c.oid, role_name, ax.privilege_type
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
 -- Constrain the REFERENCED side to relations too. Postgres draws OIDs
 -- from one cluster-wide counter shared across catalogs, so without this
 -- a rewrite-rule dependency on a pg_proc / pg_type / pg_operator object
 -- whose OID happens to collide with a pg_class relation OID would join
 -- through and emit a phantom (ref_schema, ref_name) — a spurious view
 -- reference that VIEW001/002/003 could then report as an RLS leak. The
 -- function-result deps the fixture notes are tracked via pg_proc, not
 -- pg_class, so they must be structurally excluded here, not by luck.
 AND d.refclassid = 'pg_catalog.pg_class'::regclass
JOIN pg_catalog.pg_class t ON t.oid = d.refobjid
JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
WHERE v.relkind IN ('v', 'm')
  AND t.relkind IN ('r', 'p', 'v', 'm')  -- tables, partitioned tables, AND
                                         -- views/matviews so view→view
                                         -- chains can be resolved in Python
  AND vn.nspname = ANY(%s)
  AND v.oid != t.oid             -- exclude self-rule rows
ORDER BY vn.nspname, v.relname, tn.nspname, t.relname
"""

# User-authored triggers on the captured tables. `tgisinternal = false`
# strips the foreign-key check / RI helper / partition-routing triggers
# Postgres auto-creates — those are framework plumbing, not an audit
# target. User-authored `CREATE CONSTRAINT TRIGGER` rows have
# `tgconstraint != 0` but `tgisinternal = false`, so they pass this
# filter and SEC013 captures them — deferred constraint triggers
# still fire as the table owner and present the same RLS bypass
# surface as any other AFTER trigger.
#
# The event mask is decoded from `pg_trigger.tgtype` bit by bit
# in SQL so introspection produces a human-readable string the rule can
# put straight into a message ("INSERT", "INSERT OR UPDATE", etc.) and
# the snapshot doesn't carry an opaque integer that future readers would
# have to redecode.
#
# Bit assignments (from include/catalog/pg_trigger.h — stable across
# every Postgres version pgrls supports):
#   bit 0 (mask 1)  = ROW-level (else STATEMENT)
#   bit 1 (mask 2)  = BEFORE
#   bit 2 (mask 4)  = INSERT
#   bit 3 (mask 8)  = DELETE
#   bit 4 (mask 16) = UPDATE
#   bit 5 (mask 32) = TRUNCATE
#   bit 6 (mask 64) = INSTEAD OF
#
# `array_to_string(array_remove(ARRAY[...], NULL), ' OR ')` collapses
# the per-event NULL-or-keyword cells into a single string in the order
# Postgres itself uses (INSERT, DELETE, UPDATE, TRUNCATE) — matches
# `pg_get_triggerdef` output and is what an operator reading the
# violation message expects.
#
# `tgenabled` is a single char: 'D' = disabled, 'O' (origin / normal),
# 'R' (replica only), 'A' (always). SEC013 cares about the boolean
# "could this trigger fire under any circumstance" — anything other than
# 'D' satisfies that. Captured as a bool here so the rule logic stays
# simple; the snapshot still flips on a re-enable.
#
# The ROW vs STATEMENT axis (`tgtype` bit 0) is intentionally not
# captured. Both fire as the table owner, so both present the same
# RLS-bypass surface — SEC013 doesn't care which one fired. A
# STATEMENT trigger that runs `SELECT count(*) FROM peer_tenant` once
# per UPDATE is just as leaky as a ROW trigger doing the same per
# row. Skipping the axis keeps the Trigger dataclass smaller and the
# violation message shorter.
#
# Partitioned table trigger propagation: on PG13+, declaring a
# trigger on a partitioned parent automatically clones it onto each
# child partition. The clones carry `tgparentid != 0` but
# `tgisinternal = false`, so the `tgisinternal` filter alone would
# leave them visible and SEC013 would double-fire (parent + each
# child) on a partition setup with N children. Filtering with
# `tgparentid = 0` keeps only the user-declared parent row and
# drops the auto-cloned children. The parent declaration is the
# audit target — the children are identical clones routing through
# the same function, so the operator only needs to audit once.
# Classic `INHERITS` children don't auto-propagate triggers; each
# such child carries its own user-declared trigger with
# `tgparentid = 0` and gets captured normally.
#
# ORDER BY (table_oid, trigger_name) keeps the per-table tuple
# deterministic across runs so snapshots are byte-stable. Triggers
# live in their table's namespace (pg_trigger has no tgnamespace
# column), so the trigger's schema is always the same as the
# table's — Trigger doesn't carry a redundant `schema` field.
_TRIGGERS_SQL = """
SELECT
    t.tgrelid AS table_oid,
    t.tgname AS trigger_name,
    fn.nspname AS function_schema,
    p.proname AS function_name,
    CASE
        WHEN t.tgtype & 64 = 64 THEN 'INSTEAD OF'
        WHEN t.tgtype & 2 = 2 THEN 'BEFORE'
        ELSE 'AFTER'
    END AS timing,
    array_to_string(
        array_remove(
            ARRAY[
                CASE WHEN t.tgtype & 4 = 4 THEN 'INSERT' END,
                CASE WHEN t.tgtype & 8 = 8 THEN 'DELETE' END,
                CASE WHEN t.tgtype & 16 = 16 THEN 'UPDATE' END,
                CASE WHEN t.tgtype & 32 = 32 THEN 'TRUNCATE' END
            ],
            NULL
        ),
        ' OR '
    ) AS event,
    t.tgenabled != 'D' AS enabled
FROM pg_catalog.pg_trigger t
JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
JOIN pg_catalog.pg_namespace fn ON fn.oid = p.pronamespace
WHERE t.tgisinternal = false
  AND t.tgparentid = 0
  AND t.tgrelid = ANY(%s)
ORDER BY t.tgrelid, t.tgname
"""

# Valid + ready indexes on the captured tables. PERF003 walks the
# captured `Table.indexes` to check whether columns referenced in
# a policy predicate have a leading-column index — without one,
# the planner does a sequential scan to filter rows, which is fine
# for small tables but catastrophic on multi-tenant tables with
# millions of rows.
#
# Filtering criteria:
#   * `i.indisvalid AND i.indisready` — a half-built index from a
#     failed `CREATE INDEX CONCURRENTLY` doesn't help the planner.
#     Capturing it would silence PERF003 and mislead the operator.
#
# Expression positions: `pg_index.indkey` is a `int2vector` of
# attribute numbers (attnum). Position values that are 0 are
# expression-index positions (the expression list lives in
# `indexprs`); pgrls doesn't decode the expressions in v0.5.10, so
# expression positions become empty strings in the `columns` array.
# PERF003 only checks the leading column by name, so expression
# leading positions naturally don't match any policy column — the
# operator is responsible for knowing their expression index helps.
#
# Dropped-column positions: Postgres normally drops indexes that
# reference a dropped column, but the `attisdropped` filter on the
# LEFT JOIN keeps the introspection contract clean in the edge
# cases where a dropped attnum somehow survives (manual catalog
# surgery, partial state during PG upgrades). A dropped-column
# attnum joins to no pg_attribute row → COALESCE yields the empty
# string, the same representation as an expression position. From
# PERF003's perspective both are "can't match by name," which is
# the correct read for both.
#
# `WITH ORDINALITY` on the unnest preserves the column order from
# `indkey`. The `LEFT JOIN` against `pg_attribute` returns NULL for
# expression positions (attnum 0 has no matching row); COALESCE to
# empty string for the snapshot's JSON-friendly representation.
#
# `array_remove(..., NULL)` is NOT used here — we want positional
# alignment in `columns` so a future caller can correlate position
# back to the expression list.
#
# ORDER BY (indrelid, index_name) for snapshot determinism.
_INDEXES_SQL = """
SELECT
    i.indrelid AS table_oid,
    c.relname AS index_name,
    am.amname AS access_method,
    i.indisunique AS is_unique,
    i.indpred IS NOT NULL AS is_partial,
    i.indisprimary AS is_primary,
    COALESCE(
        ARRAY(
            SELECT COALESCE(a.attname, '')
            -- Slice to the KEY columns only: indkey holds key columns
            -- followed by INCLUDE (covering) columns, and a covering
            -- column must not be read as part of the index's logical
            -- key (else SEC035 mistakes a UNIQUE(email) INCLUDE
            -- (tenant_id) for tenant-scoped). indnkeyatts = key count.
            -- `indkey::int[]` keeps int2vector's 0-based lower bound,
            -- so the first indnkeyatts elements are [0 : indnkeyatts-1].
            FROM unnest((i.indkey::int[])[0:i.indnkeyatts - 1])
                 WITH ORDINALITY AS k(attnum, ord)
            LEFT JOIN pg_catalog.pg_attribute a
                ON a.attrelid = i.indrelid
               AND a.attnum = k.attnum
               AND NOT a.attisdropped
            ORDER BY k.ord
        ),
        ARRAY[]::TEXT[]
    ) AS columns
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid
JOIN pg_catalog.pg_am am ON am.oid = c.relam
WHERE i.indisvalid
  AND i.indisready
  AND i.indrelid = ANY(%s)
ORDER BY i.indrelid, c.relname
"""

# FOREIGN KEY constraints carried on the captured (child / referencing)
# tables. SEC047 walks the captured `Table.foreign_keys` to flag a FK whose
# *parent* (referenced) table has RLS enabled when a low-trust role can write
# the child: FK validation runs as a system integrity check that bypasses
# RLS, so writing a child row that references a guessed parent key reveals
# whether that parent row exists — a cross-tenant existence covert channel
# (the FK-validation analog of SEC035's UNIQUE-index oracle).
#
# Keyed on the already-fetched child table OIDs (`con.conrelid = ANY(%s)`),
# the same pattern as `_INDEXES_SQL` / `_TRIGGERS_SQL`. The child columns are
# resolved via `unnest(con.conkey) WITH ORDINALITY` joined to `pg_attribute`
# on the CHILD relation (`conrelid`); the parent columns via
# `unnest(con.confkey) WITH ORDINALITY` joined to `pg_attribute` on the
# PARENT relation (`confrelid`). `WITH ORDINALITY` preserves the column order
# within each composite key and lines child columns up with the parent
# columns they reference (verified live, incl. multi-column FKs). The two
# ordered column arrays are built as correlated subqueries so a multi-row FK
# stays a single output row.
#
# The parent schema/table come from `confrelid` → `pg_class` / `pg_namespace`
# and are captured even when the parent lives in a schema OUTSIDE `--schemas`
# (no parent-namespace filter here): SEC047 resolves the parent in the
# snapshot and ABSTAINS (fail-closed) when it cannot — so capturing the
# parent identity unconditionally is correct, and the rule decides scope.
#
# Only validated constraints are relevant for the oracle, but an unvalidated
# (`NOT VALID`) FK still enforces the existence check on NEW rows — which is
# exactly the write path the oracle uses — so `convalidated` is NOT filtered.
# ORDER BY (conrelid, conname) for snapshot determinism.
_FOREIGN_KEYS_SQL = """
SELECT
    con.conrelid AS table_oid,
    con.conname AS name,
    rns.nspname AS ref_schema,
    rcl.relname AS ref_table,
    (
        SELECT COALESCE(array_agg(ca.attname ORDER BY k.ord), ARRAY[]::text[])
        FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
        JOIN pg_catalog.pg_attribute ca
            ON ca.attrelid = con.conrelid
           AND ca.attnum = k.attnum
    ) AS columns,
    (
        SELECT COALESCE(array_agg(fa.attname ORDER BY k.ord), ARRAY[]::text[])
        FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
        JOIN pg_catalog.pg_attribute fa
            ON fa.attrelid = con.confrelid
           AND fa.attnum = k.attnum
    ) AS ref_columns
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class rcl ON rcl.oid = con.confrelid
JOIN pg_catalog.pg_namespace rns ON rns.oid = rcl.relnamespace
WHERE con.contype = 'f'
  AND con.conrelid = ANY(%s)
ORDER BY con.conrelid, con.conname
"""

# Functions with SECURITY DEFINER set in the configured schemas. Used to
# match view bodies against — VIEW004 flags views whose definitions call
# any of these functions because a SECDEF call inside a non-invoker view
# bypasses the caller's RLS.
#
# `prosrc` is the function body. `lang.lanname` distinguishes `sql` (which
# pglast can parse top-level) from `plpgsql` and other procedural languages
# (whose bodies start with `DECLARE`/`BEGIN` and are not pglast-parseable
# as a top-level statement). VIEW004 uses the language to decide whether
# to attempt parsing or skip with a less-alarming "non-SQL language" warning.
# `owner_bypasses_rls` is the function owner's `rolsuper OR rolbypassrls`
# (joined from `pg_roles`): a SECDEF function only bypasses RLS when its
# owner is itself RLS-exempt — an ordinary owner under FORCE RLS is still
# subject to policies (verified live). `execute_roles` is the set of
# NON-owner roles holding EXECUTE, with PUBLIC rendered as the literal
# "PUBLIC". Unlike table `relacl` (default = owner-only), a function's
# DEFAULT ACL (`proacl IS NULL`) grants EXECUTE to PUBLIC, so
# `acldefault('f', proowner)` is substituted to expand the default — this
# captures the "forgot to REVOKE EXECUTE FROM PUBLIC" case that leaves a
# function anon-callable. Both feed SEC042.
_SECDEF_FUNCS_SQL = """
SELECT
    n.nspname || '.' || p.proname AS qname,
    n.nspname AS schema_name,
    p.proname AS function_name,
    -- A SQL-standard `BEGIN ATOMIC` body (PG14+) is stored PARSED in
    -- `prosqlbody`, and `prosrc` is EMPTY — not NULL, so COALESCE alone would
    -- not save us. Every body-reading consumer (VIEW004's table resolver, and
    -- through it `pgrls vector`'s retrieval-path discovery) then sees nothing
    -- and silently skips the function: two functionally identical SECDEF
    -- retrieval functions over one pgvector table, one classic and one
    -- `BEGIN ATOMIC`, yielded one path instead of two. Fall back to the
    -- deparsed body so both spellings analyze the same.
    COALESCE(NULLIF(p.prosrc, ''), pg_catalog.pg_get_function_sqlbody(p.oid))
        AS body,
    l.lanname AS lang,
    p.proconfig AS config,
    pg_catalog.pg_get_function_identity_arguments(p.oid) AS signature,
    (po.rolsuper OR po.rolbypassrls) AS owner_bypasses_rls,
    COALESCE((
        SELECT array_agg(DISTINCT CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
                                       ELSE COALESCE(ar.rolname,
                                                     'oid:' || ax.grantee::text)
                                  END)
        FROM aclexplode(
                 COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
             ) ax
        LEFT JOIN pg_catalog.pg_roles ar ON ar.oid = ax.grantee
        WHERE ax.privilege_type = 'EXECUTE'
          AND ax.grantee <> p.proowner
    ), '{}') AS execute_roles
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid = p.prolang
JOIN pg_catalog.pg_roles po ON po.oid = p.proowner
WHERE p.prosecdef = TRUE
  AND n.nspname = ANY(%s)
ORDER BY qname, signature
"""

# Roles carrying the BYPASSRLS attribute. A role with BYPASSRLS skips
# every row-level security policy on every table — SEC016 surfaces
# these so each one gets an explicit audit decision.
#
# `pg_catalog.pg_roles` is the catalog VIEW (not `pg_authid`): it is
# readable by every connected role, so introspection works without
# superuser. It exposes `rolbypassrls` / `rolsuper` / `rolcanlogin`
# directly. The existing `_POLICIES_SQL` already joins `pg_roles` for
# the same readability reason.
#
# `WHERE r.rolbypassrls` filters to the audit-relevant subset
# (mirroring `_SECDEF_FUNCS_SQL`'s `WHERE p.prosecdef = TRUE`): the
# captured set is exactly the roles SEC016 might flag, and a default
# cluster — where no role has been granted BYPASSRLS — captures zero
# rows. The Postgres-predefined `pg_*` roles (`pg_read_all_data`
# etc.) do not carry `rolbypassrls`, so they never appear here.
#
# Roles are cluster-global — this query takes no schema parameter and
# is independent of the introspector's `--schemas` set.
#
# ORDER BY rolname for snapshot determinism.
_BYPASSRLS_ROLES_SQL = """
SELECT
    r.rolname AS name,
    r.rolsuper AS superuser,
    r.rolcanlogin AS can_login
FROM pg_catalog.pg_roles r
WHERE r.rolbypassrls
ORDER BY r.rolname
"""

# Roles that can reach a BYPASSRLS role via SET ROLE — the SEC029
# surface. BYPASSRLS is a role *attribute*, never inherited through
# membership, so a member of a BYPASSRLS role doesn't bypass RLS
# automatically; but it can `SET ROLE` to the BYPASSRLS role and
# bypass from there. This computes the transitive closure of
# `pg_auth_members` (member -> roleid edges) and keeps only the
# (member, BYPASSRLS-target) pairs.
#
# `reach(member, target)` means "member is a transitive member of
# target" — i.e. member can SET ROLE to target. Base case: direct
# memberships. Recursive step: if member can reach R and R is a
# member of target, member can reach target.
#
# All `pg_auth_members` edges are treated as SET ROLE-capable. On
# PG15 every membership permits SET ROLE; on PG16+ a membership with
# `set_option = false` does not, so this can over-approximate there —
# acceptable for a warning that surfaces a bypass *path* (a false
# positive is an allowlist entry; a false negative is a missed
# escalation route). Using the raw edge set keeps the query
# identical across PG15-17 with no version-specific catalog columns.
#
# Members that already hold BYPASSRLS directly are SEC016's surface,
# not SEC029's; superusers bypass unconditionally. Both are excluded.
# `pg_auth_members` and `pg_roles` are readable by every connected
# role, so no superuser is needed. Roles are cluster-global — no
# schema parameter. ORDER BY for snapshot determinism.
_BYPASSRLS_ESCALATION_SQL = """
WITH RECURSIVE memberships(member, roleid) AS (
    SELECT member, roleid FROM pg_catalog.pg_auth_members
),
reach(member, roleid) AS (
    SELECT member, roleid FROM memberships
    UNION
    SELECT r.member, m.roleid
    FROM reach r
    JOIN memberships m ON m.member = r.roleid
)
SELECT
    mem.rolname AS member,
    mem.rolcanlogin AS member_can_login,
    tgt.rolname AS via
FROM reach
JOIN pg_catalog.pg_roles mem ON mem.oid = reach.member
JOIN pg_catalog.pg_roles tgt ON tgt.oid = reach.roleid
WHERE tgt.rolbypassrls
  AND NOT mem.rolbypassrls
  AND NOT mem.rolsuper
ORDER BY mem.rolname, tgt.rolname
"""

# Low-trust roles that can reach a table owner that is NOT FORCE'd — the
# SEC048 surface. A role that OWNS a table bypasses that table's RLS unless
# `FORCE ROW LEVEL SECURITY` is set (the SEC002 boundary). Owner *privileges*
# — unlike the BYPASSRLS role *attribute* SEC029 covers — ARE reachable
# through membership: a member of the owning role inherits its ownership (with
# INHERIT automatically; with NOINHERIT after a SET ROLE) and so bypasses RLS
# on the owner's enabled-but-not-forced tables (live-proven: a non-super/
# non-bypassrls LOGIN member of the owner read ALL rows of an ENABLEd-but-not-
# FORCEd table; FORCE is the exact non-leak boundary).
#
# `owner_roles` is the set of roles that own an enabled-not-forced RLS table
# IN the scanned schemas, EXCLUDING superuser/BYPASSRLS owners — those are
# SEC016/SEC029 territory, and excluding them keeps SEC048 strictly disjoint
# from SEC029. `reach(member, roleid)` is the transitive `pg_auth_members`
# closure (member can SET ROLE to / inherit roleid); the final join keeps only
# members that reach an `owner_roles` member, EXCLUDING superuser/BYPASSRLS
# members (they already bypass unconditionally — SEC016/SEC029 again).
#
# All `pg_auth_members` edges are treated as reachable, exactly as
# `_BYPASSRLS_ESCALATION_SQL`: on PG16+ a `WITH SET FALSE` membership does not
# permit SET ROLE, so this can over-approximate there — the same deliberate
# warning-bias (a false positive is one allowlist entry; a false negative is a
# missed bypass). `pg_auth_members`, `pg_roles`, and `pg_class` are readable by
# every connected role, so no superuser is needed. The schema list is the only
# parameter (owners are restricted to tables in scope); members are
# cluster-global. ORDER BY for snapshot determinism.
_OWNER_REACHABLE_MEMBERS_SQL = """
WITH RECURSIVE owner_roles AS (
    SELECT DISTINCT c.relowner AS owner_oid
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_catalog.pg_roles o ON o.oid = c.relowner
    WHERE c.relkind IN ('r', 'p')
      AND c.relrowsecurity
      AND NOT c.relforcerowsecurity
      AND n.nspname = ANY(%s)
      AND NOT o.rolsuper
      AND NOT o.rolbypassrls
),
memberships(member, roleid) AS (
    SELECT member, roleid FROM pg_catalog.pg_auth_members
),
reach(member, roleid) AS (
    SELECT member, roleid FROM memberships
    UNION
    SELECT r.member, m.roleid
    FROM reach r
    JOIN memberships m ON m.member = r.roleid
)
SELECT
    mem.rolname AS member,
    mem.rolcanlogin AS member_can_login,
    own.rolname AS via_owner
FROM reach
JOIN owner_roles orl ON orl.owner_oid = reach.roleid
JOIN pg_catalog.pg_roles mem ON mem.oid = reach.member
JOIN pg_catalog.pg_roles own ON own.oid = reach.roleid
WHERE NOT mem.rolsuper
  AND NOT mem.rolbypassrls
ORDER BY mem.rolname, own.rolname
"""

# Functions carrying the LEAKPROOF attribute in the configured
# schemas. A LEAKPROOF function tells the planner it has no side
# channels, so the planner may evaluate it below a security barrier
# (the RLS qual, a security_barrier view). SEC017 surfaces these so
# the operator confirms the leakproof claim actually holds.
#
# `WHERE p.proleakproof = TRUE` filters to the audit-relevant subset
# (mirroring `_SECDEF_FUNCS_SQL`'s `WHERE p.prosecdef = TRUE`).
# Postgres's own built-in leakproof functions live in `pg_catalog`,
# which is never in the linted `--schemas`, so they never appear —
# what remains is user-defined functions a superuser deliberately
# marked LEAKPROOF (only a superuser can).
#
# Each overload is captured as its OWN row (no DISTINCT, since v12):
# `public.f(int)` and `public.f(text)` both marked LEAKPROOF yield two
# rows, each carrying its `signature`
# (`pg_get_function_identity_arguments`) plus schema_name / function_name —
# so a SEC017 fixer can target `ALTER FUNCTION name(<signature>) NOT
# LEAKPROOF` per overload. SEC017 itself dedupes across overloads for its
# qualified-name-level reporting (and the allowlist key is the qualified
# name, so one entry covers every overload). The body (`prosrc`/`lanname`)
# is NOT fetched — unlike `_SECDEF_FUNCS_SQL`, SEC017 is an audit prompt,
# not a body analysis.
#
# ORDER BY qname, signature for snapshot determinism across overloads.
_LEAKPROOF_FUNCS_SQL = """
SELECT
    n.nspname || '.' || p.proname AS qname,
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_catalog.pg_get_function_identity_arguments(p.oid) AS signature
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE p.proleakproof = TRUE
  AND n.nspname = ANY(%s)
ORDER BY qname, signature
"""

# Default privileges on TABLES from `pg_default_acl` (`defaclobjtype = 'r'`).
# `ALTER DEFAULT PRIVILEGES [IN SCHEMA s] [FOR ROLE r] GRANT <priv> ON TABLES
# TO <grantee>` records one row here; every table CREATED AFTER it (in scope)
# is automatically granted the privilege. SEC044 flags a row that grants a
# row-access privilege to a low-trust grantee (PUBLIC by default), because a
# new table whose author forgets `ENABLE ROW LEVEL SECURITY` is then silently
# exposed.
#
# `aclexplode(defaclacl)` expands the aclitem[] into one (grantee, privilege)
# row each, and grantee 0 is rendered as the literal "PUBLIC" — mirroring
# `_GRANTS_SQL`. Role-name resolution joins the world-readable `pg_roles`
# (not `pg_authid`), COALESCE-ing an unresolved grantee to a stable `oid:N`
# sentinel so the `str` contract holds.
#
# `defaclnamespace` is the schema OID, or 0 for a CLUSTER-WIDE entry (one set
# without `IN SCHEMA`, which affects every schema). The LEFT JOIN to
# pg_namespace yields the schema name, or NULL for the cluster-wide case —
# `_fetch_default_privileges` maps NULL to `schema=None`.
#
# `ax.grantee <> d.defaclrole` drops the self-grant the owning role always
# carries (a cluster-wide `... TO PUBLIC` stores `{=r/owner,
# owner=arwdDxt/owner}`, so the owner's full self-ACL would otherwise surface
# as a phantom grant) — the same owner-exclusion `_GRANTS_SQL` applies to
# `relacl`. The captured set is therefore the real non-owner default grants.
#
# `defaclrole` is the GRANTOR: the role whose table creation triggers this
# default (the `FOR ROLE` target, or the role that ran the statement). It is
# part of the pg_default_acl identity — `(defaclrole, defaclnamespace,
# defaclobjtype)` — so two defaults differing only by grantor are distinct
# standing rules, each revoked only by a `FOR ROLE <grantor>` REVOKE; we
# capture it (rendered via pg_roles, `oid:N` sentinel if unresolved) so SEC044
# keys dedup on it and emits a precise remediation. `defaclrole` is never 0.
#
# Scope: schema-scoped entries are restricted to the introspected `--schemas`,
# but cluster-wide entries (`defaclnamespace = 0`) are ALWAYS captured because
# they affect tables in every schema. ALL grantees and ALL privileges are
# captured (the rule filters); capturing broadly keeps the model faithful and
# lets config widen the grantee set. ORDER BY for snapshot determinism.
_DEFAULT_PRIVILEGES_SQL = """
SELECT DISTINCT
    dn.nspname AS schema_name,
    CASE WHEN ax.grantee = 0 THEN 'PUBLIC'
         ELSE COALESCE(ar.rolname, 'oid:' || ax.grantee::text)
    END AS grantee,
    ax.privilege_type,
    COALESCE(gr.rolname, 'oid:' || d.defaclrole::text) AS grantor
FROM pg_catalog.pg_default_acl d
LEFT JOIN pg_catalog.pg_namespace dn ON dn.oid = d.defaclnamespace
LEFT JOIN LATERAL aclexplode(d.defaclacl) ax ON true
LEFT JOIN pg_catalog.pg_roles ar ON ar.oid = ax.grantee
LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = d.defaclrole
WHERE d.defaclobjtype = 'r'
  AND ax.grantee IS NOT NULL
  AND ax.grantee <> d.defaclrole
  AND (d.defaclnamespace = 0 OR dn.nspname = ANY(%s))
ORDER BY schema_name, grantee, grantor, ax.privilege_type
"""

# User-defined functions declared IMMUTABLE (`pg_proc.provolatile = 'i'`) in
# the configured schemas. An IMMUTABLE function promises the planner a fixed
# result per argument set, so the planner may CONSTANT-FOLD the call into a
# cached/reused plan. SEC046 flags one whose body reads session/identity state
# (`current_setting`, `auth.*`, `current_user`, `session_user`) or a table,
# because the folded value frozen for one caller is then served to the next
# under any reused plan (pooling, PostgREST, prepared statements, PL/pgSQL) —
# a cross-user wrong-row leak when the function is used in an RLS policy.
#
# `WHERE p.provolatile = 'i'` filters to the audit-relevant subset (mirroring
# `_LEAKPROOF_FUNCS_SQL`'s `WHERE p.proleakproof = TRUE` and
# `_SECDEF_FUNCS_SQL`'s `WHERE p.prosecdef = TRUE`). STABLE ('s') and VOLATILE
# ('v') functions are NOT folded (verified live) and are excluded.
# Postgres's own built-in IMMUTABLE functions live in `pg_catalog`, which is
# never in the linted `--schemas`, so they never appear — what remains is the
# user-defined IMMUTABLE functions a developer wrote.
#
# `prosrc` is the function body and `l.lanname` the language (mirroring
# `_SECDEF_FUNCS_SQL`); SEC046 parses a `sql` body to decide whether it reads
# session state or a table, and abstains on an empty/unparseable/non-SQL body
# (fail-closed). Each overload is captured as its OWN row (no DISTINCT): the
# body governs the verdict, so capturing each overload's body is faithful;
# SEC046 reports per qualified name. ORDER BY qname, signature for snapshot
# determinism across overloads.
_IMMUTABLE_FUNCS_SQL = """
SELECT
    n.nspname || '.' || p.proname AS qname,
    -- `BEGIN ATOMIC` bodies live in `prosqlbody`; see the SECDEF query.
    COALESCE(NULLIF(p.prosrc, ''), pg_catalog.pg_get_function_sqlbody(p.oid))
        AS body,
    l.lanname AS lang
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid = p.prolang
WHERE p.provolatile = 'i'
  AND n.nspname = ANY(%s)
ORDER BY qname, pg_catalog.pg_get_function_identity_arguments(p.oid)
"""

# Per-table publication membership for SEC051 (snapshot v22). The built-in
# `pg_publication_tables` view resolves membership the way the server does —
# expanding `FOR ALL TABLES` and (PG15+) `FOR TABLES IN SCHEMA` publications,
# not just explicit `ADD TABLE` members — and is available on every supported
# Postgres (the view has existed since PG10). Restricted to the introspected
# schemas; aggregated to one sorted publication-name array per table so the
# snapshot is deterministic.
_PUBLICATION_MEMBERSHIP_SQL = """
SELECT
    pt.schemaname AS schema_name,
    pt.tablename AS table_name,
    array_agg(pt.pubname ORDER BY pt.pubname) AS publications
FROM pg_catalog.pg_publication_tables pt
WHERE pt.schemaname = ANY(%s)
GROUP BY pt.schemaname, pt.tablename
"""


def _extract_search_path(config: list[str] | None) -> str | None:
    """Pull the `search_path` value out of a `pg_proc.proconfig` array.

    `proconfig` is a `text[]` of `name=value` GUC-override strings —
    `{search_path=pg_catalog\\, public\\, pg_temp, statement_timeout=5000}`
    — or NULL when the function overrides no GUCs. psycopg surfaces it
    as a Python `list[str]` (commas already un-escaped) or `None`.

    Returns the raw `search_path` value string (everything after the
    first `=`), or `None` when the function pins no search_path. GUC
    names are case-insensitive in Postgres, so the `search_path=`
    prefix is matched case-insensitively; the stored form is normally
    lowercase but a `SET "Search_Path" = ...` would round-trip
    differently.
    """
    if not config:
        return None
    for entry in config:
        name, sep, value = entry.partition("=")
        if sep and name.strip().lower() == "search_path":
            return value
    return None


def _fetch_secdef_functions(
    cur: Any, schemas: list[str]
) -> tuple[SecdefFunction, ...]:
    """Fetch every SECURITY DEFINER function in `schemas`.

    Returns a tuple of `SecdefFunction` records sorted by qualified name
    (the SQL `ORDER BY qname` provides the determinism). Used by both
    the introspect `Schema.security_definer_functions` field and the
    bare-call detection in `_build_secdef_calls_index` — sharing the
    fetch lets both consumers see the same set without an extra round
    trip.

    Each record carries `body` + `language` (for VIEW004's body
    parsing), `search_path` (for SEC015's pg_temp-shadowing check,
    decoded from `pg_proc.proconfig`), and `execute_roles` +
    `owner_bypasses_rls` (for SEC042's anon-executable-bypass check).
    """
    cur.execute(_SECDEF_FUNCS_SQL, [list(schemas)])
    return tuple(
        SecdefFunction(
            qualified_name=row["qname"],
            body=row["body"],
            language=row["lang"],
            search_path=_extract_search_path(row["config"]),
            signature=row["signature"] or "",
            schema_name=row["schema_name"],
            function_name=row["function_name"],
            execute_roles=tuple(sorted(row["execute_roles"] or ())),
            owner_bypasses_rls=bool(row["owner_bypasses_rls"]),
        )
        for row in cur.fetchall()
    )


def _fetch_bypassrls_roles(cur: Any) -> tuple[BypassRlsRole, ...]:
    """Fetch every role carrying the BYPASSRLS attribute.

    Returns a tuple of `BypassRlsRole` records sorted by role name
    (the SQL `ORDER BY r.rolname` provides the determinism). Takes no
    schema list — roles are cluster-global, so the captured set is the
    same regardless of which schemas are being introspected.
    """
    cur.execute(_BYPASSRLS_ROLES_SQL)
    return tuple(
        BypassRlsRole(
            name=row["name"],
            superuser=row["superuser"],
            can_login=row["can_login"],
        )
        for row in cur.fetchall()
    )


def _fetch_bypassrls_escalation_roles(
    cur: Any,
) -> tuple[BypassRlsEscalation, ...]:
    """Fetch roles that can SET ROLE to a BYPASSRLS role transitively.

    The SQL returns one (member, via) row per reachable BYPASSRLS
    target, ordered by member then target. Group consecutive rows by
    member into one `BypassRlsEscalation` each, preserving the
    target ordering as the `via` tuple. Takes no schema list — roles
    are cluster-global.
    """
    cur.execute(_BYPASSRLS_ESCALATION_SQL)
    by_member: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in cur.fetchall():
        member = row["member"]
        if member not in by_member:
            by_member[member] = {
                "via": [],
                "can_login": row["member_can_login"],
            }
            order.append(member)
        by_member[member]["via"].append(row["via"])
    return tuple(
        BypassRlsEscalation(
            member=member,
            via=tuple(by_member[member]["via"]),
            member_can_login=by_member[member]["can_login"],
        )
        for member in order
    )


# The raw `pg_auth_members` edge list (member → group). `verify --mode anon`
# walks the transitive closure of the configured anon role(s) over these to
# decide which policies an anonymous session can invoke — a `TO authenticated`
# policy is anon-reachable only if `anon` is a (transitive) member of
# `authenticated`, which the flat `{anon, PUBLIC}` name-match can't see. Roles
# and their memberships are cluster-global, so this is unfiltered by schema.
# `roleid` is the group; `member` inherits its privileges. Readable by every
# connected role.
_ROLE_MEMBERSHIPS_SQL = """
    SELECT g.rolname AS role, m.rolname AS member,
           -- PG16+ carries a per-edge INHERIT option; older servers use the
           -- member role's rolinherit. `to_jsonb` keeps one query valid on
           -- both: the key is simply absent (NULL) before PG16.
           COALESCE((to_jsonb(am) ->> 'inherit_option')::boolean, m.rolinherit)
               AS inherit
    FROM pg_catalog.pg_auth_members am
    JOIN pg_catalog.pg_roles g ON g.oid = am.roleid
    JOIN pg_catalog.pg_roles m ON m.oid = am.member
    ORDER BY member, role
"""


# Custom (dotted) GUCs a session inherits WITHOUT running `SET` — set at the
# database / role level (`ALTER DATABASE … SET app.x`, `ALTER ROLE … SET`) or
# in the server configuration. `verify --mode anon` assumes a custom GUC is
# UNSET for an anonymous session (the read raises → no rows). A standing
# `ALTER DATABASE postgres SET app.tenant_id = 'shared'` breaks that
# assumption: a fresh anon session reads the shared value and the canonical
# `tenant_id = current_setting('app.tenant_id')` policy admits every row
# stamped with it (measured live). Capturing the names lets the prover stop
# claiming PROVEN there. Session-/client-set values are excluded — those are
# this connection's own state, not what an anonymous caller inherits.
_SET_GUCS_SQL = """
SELECT DISTINCT
    lower(split_part(cfg, '=', 1)) AS name,
    CASE WHEN s.setrole = 0 THEN NULL ELSE r.rolname END AS role,
    substr(cfg, strpos(cfg, '=') + 1) AS value,
    CASE
        WHEN s.setrole <> 0 AND s.setdatabase <> 0 THEN 3
        WHEN s.setrole <> 0 THEN 2
        WHEN s.setdatabase <> 0 THEN 1
        ELSE 0
    END AS tier
FROM pg_catalog.pg_db_role_setting s
CROSS JOIN LATERAL unnest(s.setconfig) AS cfg
LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
WHERE (
    s.setdatabase = 0
    OR s.setdatabase = (
        SELECT d.oid FROM pg_catalog.pg_database d
        WHERE d.datname = current_database()
    )
)
AND split_part(cfg, '=', 1) LIKE '%.%'
ORDER BY 1, 2
"""

# Server-configuration custom GUCs. These are NOT in `pg_settings` —
# Postgres registers custom placeholders GUC_NO_SHOW_ALL (measured on PG16: a
# `postgresql.conf` line `app.sys = 'sysval'` is readable by every session,
# `current_setting` included, yet `pg_settings` has zero rows for it), so a
# first cut that read `pg_settings` captured nothing at all. `pg_file_settings`
# lists the applied file entries. It is not the whole story: a GUC given on
# the postmaster command line (`postgres -c app.x=v`, the docker-compose
# `command:` / k8s `args:` idiom) appears in NEITHER view, yet every session
# reads it — measured on PG16: `current_setting('app.cmdline')` returns the
# value while `pg_settings` and `pg_file_settings` both have zero rows. That
# is why the session probe below runs unconditionally rather than only as a
# fallback. (`ALTER SYSTEM` refuses a custom name the server has never seen,
# so `postgresql.auto.conf` adds nothing beyond the file entries.)
_FILE_SET_GUCS_SQL = """
SELECT DISTINCT lower(name) AS name, setting
FROM pg_catalog.pg_file_settings
WHERE applied AND name LIKE '%.%'
ORDER BY 1
"""

# `pg_file_settings` needs superuser / pg_read_all_settings. Without it, fall
# back to asking THIS session for every dotted GUC a policy reads: a
# server-level setting applies to every session, so a non-empty answer means
# the GUC is set — but the value could be this role's own, so it is recorded
# as "set, value not captured" (a `None` value in `Schema.set_gucs`) and the
# prover keeps it opaque rather than trusting a possibly wrong string.
_POLICY_GUC_NAMES_SQL = r"""
SELECT DISTINCT lower(m[1]) AS name
FROM pg_catalog.pg_policy p
CROSS JOIN LATERAL regexp_matches(
    pg_catalog.pg_get_expr(p.polqual, p.polrelid)
        || ' ' || COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), ''),
    $re$current_setting\(\s*'([^']+\.[^']+)'$re$, 'gi') AS m
"""


def _fetch_set_gucs(
    cur: Any,
) -> tuple[tuple[tuple[str, str | None], ...], tuple[tuple[str, str, str], ...]]:
    """Dotted GUCs already set, with their values — `([(name, value)] at
    database / server level, [(role, name, value)] at role level)`.

    Names are casefolded: GUC names are case-insensitive but
    `pg_db_role_setting.setconfig` preserves the ALTER's spelling, and a
    case-sensitive match missed `"App.Tenant"` vs `current_setting(
    'app.tenant')`. Values are captured too, so the prover can decide
    `current_setting('app.flag') = 'on'` against the configured value
    (measured: at 'off' the anonymous read returns 0 rows) instead of
    declining, and so `--probe` / `--emit-repro` can replay the session a
    real anonymous caller gets. A database-level setting overrides the
    server configuration, so it wins here.

    Role-level settings bind to the LOGIN role — see `verify._anon_login_roles`
    — so they are returned per role rather than merged. Where one name is set
    at several levels the most specific wins, exactly as Postgres resolves it.

    A `None` value means "set, but the value was not captured": the
    `pg_file_settings` fallback below cannot attribute a live
    `current_setting` to the server rather than to the introspecting role, so
    it reports only the fact, and the prover keeps such a GUC opaque.
    """
    cur.execute(_SET_GUCS_SQL)
    # Most specific tier wins, per (role, name): `ALTER ROLE x IN DATABASE d
    # SET` beats `ALTER ROLE x SET` beats `ALTER DATABASE d SET` beats `ALTER
    # ROLE ALL SET` — measured on PG16 by stripping one tier at a time and
    # re-reading `current_setting` as the role. Collapsing the tiers let the
    # lexicographically-last value win, so the prover could compare against a
    # string no session ever sees and prove isolation from it.
    best: dict[tuple[str | None, str], tuple[int, str]] = {}
    for r in cur.fetchall():
        key = (r["role"], r["name"])
        prior = best.get(key)
        if prior is None or r["tier"] > prior[0]:
            best[key] = (r["tier"], r["value"])
    db_level: dict[str, str | None] = {
        name: value for (role, name), (_t, value) in best.items() if role is None
    }
    role_level = {
        (role, name, value)
        for (role, name), (_t, value) in best.items()
        if role is not None
    }
    # Ask before reading rather than catching the failure: `introspect` runs on
    # autocommit connections too (the verdict corpus uses one), where a
    # SAVEPOINT is itself an error and could not be rolled back. Both the
    # view's ACL and the underlying set-returning function's EXECUTE are
    # checked: `GRANT SELECT ON pg_file_settings` alone still fails the read
    # with `permission denied for function pg_show_all_file_settings`, which
    # would abort the whole command.
    cur.execute(
        "SELECT pg_catalog.has_table_privilege("
        "'pg_catalog.pg_file_settings', 'SELECT') "
        "AND pg_catalog.has_function_privilege("
        "'pg_catalog.pg_show_all_file_settings()', 'EXECUTE') AS ok"
    )
    row = cur.fetchone()
    if row is not None and row["ok"]:
        cur.execute(_FILE_SET_GUCS_SQL)
        for r in cur.fetchall():
            db_level.setdefault(r["name"], r["setting"])
    # Then ask the session itself, ALWAYS — not only when the view was
    # unreadable: a GUC given on the postmaster command line is in no catalog
    # at all (measured on PG16). Only names no catalog explained are added,
    # and only as "set, value not captured", since this session's value may
    # be its own role's and is not attributable to an anonymous caller. That
    # can withhold a proof; it can never manufacture one.
    cur.execute("SELECT session_user AS me")
    me = cur.fetchone()["me"]
    own = {name for role, name, _v in role_level if role == me}
    cur.execute(_POLICY_GUC_NAMES_SQL)
    for name in [r["name"] for r in cur.fetchall()]:
        if name in db_level or name in own:
            continue
        cur.execute("SELECT current_setting(%s, true) AS v", (name,))
        got = cur.fetchone()
        if got is not None and got["v"] not in (None, ""):
            db_level[name] = None
    return tuple(sorted(db_level.items())), tuple(sorted(role_level))


def _fetch_role_memberships(cur: Any) -> tuple[RoleMembership, ...]:
    """Fetch every `pg_auth_members` edge as a (member, role) pair.

    Returns possibly `()` (a cluster with no non-default role grants) — which,
    unlike a `None` `Schema.role_memberships`, means "captured, and there are no
    memberships" so `verify --mode anon` can soundly conclude a non-anon policy
    is unreachable. The `None` default (offline/`--against`/hand-built Schema)
    means "not captured" → verify abstains instead.
    """
    cur.execute(_ROLE_MEMBERSHIPS_SQL)
    return tuple(
        RoleMembership(
            member=row["member"], role=row["role"], inherit=bool(row["inherit"])
        )
        for row in cur.fetchall()
    )


def _fetch_owner_reachable_members(
    cur: Any, schemas: list[str]
) -> tuple[OwnerReachableMember, ...]:
    """Fetch low-trust roles that can reach a non-FORCE'd table's owner.

    The SQL returns one (member, via_owner) row per reachable owner,
    ordered by member then owner. Group consecutive rows by member into
    one `OwnerReachableMember` each, preserving the owner ordering as the
    `via_owners` tuple (mirrors `_fetch_bypassrls_escalation_roles`).

    Takes the scanned `schemas` because the owner set is restricted to
    owners of enabled-not-forced RLS tables in those schemas; the
    membership closure over those owners is otherwise cluster-global.
    """
    cur.execute(_OWNER_REACHABLE_MEMBERS_SQL, [list(schemas)])
    by_member: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in cur.fetchall():
        member = row["member"]
        if member not in by_member:
            by_member[member] = {
                "via_owners": [],
                "can_login": row["member_can_login"],
            }
            order.append(member)
        by_member[member]["via_owners"].append(row["via_owner"])
    return tuple(
        OwnerReachableMember(
            member=member,
            via_owners=tuple(by_member[member]["via_owners"]),
            member_can_login=by_member[member]["can_login"],
        )
        for member in order
    )


def _fetch_leakproof_functions(
    cur: Any, schemas: list[str]
) -> tuple[LeakproofFunction, ...]:
    """Fetch every LEAKPROOF function in `schemas`.

    Returns a tuple of `LeakproofFunction` records sorted by
    `(qualified_name, signature)` (the SQL `ORDER BY qname,
    signature` provides the determinism). Since snapshot v12 each
    overload of the same qualified name is a separate entry so a
    SEC017 fixer can target each one with `ALTER FUNCTION
    name(<signature>) NOT LEAKPROOF`; SEC017 itself reports per
    qualified name (deduping across overloads) so the message
    surface is unchanged.
    """
    cur.execute(_LEAKPROOF_FUNCS_SQL, [list(schemas)])
    return tuple(
        LeakproofFunction(
            qualified_name=row["qname"],
            signature=row["signature"] or "",
            schema_name=row["schema_name"],
            function_name=row["function_name"],
        )
        for row in cur.fetchall()
    )


def _fetch_immutable_functions(
    cur: Any, schemas: list[str]
) -> tuple[ImmutableFunction, ...]:
    """Fetch every user-defined IMMUTABLE function in `schemas`.

    Returns a tuple of `ImmutableFunction` records sorted by
    `(qualified_name, signature)` (the SQL `ORDER BY` provides the
    determinism). Each overload is a separate entry; SEC046 reports per
    qualified name. The body (`prosrc`) and language (`lanname`) are captured
    so SEC046 can inspect the body for a session/identity or table read.
    """
    cur.execute(_IMMUTABLE_FUNCS_SQL, [list(schemas)])
    return tuple(
        ImmutableFunction(
            qualified_name=row["qname"],
            body=row["body"] or "",
            language=row["lang"],
        )
        for row in cur.fetchall()
    )


def _fetch_foreign_keys(
    cur: Any, table_oids: list[int]
) -> dict[int, list[ForeignKey]]:
    """Fetch FOREIGN KEY constraints, grouped per child table OID.

    Each `pg_constraint` row (contype='f') on a captured table becomes one
    `ForeignKey` on that child table, carrying its child columns (conkey
    order), the referenced parent schema/table (confrelid), and the parent
    columns (confkey order). Returns `{child_oid: [ForeignKey, ...]}`; a
    table with no foreign keys is simply absent from the dict (callers
    default to `()`). The SQL's `ORDER BY (conrelid, conname)` keeps each
    table's FK list sorted by constraint name for snapshot determinism.

    The parent is captured even when it lives outside `--schemas`; SEC047
    resolves it in the snapshot and abstains (fail-closed) when it can't.
    """
    cur.execute(_FOREIGN_KEYS_SQL, (table_oids,))
    by_oid: dict[int, list[ForeignKey]] = defaultdict(list)
    for row in cur.fetchall():
        by_oid[row["table_oid"]].append(
            ForeignKey(
                name=row["name"],
                columns=tuple(row["columns"]),
                ref_schema=row["ref_schema"],
                ref_table=row["ref_table"],
                ref_columns=tuple(row["ref_columns"]),
            )
        )
    return by_oid


def _fetch_default_privileges(
    cur: Any, schemas: list[str]
) -> tuple[DefaultPrivilege, ...]:
    """Fetch default privileges on TABLES from `pg_default_acl`.

    Returns one `DefaultPrivilege` per (schema, grantee, grantor) — privileges
    granted to the same grantee in the same scope by the same grantor are
    folded into a single record's `privileges` tuple. The grantor
    (`defaclrole`) is part of the entry's identity, so two defaults differing
    only by grantor stay distinct records. Schema-scoped entries are restricted
    to `schemas`; cluster-wide entries (`defaclnamespace = 0`, set without `IN
    SCHEMA`) are always captured and represented with `schema=None`, because
    they affect tables in every schema. SEC044 reads this.

    The SQL `ORDER BY schema_name, grantee, grantor, privilege_type` makes both
    the grouping iteration order and each record's `privileges` tuple
    deterministic across runs for byte-stable snapshots.
    """
    cur.execute(_DEFAULT_PRIVILEGES_SQL, [list(schemas)])
    # Group by (schema, grantee, grantor). The SQL renders a cluster-wide
    # entry's schema as NULL → psycopg surfaces it as None, which becomes
    # `DefaultPrivilege.schema = None`.
    acc: dict[tuple[str | None, str, str], list[str]] = defaultdict(list)
    order: list[tuple[str | None, str, str]] = []
    for row in cur.fetchall():
        key = (row["schema_name"], row["grantee"], row["grantor"])
        if key not in acc:
            order.append(key)
        acc[key].append(row["privilege_type"])
    return tuple(
        DefaultPrivilege(
            schema=schema,
            grantee=grantee,
            privileges=tuple(acc[(schema, grantee, grantor)]),
            grantor=grantor,
        )
        for (schema, grantee, grantor) in order
    )


def _build_secdef_calls_index(
    secdef_functions: tuple[SecdefFunction, ...],
    view_rows: list[dict[str, Any]],
) -> dict[tuple[str, str], tuple[str, ...]]:
    """For each view, return the sorted SECDEF function names it calls.

    Walks each view's `definition` via pglast to find `FuncCall` nodes
    whose names match the SECDEF set provided. `pg_get_viewdef` may emit
    either qualified (`public.read_secret`) or bare (`read_secret`)
    names depending on Postgres version + search_path, so we feed
    `find_func_calls` both forms and canonicalize matches back to the
    qualified name (the form VIEW004 messages with).
    """
    secdef_qnames: set[str] = {f.qualified_name for f in secdef_functions}
    if not secdef_qnames:
        return {}
    # Map bare last-segment back to its qualified form so a `read_secret()`
    # reference (no schema prefix in viewdef output) can be canonicalized
    # to `public.read_secret` for storage. Iterate `secdef_qnames` in
    # sorted order so the bare→qualified mapping is deterministic across
    # runs — set iteration order in CPython is hash-randomized for
    # strings, and snapshot v4 stores `security_definer_calls` as part
    # of the byte-stable Schema serialization, so non-deterministic
    # canonicalization would silently shuffle snapshots between runs.
    # If two SECDEF functions share the same bare name across schemas, a
    # bare `helper()` call in a view body could resolve to EITHER. Map each
    # bare name to ALL qualified SECDEF names that share it and feed every
    # candidate into the view's `security_definer_calls`, so VIEW004 parses
    # every possible body. This mirrors VIEW004's table-ref layer (which
    # over-reports all bare-name table candidates) and makes the same
    # choice: under-attribution here would be a SILENTLY MISSED leak — the
    # benign overload analyzed while the leaking one is skipped — which is
    # the worse failure for a security rule. `find_func_calls` still matches
    # a qualified call exactly when `pg_get_viewdef` emits it; the bare-name
    # expansion only ADDS candidates, never drops the exact match. Sorting
    # keeps the result byte-stable for the snapshot.
    bare_to_quals: dict[str, list[str]] = {}
    for q in sorted(secdef_qnames):
        bare_to_quals.setdefault(q.rsplit(".", 1)[-1], []).append(q)
    name_set = secdef_qnames | set(bare_to_quals.keys())

    out: dict[tuple[str, str], tuple[str, ...]] = {}
    for row in view_rows:
        key = (row["schema_name"], row["view_name"])
        try:
            parsed = pglast.parse_sql(row["definition"])
            if not parsed:
                out[key] = ()
                continue
            matches = find_func_calls(parsed[0].stmt, name_set)
        except pglast.parser.ParseError:
            # An unparseable view body is not a fatal error for
            # introspection — skip SECDEF detection for this view
            # (other rules still see its references / flags).
            out[key] = ()
            continue
        except RecursionError:
            # A pathologically deep view body (~1000+ nested calls)
            # parses fine in pglast's C parser but blows Python's
            # recursion limit inside the pure-Python find_func_calls
            # walk. RecursionError subclasses RuntimeError (not
            # ParseError), so without this guard it escapes introspect()
            # and crashes pgrls with a raw traceback instead of degrading
            # — and this path is reached on the common schema that has a
            # SECURITY DEFINER function. Skip SECDEF attribution for this
            # one view (mirrors the rule-time walk guard in
            # cli._run_rules) rather than aborting all introspection.
            # Under-attribution here means a possibly-missed VIEW004 leak
            # candidate; the view is named on stderr so the operator can
            # follow up.
            print(
                f"pgrls: warning: skipping SECURITY DEFINER call detection "
                f"for view {key[0]}.{key[1]}: body too deeply nested to "
                f"walk.",
                file=sys.stderr,
            )
            out[key] = ()
            continue
        found: set[str] = set()
        for m in matches:
            # `find_func_calls` may also return `SQLValueFunction`
            # nodes (e.g. `current_user`); those have no `funcname`
            # so they only land here if a SECDEF function happens to
            # share a grammar-special name. Skip them — VIEW004 only
            # cares about user-defined SECDEF refs.
            funcname = getattr(m, "funcname", None)
            if funcname is None:
                continue
            parts = [f.sval for f in funcname if hasattr(f, "sval")]
            if not parts:
                continue
            qualified = ".".join(parts)
            if qualified in secdef_qnames:
                found.add(qualified)
            elif len(parts) == 1:
                # Over-report ONLY for a genuinely UNQUALIFIED call: its
                # target depends on the runtime search_path, so feed ALL
                # SECDEF functions sharing the bare name to VIEW004 (the
                # leaking overload is never silently skipped — see the
                # bare_to_quals comment above).
                #
                # A QUALIFIED call (`other.read_secret()`) names exactly
                # one function with no search_path ambiguity. If that
                # exact qualified name is not a SECDEF function it is a
                # non-match and must be dropped — NOT expanded to a
                # same-bare-name SECDEF in another schema, which would
                # taint every view in the database calling any
                # `<schema>.read_secret()` (a false positive that also
                # persists into the snapshot's security_definer_calls).
                found.update(bare_to_quals.get(parts[-1], ()))
        out[key] = tuple(sorted(found))
    return out


def _resolve_view_base_tables(
    view_key: tuple[str, str],
    deps_index: dict[tuple[str, str], set[tuple[str, str]]],
    view_keys: set[tuple[str, str]],
) -> set[tuple[str, str]]:
    """The transitive base-table set a view reads, chasing view→view edges.

    `deps_index` maps each introspected view to its DIRECT dependency
    relations — tables AND other views (relkind v/m). A reference that is
    itself an introspected view is chased; anything else is a base table
    (or an out-of-scope relation we cannot resolve further) and is
    collected. So a `view → view → table` chain surfaces the underlying
    table in the outer view's references, which is what VIEW001/002/003 and
    the view fixer intersect against RLS-enabled tables. Postgres forbids
    circular view dependencies, but the `visited` guard keeps this
    terminating regardless.
    """
    tables: set[tuple[str, str]] = set()
    visited: set[tuple[str, str]] = set()
    stack = [view_key]
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        for ref in deps_index.get(current, set()):
            if ref in view_keys:
                stack.append(ref)
            else:
                tables.add(ref)
    return tables


def _build_views(
    cur: Any,
    schemas: list[str],
    secdef_functions: tuple[SecdefFunction, ...],
) -> tuple[View, ...]:
    """Build the `View` tuple for `schemas` from `pg_catalog`.

    Depends only on the schema list (not the introspected table OIDs):
    views are discovered by `_VIEWS_SQL`, their table references by
    `_VIEW_DEPS_SQL`, and their SECDEF-call attribution by matching the
    already-fetched `secdef_functions` against each view body. Shared by
    both `introspect` return paths (the no-tables early return and the
    main path) so the view-construction logic lives in one place.

    `secdef_functions` is passed in rather than re-fetched so the caller
    keeps a single `_fetch_secdef_functions` round trip per introspection
    (the same tuple also populates `Schema.security_definer_functions`).
    """
    cur.execute(_VIEWS_SQL, (schemas,))
    view_rows = cur.fetchall()
    deps_index: dict[tuple[str, str], set[tuple[str, str]]] = {}
    cur.execute(_VIEW_DEPS_SQL, [list(schemas)])
    for row in cur.fetchall():
        key = (row["view_schema"], row["view_name"])
        deps_index.setdefault(key, set()).add(
            (row["ref_schema"], row["ref_name"])
        )
    # `deps_index` now holds DIRECT edges to tables AND views. Collapse
    # view→view edges to the base tables the chain ultimately reads so
    # `references` stays "tables the view body reads" but is transitive —
    # a view built on another view no longer drops the underlying table.
    view_keys = {
        (row["schema_name"], row["view_name"]) for row in view_rows
    }
    secdef_index = _build_secdef_calls_index(secdef_functions, view_rows)
    # Per-view relacl grants (v23+), keyed by view OID. Fetched here so both
    # `introspect` paths (the no-tables early return and the main path) get
    # them without threading the table-grant map through.
    cur.execute(_VIEW_GRANTS_SQL, (schemas,))
    view_grants_acc: dict[int, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in cur.fetchall():
        view_grants_acc[row["view_oid"]][row["role_name"]].append(
            row["privilege_type"]
        )
    cur.execute(_VIEW_COLUMN_GRANTS_SQL, [list(schemas)])
    view_col_acc: dict[int, dict[tuple[str, str], list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in cur.fetchall():
        view_col_acc[row["view_oid"]][(row["role_name"], row["column_name"])].append(
            row["privilege_type"]
        )
    view_col_grants_by_oid: dict[int, tuple[ColumnGrant, ...]] = {
        oid: tuple(
            ColumnGrant(role=role, column=col, privileges=tuple(privs))
            for (role, col), privs in sorted(rolecol.items())
        )
        for oid, rolecol in view_col_acc.items()
    }
    view_grants_by_oid: dict[int, tuple[Grant, ...]] = {
        oid: tuple(
            Grant(role=role, privileges=tuple(privs))
            for role, privs in sorted(roles.items())
        )
        for oid, roles in view_grants_acc.items()
    }
    return tuple(
        View(
            schema=row["schema_name"],
            name=row["view_name"],
            is_materialized=row["is_materialized"],
            security_invoker=row["security_invoker"],
            security_barrier=row["security_barrier"],
            definition=row["definition"],
            references=tuple(sorted(
                _resolve_view_base_tables(
                    (row["schema_name"], row["view_name"]),
                    deps_index,
                    view_keys,
                )
            )),
            security_definer_calls=secdef_index.get(
                (row["schema_name"], row["view_name"]), ()
            ),
            grants=view_grants_by_oid.get(row["view_oid"], ()),
            column_grants=view_col_grants_by_oid.get(row["view_oid"], ()),
            owner=row["owner_name"] or "",
            owner_bypasses_rls=bool(row["owner_bypasses_rls"]),
            owner_is_superuser=bool(row["owner_is_superuser"]),
            # The un-collapsed edges (tables AND views) — the hops the
            # reachability walk needs; `references` above is the collapsed set.
            direct_references=tuple(
                sorted(deps_index.get((row["schema_name"], row["view_name"]), set()))
            ),
        )
        for row in view_rows
    )


def _fetch_foreign_tables(
    cur: Any, schemas: list[str]
) -> tuple[ForeignTable, ...]:
    """Build the `ForeignTable` tuple (relkind 'f' + relacl grants) for
    `schemas`. Depends only on the schema list, so it is shared by both
    `introspect` return paths (the no-tables early return and the main path).
    """
    cur.execute(_FOREIGN_TABLE_GRANTS_SQL, (schemas,))
    grants_acc: dict[int, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in cur.fetchall():
        grants_acc[row["ft_oid"]][row["role_name"]].append(
            row["privilege_type"]
        )
    grants_by_oid: dict[int, tuple[Grant, ...]] = {
        oid: tuple(
            Grant(role=role, privileges=tuple(privs))
            for role, privs in sorted(roles.items())
        )
        for oid, roles in grants_acc.items()
    }
    cur.execute(_FOREIGN_TABLES_SQL, (schemas,))
    return tuple(
        ForeignTable(
            schema=row["schema_name"],
            name=row["ft_name"],
            grants=grants_by_oid.get(row["ft_oid"], ()),
        )
        for row in cur.fetchall()
    )


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

        # Roles are cluster-global — fetch once here so both the
        # no-tables early return and the main path below see the
        # same set without re-querying. LEAKPROOF functions are
        # schema-scoped but likewise independent of the table set,
        # so fetch them here too and share across both paths.
        bypassrls_roles = _fetch_bypassrls_roles(cur)
        leakproof_funcs = _fetch_leakproof_functions(cur, schemas)
        bypassrls_escalation = _fetch_bypassrls_escalation_roles(cur)
        default_privileges = _fetch_default_privileges(cur, schemas)
        immutable_funcs = _fetch_immutable_functions(cur, schemas)
        # SEC048's owner-reachability closure is schema-scoped (its owner set
        # is restricted to enabled-not-forced RLS tables in `schemas`) but
        # independent of the per-table OID queries below, so fetch it here
        # alongside the other role/schema-scoped sets and share it across both
        # the no-tables early return and the main path.
        owner_reachable = _fetch_owner_reachable_members(cur, schemas)
        foreign_tables = _fetch_foreign_tables(cur, schemas)
        # The role-membership graph is cluster-global; captured live so
        # `verify --mode anon` can role-gate the anon prover soundly (a `None`
        # graph on an offline/snapshot Schema makes verify abstain instead).
        role_memberships = _fetch_role_memberships(cur)
        set_gucs, role_set_gucs = _fetch_set_gucs(cur)

        cur.execute(_TABLES_SQL, (schemas,))
        table_rows = cur.fetchall()
        if not table_rows:
            # No tables, but we still need to check for views and foreign tables.
            secdef_funcs = _fetch_secdef_functions(cur, schemas)
            views = _build_views(cur, schemas, secdef_funcs)
            return Schema(
                tables=(),
                views=views,
                security_definer_functions=secdef_funcs,
                bypassrls_roles=bypassrls_roles,
                leakproof_functions=leakproof_funcs,
                bypassrls_escalation_roles=bypassrls_escalation,
                default_privileges=default_privileges,
                immutable_functions=immutable_funcs,
                owner_reachable_members=owner_reachable,
                foreign_tables=foreign_tables,
                role_memberships=role_memberships,
                set_gucs=set_gucs,
                role_set_gucs=role_set_gucs,
            )

        oids = [row["table_oid"] for row in table_rows]
        cur.execute(_COLUMNS_SQL, (oids,))
        column_rows = cur.fetchall()
        cur.execute(_POLICIES_SQL, (oids,))
        policy_rows = cur.fetchall()
        cur.execute(_PARTITION_PARENTS_SQL, (oids,))
        partition_rows = cur.fetchall()
        cur.execute(_INHERITANCE_PARENTS_SQL, (oids,))
        inheritance_rows = cur.fetchall()
        cur.execute(_TRIGGERS_SQL, (oids,))
        trigger_rows = cur.fetchall()
        cur.execute(_INDEXES_SQL, (oids,))
        index_rows = cur.fetchall()
        foreign_keys_by_oid = _fetch_foreign_keys(cur, oids)
        cur.execute(_GRANTS_SQL, (schemas,))
        grants_by_oid: dict[int, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for row in cur.fetchall():
            grants_by_oid[row["table_oid"]][row["role_name"]].append(
                row["privilege_type"]
            )

        # Column-level grants (pg_attribute.attacl), grouped per
        # (role, column) so each column grant is one ColumnGrant.
        cur.execute(_COLUMN_GRANTS_SQL, (schemas,))
        col_grants_acc: dict[
            int, dict[tuple[str, str], list[str]]
        ] = defaultdict(lambda: defaultdict(list))
        for row in cur.fetchall():
            col_grants_acc[row["table_oid"]][
                (row["role_name"], row["column_name"])
            ].append(row["privilege_type"])
        column_grants_by_oid: dict[int, list[ColumnGrant]] = {
            oid: [
                ColumnGrant(
                    role=role, column=col, privileges=tuple(privs)
                )
                for (role, col), privs in sorted(rolecol.items())
            ]
            for oid, rolecol in col_grants_acc.items()
        }

        # Publication memberships (resolved via `pg_publication_tables`) per
        # table, keyed by (schema, name) since the view reports names — read by
        # SEC051. A table in no publication is simply absent from the map.
        cur.execute(_PUBLICATION_MEMBERSHIP_SQL, (schemas,))
        publications_by_qname: dict[tuple[str, str], tuple[str, ...]] = {
            (row["schema_name"], row["table_name"]): tuple(row["publications"])
            for row in cur.fetchall()
        }

        secdef_funcs = _fetch_secdef_functions(cur, schemas)
        views = _build_views(cur, schemas, secdef_funcs)

    columns_by_oid: dict[int, list[str]] = defaultdict(list)
    column_details_by_oid: dict[int, list[Column]] = defaultdict(list)
    for row in column_rows:
        columns_by_oid[row["table_oid"]].append(row["column_name"])
        column_details_by_oid[row["table_oid"]].append(
            Column(
                name=row["column_name"],
                data_type=row["data_type"],
                is_nullable=row["is_nullable"],
            )
        )

    partition_parent_by_oid: dict[int, tuple[str, str]] = {
        row["child_oid"]: (row["parent_schema"], row["parent_name"])
        for row in partition_rows
    }

    # Classic-`INHERITS` parents — aggregated per child because a child may
    # inherit from MULTIPLE parents (a DAG). Sort each child's parent list so
    # the snapshot is deterministic regardless of `pg_inherits` row order.
    inherits_acc: dict[int, set[tuple[str, str]]] = defaultdict(set)
    for row in inheritance_rows:
        inherits_acc[row["child_oid"]].add(
            (row["parent_schema"], row["parent_name"])
        )
    inherits_by_oid: dict[int, tuple[tuple[str, str], ...]] = {
        oid: tuple(sorted(parents)) for oid, parents in inherits_acc.items()
    }

    indexes_by_oid: dict[int, list[Index]] = defaultdict(list)
    for row in index_rows:
        indexes_by_oid[row["table_oid"]].append(
            Index(
                name=row["index_name"],
                access_method=row["access_method"],
                # Each column-name comes from the LEFT JOIN to
                # pg_attribute. Expression positions (where attnum
                # was 0) yielded empty strings in the array via
                # the COALESCE in the SQL. The conversion to tuple
                # here preserves positional alignment for any
                # future caller that wants to correlate the
                # `columns` tuple back to `indkey`.
                columns=tuple(row["columns"]),
                is_unique=row["is_unique"],
                is_partial=row["is_partial"],
                is_primary=row["is_primary"],
            )
        )

    triggers_by_oid: dict[int, list[Trigger]] = defaultdict(list)
    for row in trigger_rows:
        # `event` must be a non-empty string: `pg_trigger.tgtype`
        # always has at least one of INSERT / DELETE / UPDATE /
        # TRUNCATE set, and the CASE chain in `_TRIGGERS_SQL` covers
        # all four. If a future Postgres adds a fifth event bit
        # pgrls doesn't recognize, every CASE arm produces NULL and
        # `array_remove(..., NULL)` empties the array — but
        # `array_to_string([], ' OR ')` yields the EMPTY STRING, not
        # NULL. Guard on falsiness (catches both '' and None) so the
        # documented failsafe actually fires; otherwise a future event
        # bit would silently produce a malformed "(BEFORE )" message.
        # Matches the `polcmd` unknown-value handling below.
        if not row["event"]:
            raise RuntimeError(
                f"Unknown pg_trigger.tgtype event bits for trigger "
                f"{row['trigger_name']!r} (table OID "
                f"{row['table_oid']}). The introspection query's "
                "INSERT/DELETE/UPDATE/TRUNCATE bit decode produced "
                "no event names — likely a new Postgres version "
                "with an event bit pgrls hasn't been taught about. "
                "Please open an issue at "
                "https://github.com/pgrls/pgrls/issues."
            )
        triggers_by_oid[row["table_oid"]].append(
            Trigger(
                name=row["trigger_name"],
                function_schema=row["function_schema"],
                function_name=row["function_name"],
                event=row["event"],
                timing=row["timing"],
                enabled=row["enabled"],
            )
        )

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
            inherits=inherits_by_oid.get(row["table_oid"], ()),
            in_publications=publications_by_qname.get(
                (row["schema_name"], row["table_name"]), ()
            ),
            grants=tuple(
                Grant(role=role, privileges=tuple(privileges))
                for role, privileges in sorted(
                    grants_by_oid.get(row["table_oid"], {}).items()
                )
            ),
            column_details=tuple(
                column_details_by_oid.get(row["table_oid"], [])
            ),
            triggers=tuple(triggers_by_oid.get(row["table_oid"], [])),
            indexes=tuple(indexes_by_oid.get(row["table_oid"], [])),
            column_grants=tuple(
                column_grants_by_oid.get(row["table_oid"], [])
            ),
            foreign_keys=tuple(
                foreign_keys_by_oid.get(row["table_oid"], [])
            ),
            owner=row["owner_name"],
        )
        for row in table_rows
    ]

    return Schema(
        tables=tuple(tables),
        views=views,
        security_definer_functions=secdef_funcs,
        bypassrls_roles=bypassrls_roles,
        leakproof_functions=leakproof_funcs,
        bypassrls_escalation_roles=bypassrls_escalation,
        default_privileges=default_privileges,
        immutable_functions=immutable_funcs,
        owner_reachable_members=owner_reachable,
        foreign_tables=foreign_tables,
        role_memberships=role_memberships,
        set_gucs=set_gucs,
        role_set_gucs=role_set_gucs,
    )
