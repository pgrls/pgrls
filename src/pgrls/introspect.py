"""Read RLS-relevant state from `pg_catalog` into a normalized Schema."""
from __future__ import annotations

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
    Grant,
    Index,
    LeakproofFunction,
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
SELECT
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
_SECDEF_FUNCS_SQL = """
SELECT
    n.nspname || '.' || p.proname AS qname,
    n.nspname AS schema_name,
    p.proname AS function_name,
    p.prosrc AS body,
    l.lanname AS lang,
    p.proconfig AS config,
    pg_catalog.pg_get_function_identity_arguments(p.oid) AS signature
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid = p.prolang
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
    parsing) and `search_path` (for SEC015's pg_temp-shadowing
    check, decoded from `pg_proc.proconfig`).
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
        except pglast.parser.ParseError:
            # An unparseable view body is not a fatal error for
            # introspection — skip SECDEF detection for this view
            # (other rules still see its references / flags).
            out[key] = ()
            continue
        if not parsed:
            out[key] = ()
            continue
        matches = find_func_calls(parsed[0].stmt, name_set)
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
        )
        for row in view_rows
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

        cur.execute(_TABLES_SQL, (schemas,))
        table_rows = cur.fetchall()
        if not table_rows:
            # No tables, but we still need to check for views.
            secdef_funcs = _fetch_secdef_functions(cur, schemas)
            views = _build_views(cur, schemas, secdef_funcs)
            return Schema(
                tables=(),
                views=views,
                security_definer_functions=secdef_funcs,
                bypassrls_roles=bypassrls_roles,
                leakproof_functions=leakproof_funcs,
                bypassrls_escalation_roles=bypassrls_escalation,
            )

        oids = [row["table_oid"] for row in table_rows]
        cur.execute(_COLUMNS_SQL, (oids,))
        column_rows = cur.fetchall()
        cur.execute(_POLICIES_SQL, (oids,))
        policy_rows = cur.fetchall()
        cur.execute(_PARTITION_PARENTS_SQL, (oids,))
        partition_rows = cur.fetchall()
        cur.execute(_TRIGGERS_SQL, (oids,))
        trigger_rows = cur.fetchall()
        cur.execute(_INDEXES_SQL, (oids,))
        index_rows = cur.fetchall()
        cur.execute(_GRANTS_SQL, (schemas,))
        grants_by_oid: dict[int, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for row in cur.fetchall():
            grants_by_oid[row["table_oid"]][row["role_name"]].append(
                row["privilege_type"]
            )

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
    )
