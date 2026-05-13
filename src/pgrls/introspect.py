"""Read RLS-relevant state from `pg_catalog` into a normalized Schema."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, cast

import pglast
import psycopg
from psycopg.rows import dict_row

from pgrls.ast_utils import find_func_calls, parse_expr
from pgrls.model import (
    Column,
    Grant,
    Index,
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
    COALESCE(
        ARRAY(
            SELECT COALESCE(a.attname, '')
            FROM unnest(i.indkey::int[]) WITH ORDINALITY AS k(attnum, ord)
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
    p.prosrc AS body,
    l.lanname AS lang
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid = p.prolang
WHERE p.prosecdef = TRUE
  AND n.nspname = ANY(%s)
ORDER BY qname
"""


def _fetch_secdef_functions(
    cur: Any, schemas: list[str]
) -> tuple[SecdefFunction, ...]:
    """Fetch every SECURITY DEFINER function in `schemas` with body + lang.

    Returns a tuple of `SecdefFunction` records sorted by qualified name
    (the SQL `ORDER BY qname` provides the determinism). Used by both
    the introspect `Schema.security_definer_functions` field and the
    bare-call detection in `_build_secdef_calls_index` — sharing the
    fetch lets both consumers see the same set without an extra round
    trip.
    """
    cur.execute(_SECDEF_FUNCS_SQL, [list(schemas)])
    return tuple(
        SecdefFunction(
            qualified_name=row["qname"],
            body=row["body"],
            language=row["lang"],
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
    # If two SECDEF functions share the same bare name across schemas,
    # `setdefault` keeps the alphabetically-first qualified form. This
    # is a best-effort attribution path: `find_func_calls` still
    # matches the qualified form exactly when `pg_get_viewdef` emits
    # it, and the bare-only fallback is rare in practice (most viewdef
    # output qualifies cross-schema function calls). VIEW004 takes a
    # different tack at the *table*-ref layer — when a bare table name
    # in a function body could resolve to multiple RLS-protected
    # tables, it over-reports all candidates rather than picking one —
    # because the rule's user-facing message is what surfaces the
    # leak, and under-attribution there would be silently insecure.
    # The two layers (function-name canonicalization here, table-name
    # over-reporting in VIEW004) chose opposite trade-offs based on
    # what failure mode hurts the user most.
    bare_to_qual: dict[str, str] = {}
    for q in sorted(secdef_qnames):
        bare_to_qual.setdefault(q.rsplit(".", 1)[-1], q)
    name_set = secdef_qnames | set(bare_to_qual.keys())

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
            else:
                bare = parts[-1]
                if bare in bare_to_qual:
                    found.add(bare_to_qual[bare])
        out[key] = tuple(sorted(found))
    return out


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
            secdef_funcs_early = _fetch_secdef_functions(cur, schemas)
            secdef_index_early = _build_secdef_calls_index(
                secdef_funcs_early, view_rows_early
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
                    security_definer_calls=secdef_index_early.get(
                        (row["schema_name"], row["view_name"]), ()
                    ),
                )
                for row in view_rows_early
            )
            return Schema(
                tables=(),
                views=views_early,
                security_definer_functions=secdef_funcs_early,
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

        cur.execute(_VIEWS_SQL, (schemas,))
        view_rows = cur.fetchall()
        deps_index: dict[tuple[str, str], set[tuple[str, str]]] = {}
        cur.execute(_VIEW_DEPS_SQL, [list(schemas)])
        for row in cur.fetchall():
            key = (row["view_schema"], row["view_name"])
            deps_index.setdefault(key, set()).add(
                (row["ref_schema"], row["ref_name"])
            )
        secdef_funcs = _fetch_secdef_functions(cur, schemas)
        secdef_index = _build_secdef_calls_index(secdef_funcs, view_rows)

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
            )
        )

    triggers_by_oid: dict[int, list[Trigger]] = defaultdict(list)
    for row in trigger_rows:
        # `event` must be a non-empty string: `pg_trigger.tgtype`
        # always has at least one of INSERT / DELETE / UPDATE /
        # TRUNCATE set, and the CASE chain in `_TRIGGERS_SQL` covers
        # all four. If a future Postgres adds a fifth event bit
        # pgrls doesn't recognize, every CASE arm produces NULL,
        # `array_remove(..., NULL)` empties the array, and
        # `array_to_string([], ' OR ')` yields NULL. Raise loudly so
        # the operator files a bug rather than seeing a malformed
        # "(BEFORE )" message that's easy to misread. Matches the
        # `polcmd` unknown-value handling below.
        if row["event"] is None:
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
            security_definer_calls=secdef_index.get(
                (row["schema_name"], row["view_name"]), ()
            ),
        )
        for row in view_rows
    )

    return Schema(
        tables=tuple(tables),
        views=views,
        security_definer_functions=secdef_funcs,
    )
