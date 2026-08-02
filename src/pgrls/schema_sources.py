"""Resolve a `pgrls.model.Schema` from one of three sources (sql / database_url / snapshot).

This module is the FastMCP-agnostic schema-resolution core shared by the CLI
(`pgrls lint/fix/generate --sql-file/--snapshot`) and the MCP server; it has
NO dependency on the `fastmcp` extra.

Three sources, EXACTLY ONE per call (`resolve_schema` enforces this):

* ``database_url`` — connect read-only, introspect, close. Mirrors
  `cli._connect_and_introspect`. Any psycopg error is sanitized so the DSN /
  credentials never leak into the message returned to the agent.
* ``snapshot`` — a `pgrls snapshot` JSON path. Loaded via
  `Schema.from_snapshot`, then each policy's USING / WITH CHECK is **re-parsed**
  into `using_ast` / `with_check_ast`: a snapshot serializes only
  `using_sql` / `with_check_sql` (see `model.from_snapshot`'s docstring), so
  without the re-parse `verify` would return all-``unverified``. This mirrors
  the on-demand re-parse `diff/columns.py` already does.
* ``sql`` — the NEW offline path (`schema_from_sql`): parse raw DDL with
  `pglast` and build a `Schema` directly, no database. THE crux of the server.

Correctness posture (the dangerous direction): a ``sql=`` input that parses but
yields an *empty or wrong* Schema would make `lint` return "no findings" and
falsely reassure the agent. `schema_from_sql` is therefore deliberately
faithful, and `schema_source_warnings` surfaces the catalog-only rules that are
structurally inert on a `sql=`-built schema — so the server can tell the agent
that absence-of-finding is NOT proof.
"""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Literal

import pglast
import pglast.parser
from pglast import ast as _pgast
from pglast.enums.parsenodes import (
    A_Expr_Kind,
    AlterTableType,
    ConstrType,
    GrantTargetType,
    ObjectType,
    RoleSpecType,
)
from pglast.stream import RawStream

from pgrls import ast_utils
from pgrls.model import (
    SNAPSHOT_VERSION,
    Column,
    ColumnGrant,
    Grant,
    Policy,
    Schema,
    Table,
)

SchemaSource = Literal["sql", "database_url", "snapshot"]


class SchemaSourceError(Exception):
    """A typed error from `resolve_schema` / `schema_from_sql`.

    `kind` is one of the stable structured-error kinds the MCP tools surface to
    the agent (`bad_sql`, `db_unreachable`, `no_schema_source`,
    `multiple_schema_sources`). The server maps this straight onto the
    `{"error": {"kind": ..., "message": ...}}` response shape.
    """

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


# pglast's `cmd_name` on a CreatePolicyStmt is the lowercased command word
# ("select"/"insert"/"update"/"delete"/"all") — the offline analog of
# `introspect._POLICY_CMD_MAP` (which maps `pg_policy.polcmd`'s single letters).
# An omitted `FOR` clause parses as "all" (Postgres's default), matching the
# `*` → "ALL" introspect mapping.
_POLICY_CMD_WORD_MAP: dict[str, str] = {
    "all": "ALL",
    "select": "SELECT",
    "insert": "INSERT",
    "update": "UPDATE",
    "delete": "DELETE",
}

# `GRANT ALL ON <table>` carries an empty privileges list in the AST; expand it
# to the privilege set `aclexplode` would materialize on a live database so the
# GRANT-dependent rules (SEC041 / SEC045 / SEC047) see the real grant. MAINTAIN
# (PG17+) is omitted to match the canonical pre-17 `GRANT ALL` expansion; the
# rules test membership, so an over- vs under-expansion here only ever makes a
# write/content privilege *more* visible, never hides one.
_GRANT_ALL_PRIVILEGES: tuple[str, ...] = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)

# `GRANT ALL (col) ON <table>` grants every *column*-applicable privilege on
# that column. Postgres column ACLs only carry SELECT / INSERT / UPDATE /
# REFERENCES, so that is the expansion (the analog of `_GRANT_ALL_PRIVILEGES`
# for the column-level path).
_COLUMN_GRANT_ALL_PRIVILEGES: tuple[str, ...] = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "REFERENCES",
)


def _normalize_in_membership(node: Any) -> Any:
    """Rewrite ``x IN (...)`` / ``x NOT IN (...)`` to the canonical form
    Postgres's ``pg_get_expr`` emits, in place, recursively.

    Introspection feeds the rules and the Z3 encoder predicates as rendered by
    ``pg_get_expr``, which normalizes a value-list membership test to ``x = v``
    (single) / ``x = ANY (ARRAY[...])`` (multi) — and the negated forms to
    ``x <> v`` / ``x <> ALL (ARRAY[...])``. The rules/encoder only recognize
    *those* shapes; a raw ``A_Expr(AEXPR_IN)`` (which the offline ``sql=`` parse
    preserves, the one place ``pg_get_expr`` never runs) would be missed —
    making `verify` under-claim (``unverified`` instead of ``leak``) and
    silencing SEC038 on the flagship anon-read shape. Normalizing here keeps the
    offline path faithful to a live database.
    """
    if node is None or isinstance(node, (str, int, float, bool)):
        return node
    if isinstance(node, (list, tuple)):
        for item in node:
            _normalize_in_membership(item)
        return node
    if isinstance(node, _pgast.Node):
        for field_name in node:
            _normalize_in_membership(getattr(node, field_name, None))
        if (
            isinstance(node, _pgast.A_Expr)
            and node.kind == A_Expr_Kind.AEXPR_IN
            and isinstance(node.rexpr, (list, tuple))
        ):
            elems = list(node.rexpr)
            negated = bool(node.name) and node.name[0].sval == "<>"
            if len(elems) == 1:
                node.kind = A_Expr_Kind.AEXPR_OP
                node.rexpr = elems[0]
            else:
                node.kind = (
                    A_Expr_Kind.AEXPR_OP_ALL
                    if negated
                    else A_Expr_Kind.AEXPR_OP_ANY
                )
                node.rexpr = _pgast.A_ArrayExpr(elements=tuple(elems))
    return node


def _parse_clause(sql_text: str, *, location: str, clause: str) -> Any:
    """Parse a policy USING / WITH CHECK fragment, normalizing ``IN`` membership
    to the introspect-canonical form so the offline `sql=` AST matches a live
    DB's (see `_normalize_in_membership`)."""
    expr = ast_utils.parse_expr(sql_text, location=location, clause=clause)
    return _normalize_in_membership(expr)


def resolve_schema(
    *,
    sql: str | None = None,
    database_url: str | None = None,
    snapshot: str | None = None,
    schemas: tuple[str, ...] | None = None,
) -> tuple[Schema, SchemaSource, int | None]:
    """Build a `Schema` from EXACTLY ONE of `sql` / `database_url` / `snapshot`.

    Returns `(schema, source, snapshot_version)`. `source` is the kind that was
    used (for the `schema_source` field the tools echo back). `snapshot_version`
    is the declared format version of a `snapshot` source (which `inert_rule_ids`
    uses to decide which catalog-only rules that snapshot can run), or `None` for
    the `sql` / `database_url` sources. Raises `SchemaSourceError` with a
    structured `kind` on zero sources (`no_schema_source`), more than one
    (`multiple_schema_sources`), a pglast parse failure (`bad_sql`), or a
    database error (`db_unreachable`, sanitized).

    `schemas` applies to the `database_url` (which schemas to introspect) and
    `sql` (which schema an unqualified relation defaults into) paths; it is
    ignored for `snapshot` (a snapshot already pins its captured schemas).
    Defaults to `("public",)`.
    """
    provided = [
        name
        for name, value in (
            ("sql", sql),
            ("database_url", database_url),
            ("snapshot", snapshot),
        )
        if value is not None
    ]
    if not provided:
        raise SchemaSourceError(
            "no_schema_source",
            "exactly one schema source is required: pass `sql` (raw DDL to "
            "analyze offline), `database_url` (a live Postgres connection), or "
            "`snapshot` (a path to a pgrls snapshot JSON).",
        )
    if len(provided) > 1:
        raise SchemaSourceError(
            "multiple_schema_sources",
            "exactly one schema source is allowed, but "
            f"{', '.join(provided)} were all given. Pass only one of `sql`, "
            "`database_url`, or `snapshot`.",
        )

    effective_schemas = schemas if schemas else ("public",)

    if sql is not None:
        return schema_from_sql(sql, schemas=effective_schemas), "sql", None
    if snapshot is not None:
        return _schema_from_snapshot(snapshot)
    assert database_url is not None  # guaranteed by the guards above
    return (
        _schema_from_database(database_url, effective_schemas),
        "database_url",
        None,
    )


def _schema_from_database(database_url: str, schemas: tuple[str, ...]) -> Schema:
    """Connect read-only, introspect, close. Mirrors `cli._connect_and_introspect`.

    The connection is short-lived and issues only SELECTs (`introspect` reads
    the catalogs). On any psycopg error the message is sanitized — the
    connection string can embed credentials, so the raw error (which may echo
    the DSN) is never returned to the agent.
    """
    # psycopg is imported lazily so a `sql=` / `snapshot=` call never pays for
    # the driver import — and so this module imports cleanly even where psycopg
    # is unavailable.
    import psycopg

    from pgrls.introspect import introspect

    try:
        with psycopg.connect(database_url) as conn:
            return introspect(conn, schemas=list(schemas))
    except psycopg.Error as exc:
        # NEVER include `exc` verbatim or `database_url` — either can leak
        # credentials. Surface only the exception class name.
        raise SchemaSourceError(
            "db_unreachable",
            "could not introspect the database "
            f"({type(exc).__name__}). Check the connection and that the role "
            "can read the catalogs. (Connection details are withheld so "
            "credentials are not echoed.)",
        ) from exc
    except ValueError as exc:
        # e.g. a reserved schema name passed in `schemas`. Safe to surface.
        raise SchemaSourceError("db_unreachable", str(exc)) from exc


def _schema_from_snapshot(
    snapshot_path: str,
) -> tuple[Schema, SchemaSource, int | None]:
    """Load a snapshot JSON and rebuild policy ASTs so `verify` works.

    Returns `(schema, source, version)`, matching `resolve_schema`'s shape.

    A snapshot built offline from DDL (`snapshot --sql-file`) carries a
    `"source": "sql"` provenance marker. It is stamped at the current format
    version with empty catalog arrays — `schema_from_sql` can't express
    indexes, roles, function bodies, foreign keys — so by version alone it is
    indistinguishable from a live-database capture. Resolve it back to the
    `sql` source so every catalog-dependent rule is treated as inert
    downstream (`lint --snapshot`, `pgrls pr`, MCP): the same protection
    `lint --sql-file` gets, so an offline run never reads a silent catalog-rule
    no-op as coverage. Any other marker (or none) is a full capture →
    `snapshot`, whose `version` `inert_rule_ids` uses to decide which
    catalog-only rules that snapshot is new enough to run.

    `Schema.from_snapshot` leaves `using_ast` / `with_check_ast` as `None`
    (snapshots serialize only the SQL). `verify` reads the ASTs, so without this
    re-parse every table comes back `unverified`. Re-parse each policy's
    USING / WITH CHECK via `ast_utils.parse_expr` — the same on-demand parse
    `diff/columns.py` does for snapshot-fed diffs.
    """
    try:
        with open(snapshot_path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError as exc:
        raise SchemaSourceError(
            "bad_sql",
            f"snapshot file not found: {snapshot_path!r}.",
        ) from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise SchemaSourceError(
            "bad_sql",
            f"could not read snapshot {snapshot_path!r}: {exc}.",
        ) from exc

    try:
        schema = Schema.from_snapshot(payload)
    except (ValueError, KeyError, TypeError) as exc:
        raise SchemaSourceError(
            "bad_sql",
            f"{snapshot_path!r} is not a valid pgrls snapshot: {exc}.",
        ) from exc

    # `from_snapshot` accepted the payload, so `version` is a supported int.
    if payload.get("source") == "sql":
        # Offline-built: resolve to `sql` (catalog rules inert). The `sql`
        # source is version-independent, so pair it with `None` like every
        # other `sql` resolution.
        return reparse_policy_asts(schema), "sql", None
    return reparse_policy_asts(schema), "snapshot", int(payload["version"])


def reparse_policy_asts(schema: Schema) -> Schema:
    """Return a copy of `schema` with every policy's USING / WITH CHECK parsed.

    Tables (and the Schema) are frozen dataclasses, so this rebuilds via
    `dataclasses.replace`. Policies that already carry ASTs (e.g. a Schema not
    from a snapshot) are passed through untouched.
    """
    new_tables: list[Table] = []
    for table in schema.tables:
        new_policies: list[Policy] = []
        rebuilt = False
        for policy in table.policies:
            using_ast = policy.using_ast
            check_ast = policy.with_check_ast
            if using_ast is None and policy.using_sql:
                using_ast = _parse_clause(
                    policy.using_sql,
                    location=f"{table.qualified_name}.{policy.name}",
                    clause="USING",
                )
            if check_ast is None and policy.with_check_sql:
                check_ast = _parse_clause(
                    policy.with_check_sql,
                    location=f"{table.qualified_name}.{policy.name}",
                    clause="WITH CHECK",
                )
            if using_ast is not policy.using_ast or check_ast is not policy.with_check_ast:
                new_policies.append(
                    replace(policy, using_ast=using_ast, with_check_ast=check_ast)
                )
                rebuilt = True
            else:
                new_policies.append(policy)
        if rebuilt:
            new_tables.append(replace(table, policies=tuple(new_policies)))
        else:
            new_tables.append(table)
    return replace(schema, tables=tuple(new_tables))


def schema_from_sql(sql: str, schemas: tuple[str, ...] = ("public",)) -> Schema:
    """Build a `Schema` from raw DDL — the offline analysis path. THE crux.

    Parses `sql` with `pglast` and walks the statements TOLERANTLY: any
    statement shape this builder doesn't model (functions, views, indexes, FKs,
    roles, ALTER DEFAULT PRIVILEGES, …) is silently skipped. The ONLY thing that
    raises is a pglast `ParseError` on the whole input — surfaced as a
    `bad_sql` `SchemaSourceError` so the agent learns its DDL didn't parse
    rather than receiving a falsely-clean "no findings".

    What IS modeled:

    * ``CREATE TABLE`` → a `Table` with `Column`s (name + Postgres data type).
      An unqualified relation defaults to the first entry in `schemas`
      (``public`` by default), keyed on ``(schema, name)``.
    * ``ALTER TABLE … ENABLE / FORCE ROW LEVEL SECURITY`` → sets the table's
      `rls_enabled` / `force_rls`.
    * ``CREATE POLICY`` → a `Policy` (name, command, permissive vs
      ``AS RESTRICTIVE``, ``TO`` roles, and USING / WITH CHECK parsed into the
      ASTs `verify` and the AST rules need).
    * ``ALTER POLICY`` → updates the named policy's USING / WITH CHECK / roles
      in place (a later ``ALTER POLICY … USING (true)`` loosening is honored,
      not read as the policy's pre-ALTER form).
    * ``DROP POLICY`` / ``DROP TABLE`` → removes the policy / table from the
      model, so a dropped RLS guard is reflected. Statements replay in source
      order.
    * ``GRANT <privs> ON <table> TO <roles>`` → a `Grant` so the
      GRANT-dependent rules fire.

    What is intentionally absent (the documented v1 scope): anything the offline
    AST cannot express — BYPASSRLS roles, `pg_default_acl`, SECURITY DEFINER
    function owners, foreign keys, indexes, triggers. The catalog-only rules
    that read those fields fail closed on the missing data and abstain quietly;
    `schema_source_warnings` names them so the caller doesn't mistake their
    silence for a clean bill of health.
    """
    try:
        statements = pglast.parse_sql(sql)
    except pglast.parser.ParseError as exc:
        raise SchemaSourceError(
            "bad_sql",
            f"could not parse the provided SQL: {exc}.",
        ) from exc

    default_schema = schemas[0] if schemas else "public"

    # Build tables first (CREATE TABLE), then layer ALTER / CREATE POLICY /
    # GRANT onto them, so a policy or grant that precedes its table in the input
    # still attaches. Two passes keep that order-independent.
    tables: dict[tuple[str, str], _TableBuilder] = {}

    # Pass 1: CREATE TABLE.
    for raw in statements:
        stmt = raw.stmt
        if type(stmt).__name__ != "CreateStmt":
            continue
        key = _relation_key(stmt.relation, default_schema)
        if key is None:
            continue
        if key in tables:
            # A second CREATE for the same relation: either `IF NOT EXISTS`
            # (a no-op in Postgres) or DDL that would error outright. Either
            # way the first definition stands — re-walking `tableElts` here
            # would append the columns a second time and hand every
            # column-keyed rule a duplicated list.
            continue
        builder = _TableBuilder(schema=key[0], name=key[1])
        tables[key] = builder
        # Declarative partition child (`PARTITION OF parent`) and classic
        # `INHERITS (...)` children both arrive as `inhRelations`; the
        # `partbound` clause is what distinguishes them. The model keeps them
        # in separate fields because SEC001/SEC041/SEC043 branch on which
        # kind of parent a table has.
        parents = [
            p
            for p in (
                _relation_key(rel, default_schema)
                for rel in (stmt.inhRelations or ())
            )
            if p is not None
        ]
        if parents and getattr(stmt, "partbound", None) is not None:
            builder.partition_of = parents[0]
        elif parents:
            builder.inherits = parents
        # A child's columns come from its parent(s): `PARTITION OF` copies them
        # wholesale (and forbids declaring more), `INHERITS` copies them and
        # allows extras. Valid DDL defines the parent first, so its builder is
        # already populated. Without this a partition child modelled offline
        # has zero columns and every column-keyed rule silently skips it.
        for parent_key in parents:
            parent = tables.get(parent_key)
            if parent is None:
                continue
            for col in parent.columns:
                if not any(c.name == col.name for c in builder.columns):
                    builder.columns.append(col)
        for elt in stmt.tableElts or ():
            if type(elt).__name__ != "ColumnDef":
                continue
            colname = elt.colname
            data_type = _column_type(elt)
            if colname and data_type:
                builder.columns.append(
                    Column(
                        name=colname,
                        data_type=data_type,
                        is_nullable=not _column_def_is_not_null(elt),
                    )
                )
        # A table-level `PRIMARY KEY (a, b)` constraint makes its columns NOT
        # NULL just as an inline `PRIMARY KEY` does.
        for pk_col in _table_constraint_pk_columns(stmt):
            builder.set_not_null(pk_col)

    # Pass 2: ALTER TABLE (RLS toggles), CREATE POLICY, GRANT, RENAME.
    for raw in statements:
        stmt = raw.stmt
        kind = type(stmt).__name__
        if kind == "AlterTableStmt":
            _apply_alter_table(stmt, tables, default_schema)
        elif kind == "CreatePolicyStmt":
            _apply_create_policy(stmt, tables, default_schema)
        elif kind == "AlterPolicyStmt":
            _apply_alter_policy(stmt, tables, default_schema)
        elif kind == "DropStmt":
            _apply_drop(stmt, tables, default_schema)
        elif kind == "GrantStmt":
            _apply_grant(stmt, tables, default_schema)
        elif kind == "RenameStmt":
            _apply_rename(stmt, tables, default_schema)
        # Every other statement shape is skipped tolerantly.

    return Schema(tables=tuple(b.build() for b in tables.values()))


class _TableBuilder:
    """Mutable accumulator for one table while walking the DDL statements."""

    def __init__(self, *, schema: str, name: str) -> None:
        self.schema = schema
        self.name = name
        self.rls_enabled = False
        self.force_rls = False
        self.columns: list[Column] = []
        self.policies: list[Policy] = []
        self.grants: list[Grant] = []
        self.column_grants: list[ColumnGrant] = []
        self.partition_of: tuple[str, str] | None = None
        self.inherits: list[tuple[str, str]] = []

    def set_not_null(self, colname: str, *, not_null: bool = True) -> None:
        """Flip one column's nullability in place (`SET`/`DROP NOT NULL`)."""
        for i, col in enumerate(self.columns):
            if col.name == colname:
                self.columns[i] = replace(col, is_nullable=not not_null)
                return

    def drop_column(self, colname: str) -> None:
        self.columns = [c for c in self.columns if c.name != colname]

    def build(self) -> Table:
        return Table(
            schema=self.schema,
            name=self.name,
            rls_enabled=self.rls_enabled,
            force_rls=self.force_rls,
            policies=tuple(self.policies),
            columns=tuple(c.name for c in self.columns),
            column_details=tuple(self.columns),
            grants=tuple(self.grants),
            column_grants=_merge_column_grants(self.column_grants),
            partition_of=self.partition_of,
            inherits=tuple(self.inherits),
        )


def _column_def_is_not_null(column_def: Any) -> bool:
    """Whether an inline `ColumnDef` is NOT NULL.

    Both an explicit `NOT NULL` and an inline `PRIMARY KEY` make the column
    non-nullable in Postgres. Losing this made every offline column nullable,
    which fed SEC030 (nullable tenant discriminator) a false positive on every
    DB-free path.
    """
    for con in getattr(column_def, "constraints", None) or ():
        if type(con).__name__ != "Constraint":
            continue
        if getattr(con, "contype", None) in (
            ConstrType.CONSTR_NOTNULL,
            ConstrType.CONSTR_PRIMARY,
        ):
            return True
    return False


def _table_constraint_pk_columns(stmt: Any) -> list[str]:
    """Column names named by a table-level `PRIMARY KEY (...)` constraint."""
    out: list[str] = []
    for elt in getattr(stmt, "tableElts", None) or ():
        if type(elt).__name__ != "Constraint":
            continue
        if getattr(elt, "contype", None) != ConstrType.CONSTR_PRIMARY:
            continue
        for key in getattr(elt, "keys", None) or ():
            name = getattr(key, "sval", None) or getattr(key, "str", None)
            if isinstance(name, str):
                out.append(name)
    return out


def _apply_rename(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
) -> None:
    """Apply `ALTER TABLE <old> RENAME TO <new>`.

    Without this the model keeps the pre-rename name, so every finding on the
    table pointed at a relation that does not exist after the migration — a
    `pgrls pr` annotation naming a phantom table. Renames of anything other
    than a table (columns, policies, constraints) are left alone.
    """
    if getattr(stmt, "renameType", None) != ObjectType.OBJECT_TABLE:
        return
    old = _relation_key(stmt.relation, default_schema)
    newname = getattr(stmt, "newname", None)
    if old is None or not newname:
        return
    builder = tables.pop(old, None)
    if builder is None:
        return
    new = (old[0], newname)
    builder.name = newname
    # A rename onto an occupied name cannot happen in valid DDL; if the input
    # is invalid anyway, the later definition wins rather than being dropped.
    tables[new] = builder


def _merge_column_grants(
    grants: list[ColumnGrant],
) -> tuple[ColumnGrant, ...]:
    """Merge grants sharing a ``(role, column)`` into one with unioned
    privileges, preserving first-seen order.

    Introspection groups column ACLs per ``(role, column)``, so two separate
    ``GRANT … (col) … TO r`` statements appear live as a single `ColumnGrant`.
    Mirror that here so the offline `sql=` path produces the same model — and
    SEC045 reports one finding per exposed column, not one per GRANT statement.
    """
    merged: dict[tuple[str, str], set[str]] = {}
    order: list[tuple[str, str]] = []
    for g in grants:
        key = (g.role, g.column)
        if key not in merged:
            merged[key] = set()
            order.append(key)
        merged[key].update(g.privileges)
    return tuple(
        ColumnGrant(role=r, column=c, privileges=tuple(sorted(merged[(r, c)])))
        for (r, c) in order
    )


def _relation_key(
    relation: Any, default_schema: str
) -> tuple[str, str] | None:
    """`(schema, name)` for a RangeVar, defaulting an unqualified schema."""
    if relation is None:
        return None
    name = getattr(relation, "relname", None)
    if not name:
        return None
    schema = getattr(relation, "schemaname", None) or default_schema
    return (schema, name)


def _column_type(column_def: Any) -> str | None:
    """Render a ColumnDef's typeName back to its `CREATE TABLE` text form.

    Uses pglast's deparser on the `TypeName` node — the same round-trip the
    introspect path's data types take — so e.g. ``numeric(10,2)`` and
    ``timestamp with time zone`` survive intact. The deparser maps pglast's
    internal aliases (``int4`` → ``integer``) to the canonical Postgres
    spelling, matching what introspection captures.
    """
    type_name = getattr(column_def, "typeName", None)
    if type_name is None:
        return None
    try:
        # `str(...)` pins the result type — pglast's RawStream is untyped
        # (mypy override), so the bare call returns `Any`.
        return str(RawStream()(type_name))
    except Exception:
        # Defensive: an exotic type the deparser can't render is dropped rather
        # than aborting the whole table (tolerant-walk contract). The column
        # name is still captured by the caller only when a type renders.
        return None


def _apply_alter_table(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
) -> None:
    key = _relation_key(stmt.relation, default_schema)
    if key is None:
        return
    builder = tables.get(key)
    if builder is None:
        # An ALTER on a table we never saw a CREATE for (e.g. the agent pasted
        # only the ALTER). Create a shell so the RLS toggle still records — a
        # table with RLS on and no columns/policies is a legitimate (if
        # incomplete) thing to lint.
        builder = _TableBuilder(schema=key[0], name=key[1])
        tables[key] = builder
    for cmd in stmt.cmds or ():
        subtype = getattr(cmd, "subtype", None)
        if subtype == AlterTableType.AT_EnableRowSecurity:
            builder.rls_enabled = True
        elif subtype == AlterTableType.AT_ForceRowSecurity:
            builder.force_rls = True
        elif subtype == AlterTableType.AT_DisableRowSecurity:
            builder.rls_enabled = False
        elif subtype == AlterTableType.AT_NoForceRowSecurity:
            builder.force_rls = False
        elif subtype == AlterTableType.AT_AddColumn:
            col = getattr(cmd, "def_", None)
            if col is not None and type(col).__name__ == "ColumnDef":
                colname = col.colname
                data_type = _column_type(col)
                if colname and data_type:
                    builder.columns.append(
                        Column(
                            name=colname,
                            data_type=data_type,
                            is_nullable=not _column_def_is_not_null(col),
                        )
                    )
        elif subtype == AlterTableType.AT_DropColumn:
            # Without this the model keeps a column the migration removed, so
            # column-keyed rules (SEC030's discriminator, SEC045's sensitive
            # column) fire on a column that no longer exists.
            name = getattr(cmd, "name", None)
            if name:
                builder.drop_column(name)
        elif subtype == AlterTableType.AT_SetNotNull:
            name = getattr(cmd, "name", None)
            if name:
                builder.set_not_null(name)
        elif subtype == AlterTableType.AT_DropNotNull:
            name = getattr(cmd, "name", None)
            if name:
                builder.set_not_null(name, not_null=False)
        # Other ALTER subcommands are ignored.


def _apply_create_policy(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
) -> None:
    key = _relation_key(getattr(stmt, "table", None), default_schema)
    if key is None:
        return
    builder = tables.get(key)
    if builder is None:
        builder = _TableBuilder(schema=key[0], name=key[1])
        tables[key] = builder

    name = getattr(stmt, "policy_name", None)
    if not name:
        return
    command = _POLICY_CMD_WORD_MAP.get((stmt.cmd_name or "all").lower())
    if command is None:
        # An unrecognized command word — skip rather than guess.
        return

    using_sql = _deparse_or_none(getattr(stmt, "qual", None))
    check_sql = _deparse_or_none(getattr(stmt, "with_check", None))
    location = f"{key[0]}.{key[1]}.{name}"
    using_ast = (
        _parse_clause(using_sql, location=location, clause="USING")
        if using_sql is not None
        else None
    )
    check_ast = (
        _parse_clause(check_sql, location=location, clause="WITH CHECK")
        if check_sql is not None
        else None
    )

    builder.policies.append(
        Policy(
            name=name,
            command=command,  # type: ignore[arg-type]
            permissive=bool(getattr(stmt, "permissive", True)),
            roles=_role_specs(getattr(stmt, "roles", None)),
            using_sql=using_sql,
            with_check_sql=check_sql,
            using_ast=using_ast,
            with_check_ast=check_ast,
        )
    )


def _apply_alter_policy(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
) -> None:
    """Apply ``ALTER POLICY`` — replace the named policy's USING / WITH CHECK /
    roles in place, leaving clauses the statement omits unchanged (Postgres
    semantics). Without this, a migration that loosens a policy *after* creating
    it (`ALTER POLICY p … USING (true)`) would be modeled as its pre-ALTER form
    — a silent false-negative for the offline `sql=` path and the DB-free
    `pgrls diff` gate built on it. Statements replay in source order (`CREATE`
    then `ALTER` are both in pass 2), so the accumulated policy is the net one.
    """
    key = _relation_key(getattr(stmt, "table", None), default_schema)
    if key is None:
        return
    builder = tables.get(key)
    if builder is None:
        return  # ALTER POLICY on a table this input never CREATEd.
    name = getattr(stmt, "policy_name", None)
    if not name:
        return
    location = f"{key[0]}.{key[1]}.{name}"
    for i, policy in enumerate(builder.policies):
        if policy.name != name:
            continue
        updates: dict[str, Any] = {}
        roles = getattr(stmt, "roles", None)
        if roles:
            updates["roles"] = _role_specs(roles)
        qual = getattr(stmt, "qual", None)
        if qual is not None:
            using_sql = _deparse_or_none(qual)
            updates["using_sql"] = using_sql
            updates["using_ast"] = (
                _parse_clause(using_sql, location=location, clause="USING")
                if using_sql is not None
                else None
            )
        with_check = getattr(stmt, "with_check", None)
        if with_check is not None:
            check_sql = _deparse_or_none(with_check)
            updates["with_check_sql"] = check_sql
            updates["with_check_ast"] = (
                _parse_clause(check_sql, location=location, clause="WITH CHECK")
                if check_sql is not None
                else None
            )
        if updates:
            builder.policies[i] = replace(policy, **updates)
        return
    # No policy of that name — an ALTER before its CREATE (invalid SQL) or on a
    # policy this input never modeled; nothing to update.


def _apply_drop(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
) -> None:
    """Apply ``DROP POLICY`` / ``DROP TABLE`` — remove the object from the model
    so a dropped RLS guard (or whole table) is reflected offline. Other ``DROP``
    object types (index, function, view, sequence, …) are not modeled and are
    skipped, as before. The one unfaithful case is a ``DROP TABLE`` *followed
    by* a re-``CREATE TABLE`` of the same name in the same input (`CREATE TABLE`
    is resolved in pass 1) — the table is treated as dropped; this matches the
    existing two-pass limitation and is rare in a single migration set.
    """
    remove_type = getattr(stmt, "removeType", None)
    if remove_type == ObjectType.OBJECT_POLICY:
        for namelist in stmt.objects or ():
            parts = _drop_name_parts(namelist)
            if len(parts) < 2:
                continue  # a policy name is `[…table…, policy]`.
            builder = tables.get(_drop_table_key(parts[:-1], default_schema))
            if builder is not None:
                policy_name = parts[-1]
                builder.policies = [
                    p for p in builder.policies if p.name != policy_name
                ]
    elif remove_type == ObjectType.OBJECT_TABLE:
        for namelist in stmt.objects or ():
            parts = _drop_name_parts(namelist)
            if parts:
                tables.pop(_drop_table_key(parts, default_schema), None)


def _drop_name_parts(namelist: Any) -> list[str]:
    """The string identifier parts of one ``DROP`` object name, or `[]` if any
    part is missing (a shape we can't resolve — skip it rather than guess)."""
    if not isinstance(namelist, (list, tuple)):
        return []
    parts = [getattr(n, "sval", None) for n in namelist]
    return [p for p in parts if p] if all(parts) else []


def _drop_table_key(
    table_parts: list[str], default_schema: str
) -> tuple[str, str]:
    """`(schema, table)` from a table's name parts (`[schema, table]` or
    `[table]`), defaulting an unqualified schema — the same keying as
    `_relation_key`."""
    if len(table_parts) == 1:
        return (default_schema, table_parts[0])
    return (table_parts[-2], table_parts[-1])


def _apply_grant(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
) -> None:
    """Record a direct `GRANT <privs> ON <table> TO <roles>` as a `Grant`.

    Only a GRANT (not REVOKE), targeting a specific table object (not
    ``ALL TABLES IN SCHEMA``), on a TABLE (not a schema / function / sequence)
    is modeled. Everything else is skipped tolerantly. A grant naming a table
    we never saw a CREATE for is dropped — there is no table to attach it to and
    fabricating a shell would invent a relation the user didn't declare.
    """
    if not getattr(stmt, "is_grant", False):
        return  # REVOKE
    if getattr(stmt, "targtype", None) != GrantTargetType.ACL_TARGET_OBJECT:
        return  # ALL TABLES IN SCHEMA, etc.
    if getattr(stmt, "objtype", None) != ObjectType.OBJECT_TABLE:
        return  # schema / function / sequence grant

    table_privs, column_privs = _grant_privileges(stmt)
    if not table_privs and not column_privs:
        return
    grantees = _role_specs(getattr(stmt, "grantees", None))
    if not grantees:
        return

    for obj in stmt.objects or ():
        if type(obj).__name__ != "RangeVar":
            continue
        key = _relation_key(obj, default_schema)
        if key is None:
            continue
        builder = tables.get(key)
        if builder is None:
            # GRANT references a table not declared in this DDL — skip.
            continue
        for role in grantees:
            if table_privs:
                builder.grants.append(Grant(role=role, privileges=table_privs))
            for column, privs in column_privs.items():
                builder.column_grants.append(
                    ColumnGrant(
                        role=role,
                        column=column,
                        privileges=tuple(sorted(privs)),
                    )
                )


def _grant_privileges(
    stmt: Any,
) -> tuple[tuple[str, ...], dict[str, set[str]]]:
    """Split a GrantStmt's privileges into table-level and column-level.

    Returns ``(table_privileges, {column: {privileges}})``. An empty privilege
    list is Postgres's ``GRANT ALL`` (table-level). A column-scoped privilege
    (``GRANT SELECT (col) …``) feeds `ColumnGrant` — the SEC045 PII-exposure
    rule reads those; ``GRANT ALL (col)`` expands to the column-applicable set.
    """
    privs = stmt.privileges
    if not privs:
        # Empty privilege list is Postgres's `GRANT ALL` (whole table).
        return _GRANT_ALL_PRIVILEGES, {}
    table_out: list[str] = []
    column_out: dict[str, set[str]] = {}
    for ap in privs:
        cols = getattr(ap, "cols", None)
        name = getattr(ap, "priv_name", None)
        if cols:
            col_privs = (
                {name.upper()}
                if name
                else set(_COLUMN_GRANT_ALL_PRIVILEGES)  # GRANT ALL (col)
            )
            for col in cols:
                colname = getattr(col, "sval", None)
                if colname:
                    column_out.setdefault(colname, set()).update(col_privs)
            continue
        if name:
            table_out.append(name.upper())
    return tuple(table_out), column_out


def _role_specs(roles: Any) -> tuple[str, ...]:
    """Role names from a list of pglast RoleSpec nodes.

    `ROLESPEC_PUBLIC` becomes the literal ``"PUBLIC"`` (the convention
    `Policy.roles` / `Grant.role` use); a named role yields its `rolename`. The
    session pseudo-roles (`CURRENT_USER` / `SESSION_USER` / `CURRENT_ROLE`) are
    rendered as their SQL keyword so they are at least visible to the rules.
    """
    out: list[str] = []
    for role in roles or ():
        roletype = getattr(role, "roletype", None)
        if roletype == RoleSpecType.ROLESPEC_PUBLIC:
            out.append("PUBLIC")
        elif roletype == RoleSpecType.ROLESPEC_CURRENT_USER:
            out.append("CURRENT_USER")
        elif roletype == RoleSpecType.ROLESPEC_SESSION_USER:
            out.append("SESSION_USER")
        elif roletype == RoleSpecType.ROLESPEC_CURRENT_ROLE:
            out.append("CURRENT_ROLE")
        else:
            name = getattr(role, "rolename", None)
            if name:
                out.append(name)
    return tuple(out)


def _deparse_or_none(node: Any) -> str | None:
    """Render a policy USING / WITH CHECK expression node back to SQL text.

    Returns the deparsed fragment (which `parse_expr` then re-parses into the
    canonical AST shape the rules expect), or `None` when the clause is absent.
    """
    if node is None:
        return None
    try:
        # `str(...)`: RawStream is untyped (mypy override) → bare call is `Any`.
        return str(RawStream()(node))
    except Exception:
        return None


# Catalog-dependent rules: each reads a model field that an offline schema
# source may not carry. Each maps to a human label and the SNAPSHOT VERSION at
# which a `pgrls snapshot` first serializes every field that rule needs (the
# LATEST version across all fields it reads — e.g. SEC035 needs `indexes` (v7)
# AND `Index.is_primary` (v13), so its threshold is 13).
#
# CAUTION when adding/editing a rule: the threshold is the max over EVERY field
# the rule's `check` consumes — including a field it reaches only through a
# shared helper (SEC041/SEC043 gate on `sec041._is_directly_reachable`, which
# reads `Table.column_grants` (v8), so neither may be below 8 however early its
# own marquee field landed). A threshold set BELOW a field the rule actually
# reads is a silent false-clean: an older snapshot decodes that field as empty,
# the rule runs, finds nothing, and is wrongly reported as covered. The
# `test_offline_noop_rule_*` regression tests fire each rule at its threshold to
# catch this. The inert decision is
# SOURCE-AWARE (see `inert_rule_ids`) rather than a hardcoded blanket list:
#
#   * a `sql=` schema carries NONE of these — `schema_from_sql` models only RLS
#     flags, policies, columns and grants from DDL — so every rule here is inert
#     on it (the data lives in pg_catalog, not in CREATE/ALTER/GRANT text);
#   * a `snapshot` declares the introspector version that wrote it; a rule is
#     inert only when that version predates the rule's threshold (the field was
#     not captured and decodes back as an empty default — a silent no-op). A
#     current snapshot meets every threshold, so it exercises the full rule set
#     and an absence of findings on it is real coverage, not "couldn't run".
#
# Keying on the declared version (not on whether a field happens to be empty) is
# what lets a complete snapshot of a feature-light database — no triggers, no
# BYPASSRLS roles — still count those rules as *run and clean* rather than
# *skipped*, while a pre-threshold snapshot fails closed.
#
# PERF005 is deliberately ABSENT: it reads the `--perf` runtime-stats artifact,
# not a schema field, so it no-ops without `--perf` on EVERY source (exactly as
# on a live database) and is never a coverage gap of the schema source itself.
_CATALOG_DEPENDENT_RULES: dict[str, tuple[str, int]] = {
    "SEC013": ("triggers on RLS tables", 6),
    "SEC014": ("SECURITY DEFINER functions", 4),
    "SEC015": ("SECURITY DEFINER function search_path", 8),
    "SEC016": ("BYPASSRLS roles", 9),
    "SEC017": ("LEAKPROOF functions", 10),
    "SEC023": ("policy TO clause names a BYPASSRLS role", 9),
    "SEC029": ("SET ROLE → BYPASSRLS escalation", 11),
    "SEC035": ("UNIQUE-index cross-tenant existence oracle", 13),
    # SEC041/SEC043 gate every emission on `sec041._is_directly_reachable`,
    # which reads `Table.grants` (v3) AND `Table.column_grants` (v8) — so their
    # threshold is the max over partition_of/inherits AND that reachability gate.
    "SEC041": ("partition of an RLS-enabled parent", 8),
    "SEC042": ("anon-exposed SECURITY DEFINER functions", 16),
    "SEC043": ("classic-INHERITS child of an RLS parent", 17),
    "SEC044": ("ALTER DEFAULT PRIVILEGES (pg_default_acl)", 18),
    "SEC046": ("user-defined IMMUTABLE functions", 19),
    "SEC047": ("foreign keys to RLS-enabled parents", 20),
    "SEC048": ("owner-reachable members that bypass RLS", 21),
    "SEC051": ("Realtime publication membership (pg_publication_tables)", 22),
    # SEC052 gates every emission on `View.grants` (v23) — a view REVOKE'd from
    # low-trust roles isn't flagged — so on a pre-v23 snapshot (or a view-less
    # SQL-file source) it must be inert *loudly*, not silently no-op past
    # --require-full-coverage.
    "SEC052": ("view grants that expose auth.users (relacl)", 23),
    # SEC053 fires only on `Schema.foreign_tables` (v24), which a view/table-less
    # SQL source never models and a pre-v24 snapshot lacks — so it must be inert
    # *loudly* there, not silently pass --require-full-coverage.
    "SEC053": ("foreign tables and their grants (relkind 'f')", 24),
    # SEC054 gates on `View.grants` (v23) to confirm the matview is
    # API-reachable — like SEC052, it must be inert *loudly* on a pre-v23
    # snapshot / view-less SQL source, not silently pass --require-full-coverage.
    "SEC054": ("materialized-view grants (relacl)", 23),
    "PERF003": ("policy-predicate column indexes", 7),
    # PERF004 reaches `Table.indexes` (v7) through `perf003._has_leading_column_index`
    # — same shared-helper path as SEC041/SEC043; the helper reads only
    # `Index.columns` (v7 baseline), not `is_primary` (v13), so the threshold is 7.
    "PERF004": ("policy-predicate function-wrapped column indexes", 7),
    "VIEW001": ("views over RLS tables", 4),
    "VIEW002": ("non-security-barrier view over RLS table", 4),
    "VIEW003": ("view ownership chains", 4),
    "VIEW004": ("SECURITY DEFINER calls from view bodies", 4),
}

# Every threshold must be reachable by the current snapshot format, or that rule
# would be permanently inert on snapshots (a silent coverage gap). Pinned here
# so adding a rule whose field lands in a future version can't slip through.
assert all(v <= SNAPSHOT_VERSION for _, v in _CATALOG_DEPENDENT_RULES.values())

WarnCommand = Literal["lint", "fix", "generate", "snapshot"]


def inert_rule_ids(
    source: SchemaSource, *, snapshot_version: int | None = None
) -> frozenset[str]:
    """Rule IDs that cannot fire on this source and must be explicitly skipped.

    Source-aware so an offline run can never read a silent no-op as coverage,
    while a complete snapshot still exercises its full rule set:

    * ``sql`` — `schema_from_sql` models only RLS flags, policies, columns and
      grants, so every catalog-dependent rule is inert (the data it reads lives
      in pg_catalog, never in CREATE/ALTER/GRANT DDL).
    * ``snapshot`` — a rule is inert when `snapshot_version` predates the
      version that first serialized the field it needs (an older snapshot never
      wrote it, so it decodes as an empty default and the rule would silently
      no-op). A current snapshot meets every threshold → this set is empty. An
      unknown version (`None`) fails closed: every catalog-dependent rule is
      treated as inert.
    * ``database_url`` — the live catalog has everything → nothing is inert.
    """
    if source == "sql":
        return frozenset(_CATALOG_DEPENDENT_RULES)
    if source == "snapshot":
        version = snapshot_version if snapshot_version is not None else 0
        return frozenset(
            rule_id
            for rule_id, (_, min_version) in _CATALOG_DEPENDENT_RULES.items()
            if version < min_version
        )
    return frozenset()


def schema_source_warnings(
    source: SchemaSource,
    *,
    command: WarnCommand | None = None,
    snapshot_version: int | None = None,
) -> list[str]:
    """Soundness caveats for an offline response, per source + command.

    `command=None` (the MCP default) preserves the original lint-flavored text
    verbatim. The CLI passes its command so `generate` gets a generation-scoped
    caveat. The skipped-rule list is computed via `inert_rule_ids`, so a current
    snapshot reports nothing skipped. A live `database_url` → no warnings.
    """
    if source not in ("sql", "snapshot"):
        return []
    if command == "generate":
        return [
            "Generation reflects only the tables and policies in the provided "
            "schema — roles, grants, and policies defined elsewhere are not "
            "seen. Review the output against your full schema before applying.",
        ]
    inert = ", ".join(
        sorted(inert_rule_ids(source, snapshot_version=snapshot_version))
    )
    if source == "snapshot":
        lines = [
            "Analysis is of the snapshot only — no live database. A snapshot is "
            "a point-in-time capture, so re-run against a live database for "
            "runtime checks (--perf) and the latest catalog state.",
        ]
        if inert:
            lines.append(
                "Skipped (this snapshot predates these rules' inputs; "
                f"re-capture to cover them): {inert}."
            )
        return lines
    if command == "snapshot":
        return [
            "This snapshot was built from the provided SQL offline — no live "
            "database. It captures only what CREATE/ALTER/GRANT DDL expresses "
            "(RLS flags, policies, columns, grants); catalog-only state "
            "(BYPASSRLS roles, SECURITY DEFINER functions, triggers, indexes, "
            "foreign keys) is absent, so diffing it against a live-database "
            "snapshot may show spurious differences.",
        ]
    if command in {"lint", "fix"}:
        return [
            "Analysis is of the provided SQL only — no live database. Rules that "
            "depend on catalog state (BYPASSRLS roles, SECURITY DEFINER functions, "
            "triggers, indexes, and foreign keys) cannot fire here, so an absence "
            "of findings is NOT a proof of safety. "
            "For full coverage, run against a live database "
            "(--database-url or $DATABASE_URL).",
            f"Inert on sql= input (catalog-only): {inert}.",
        ]
    return [
        "Analysis is of the provided SQL only — no live database. Rules that "
        "depend on catalog state not expressible in CREATE/ALTER/GRANT DDL "
        "cannot fire here, so an absence of findings is NOT a proof of safety. "
        "For full coverage, run pgrls against a live database_url or a "
        "snapshot.",
        f"Inert on sql= input (catalog-only): {inert}.",
    ]
