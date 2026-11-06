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

import contextlib
import dataclasses

import json
import re
from dataclasses import replace
from collections.abc import Set as AbstractSet
from typing import Any, Literal

import pglast
import pglast.parser
from pglast import ast as _pgast
from pglast.enums.parsenodes import (
    A_Expr_Kind,
    AlterTableType,
    ConstrType,
    DiscardMode,
    DropBehavior,
    GrantTargetType,
    ObjectType,
    RoleSpecType,
    SetOperation,
    TransactionStmtKind,
    VariableSetKind,
)
from pglast.enums.primnodes import OnCommitAction
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
    `sql` (which schemas are in scope; an unqualified relation resolves on
    the search path the SQL sets, as Postgres resolves it) paths; it is
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
    roles, ALTER DEFAULT PRIVILEGES, …) is silently skipped. What raises — a
    `bad_sql` `SchemaSourceError`, so the agent learns its SQL could not be
    read rather than receiving a falsely-clean "no findings" — is a pglast
    `ParseError` on the whole input, and SQL whose effect pgrls cannot model:
    a psql meta-command other than the harmless ones, a setting that changes
    how Postgres reads the text, objects or a transaction before the last
    `\\connect`, or a `\\connect` to a database it creates from a template
    other than template0 or in an encoding other than UTF8.

    What IS modeled:

    * ``CREATE TABLE`` → a `Table` with `Column`s (name + Postgres data type).
      An unqualified relation resolves on the search path the SQL sets, as
      the statements run, whatever `schemas` lists (`_model_statements`);
      keyed on ``(schema, name)``. What a ROLLBACK undoes is left out.
    * ``ALTER TABLE … ENABLE / FORCE ROW LEVEL SECURITY`` → sets the table's
      `rls_enabled` / `force_rls`; ``ALTER TABLE … ATTACH / DETACH
      PARTITION`` sets / clears the child's `partition_of` (the form
      ``pg_dump`` writes partitions in) for a child and parent created
      before it; ``ALTER TABLE … RENAME`` carries the name to its
      partitions and children. A partition's parents outside `schemas` are
      left out, as live lint does not see them. An ALTER on a view, sequence or other
      non-table relation is ignored. psql meta-command lines that do not
      change the SQL (``\\restrict``, ``\\echo``, a ``\\connect`` to one
      database after only database-level statements) are skipped; any
      other is refused.
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
    if _holds_copy_data(sql):
        # Before anything reads its rows (a `\\N` NULL, an apostrophe) as SQL.
        raise SchemaSourceError(
            "bad_sql",
            "the SQL holds COPY data (a pg_dump with data); dump the "
            "schema with pg_dump --schema-only.",
        )
    if "\x00" in sql:
        # pglast stops at a NUL; psql drops only the rest of that line.
        raise SchemaSourceError("bad_sql", "the SQL holds a NUL character.")
    # pg_dump writes psql meta-commands (`\\restrict <key>` since the August
    # 2025 minor releases: 13.22, 14.19, 15.14, 16.10, 17.6), which
    # are not SQL; each is blanked so offsets into `sql` still hold.
    sql, commands = _split_psql_meta_commands(sql)
    connects = _check_psql_meta_commands(commands)
    # The last one: psql ends statements by its own rules (a `begin` in a
    # CREATE FUNCTION opens a body to it), so one it reads past a
    # `\\connect` runs, and commits or rolls back, in the next session.
    connect = connects[-1] if connects else None
    try:
        statements = pglast.parse_sql(sql)
        if commands:
            _check_blanked_lines(sql, commands)
    except pglast.parser.ParseError as exc:
        raise SchemaSourceError(
            "bad_sql",
            f"could not parse the provided SQL: {exc}.",
        ) from exc
    _check_lexer_settings(statements, non_ascii=not sql.isascii())
    if any(isinstance(raw.stmt, _pgast.AlterObjectSchemaStmt)
           and raw.stmt.objectType == ObjectType.OBJECT_TABLE for raw in statements):
        # Policies elsewhere name the table by its old schema, and a later
        # CREATE of the old name would merge with it.
        raise SchemaSourceError(
            "bad_sql",
            "the SQL moves a table to another schema (ALTER TABLE … SET SCHEMA), "
            "which pgrls does not model; lint a dump of the schema after the "
            "move, or the live database.",
        )
    if any(_type_named(raw.stmt) in _LITERAL_CASTS for raw in statements):
        # A cast to it would then be to that type, which may change the
        # literal (`'appx'::text` under a domain over varchar(3)).
        raise SchemaSourceError(
            "bad_sql",
            "the SQL creates a type named like a built-in one (text, bool, varchar, "
            "boolean) that pgrls reads a cast to as keeping its literal.",
        )
    if any(isinstance(raw.stmt, _pgast.RenameStmt)
           and raw.stmt.renameType == ObjectType.OBJECT_SCHEMA for raw in statements):
        # Every table in it moves, and names resolve in the new one.
        raise SchemaSourceError(
            "bad_sql",
            "the SQL renames a schema (ALTER SCHEMA … RENAME), which pgrls does "
            "not model; lint a dump of the schema after the rename, or the live "
            "database.",
        )
    if any(isinstance(raw.stmt, _pgast.CopyStmt) and raw.stmt.is_from
           and raw.stmt.filename is None and not raw.stmt.is_program
           for raw in statements):
        # psql reads the rows from the file itself, up to a `\\.` line.
        raise SchemaSourceError(
            "bad_sql",
            "the SQL copies rows from stdin, which psql reads from the file "
            "itself; dump the schema with pg_dump --schema-only.",
        )

    def end(raw: Any) -> int:
        # Where the statement ends: its start can include the gap before it.
        return (raw.stmt_location or 0) + raw.stmt_len if raw.stmt_len else len(sql)

    if connect is not None and any(
        isinstance(raw.stmt, _pgast.CreatedbStmt) and any(
            opt.defname == "encoding" and str(
                getattr(opt.arg, "sval", None) or getattr(opt.arg, "ival", "")
            ).lower().replace("_", "").replace("-", "") not in ("utf8", "unicode", "6")
            for opt in raw.stmt.options or ())
        for raw in statements
    ):
        # psql reads what follows in the new database's encoding; set back to
        # UTF8, Postgres still converts it to that one (failing on what it
        # cannot hold, a `U&'\\0101'` escape too) and, single-byte even as
        # SQL_ASCII, cuts names by byte and folds them by its locale.
        raise SchemaSourceError(
            "bad_sql",
            "the SQL connects to a database it creates with an encoding other "
            "than UTF8, where Postgres reads the SQL differently from how pgrls "
            "reads it.",
        )
    if connect is not None and any(
        isinstance(raw.stmt, _pgast.CreatedbStmt) and any(
            opt.defname == "template" and getattr(opt.arg, "sval", None) != "template0"
            for opt in raw.stmt.options or ())
        for raw in statements
    ):
        # The database copies the template's objects, which the SQL does not
        # show. (`template1`, the default, is taken to be as pg_dump leaves it:
        # a database linted by its own dump would not show those either.)
        raise SchemaSourceError(
            "bad_sql",
            "the SQL creates a database from a template other than template0 "
            "and connects to it; pgrls cannot see the template's objects.",
        )
    if connect is not None and any(
        end(raw) < connect and not _clears_a_template_flag(raw.stmt)
        and not (isinstance(raw.stmt, _pgast.SecLabelStmt)
                 and raw.stmt.objtype == ObjectType.OBJECT_DATABASE)
        # psql rolls a transaction open at any `\\connect` back there.
        and not (isinstance(raw.stmt, _pgast.TransactionStmt)
                 and not any(_open_at(statements, c, end) for c in connects))
        and (type(raw.stmt).__name__ not in _DATABASE_LEVEL_STATEMENTS
             or getattr(raw.stmt, "intoClause", None) is not None  # SELECT … INTO
             # A CTE that writes (a database's settings into its catalog).
             or any(isinstance(node, _WRITES) for node in _subnodes(raw.stmt)))
        for raw in statements
    ):
        # A `\\connect` after objects were created (or a transaction begun)
        # switches database: what follows is another database's schema,
        # which must not merge, and an open transaction is rolled back.
        raise SchemaSourceError(
            "bad_sql",
            "the SQL creates objects, writes or begins a transaction and then "
            "\\connects to another database; lint each database's schema "
            "separately.",
        )

    # Every relation name is qualified by now, as Postgres resolves it on the
    # search path the SQL sets (whatever the linted scope).
    statements = _model_statements(
        statements, after=lambda raw: connect is None or end(raw) >= connect)
    default_schema = "public"
    # Relations the input creates that are not tables: pg_dump writes
    # `ALTER … OWNER TO` for each, and an ALTER on one must not invent a table.
    non_tables = {
        key for raw in statements
        if (key := _relation_key(_non_table_relation(raw.stmt), default_schema)) is not None
    }

    # Build tables first (CREATE TABLE), then layer ALTER / CREATE POLICY /
    # GRANT onto them, so a policy or grant that precedes its table in the input
    # still attaches. Two passes keep that order-independent.
    tables: dict[tuple[str, str], _TableBuilder] = {}

    # Where any table may go away — any DROP (a CASCADE of a function in a
    # partition key, an access method or an extension reaches tables in any
    # schema), a DROP OWNED, a rename of a relation — so a CREATE … IF NOT
    # EXISTS of one still there is told from a re-create. Conservative: the
    # skip only stands with none of these between (pg_dump writes no IF NOT
    # EXISTS).
    removals = [
        index for index, raw in enumerate(statements)
        if isinstance(raw.stmt, (_pgast.DropStmt, _pgast.DropOwnedStmt))
        or (isinstance(raw.stmt, _pgast.RenameStmt) and raw.stmt.relation is not None)
        or _runs_code(raw.stmt)  # a DROP in a DO block, a procedure, a function
    ]

    def gone_between(after: int, before: int, key: tuple[str, str] | None = None) -> bool:
        # (A rename takes away only the relation it renames.)
        return any(after < r < before and not (
            key is not None and isinstance(statements[r].stmt, _pgast.RenameStmt)
            and _relation_key(statements[r].stmt.relation, default_schema) != key)
            for r in removals)

    # Pass 1: CREATE TABLE (plus the two data-derived forms).
    # (Stepped a statement behind: as each runs, it holds what came before.)
    made = _Holds(default_schema)

    # Each table by the CREATE that made it. One made under a name the SQL
    # gave something before (a table dropped or renamed away, or renamed
    # in, as pass 2 will follow) waits to take that name until pass 2
    # reaches its CREATE; the first by a name takes it now, so a policy or
    # grant before its CREATE still finds it (unless the name was dropped or
    # renamed before: then the policy is the old table's).
    by_made: dict[int, _TableBuilder] = {}
    unborn: dict[int, tuple[tuple[str, str], _TableBuilder]] = {}

    def place(key: tuple[str, str], builder: _TableBuilder, index: int) -> None:
        by_made[index] = builder
        if key in tables or key in made.ever or key[0] in made.dropped_schemas:
            unborn[index] = (key, builder)
        else:
            tables[key] = builder

    def no_op_over(stmt: Any, key: tuple[str, str], index: int) -> bool:
        # IF NOT EXISTS of a name another relation (a view, a sequence)
        # holds, with nothing that may have removed it between.
        return (getattr(stmt, "if_not_exists", False)
                and key in made.holds and made.holds[key] not in by_made
                and not gone_between(made.holds[key], index))

    for index, raw in enumerate(statements):
        if index:
            made.step(statements[index - 1].stmt, index - 1)
        stmt = raw.stmt
        kind = type(stmt).__name__
        if kind != "CreateStmt":
            # `CREATE TABLE x AS SELECT …` and `SELECT … INTO x` create a REAL
            # table — one with no RLS, which is exactly what SEC001 exists to
            # catch — but neither is a CreateStmt, so both were invisible and
            # the DB-free path reported nothing on them. Register the relation
            # so the table-level rules see it. Its columns come from the SELECT
            # and cannot be resolved without a catalog, so it is registered
            # WITHOUT columns: column-keyed rules stay silent (honest) rather
            # than guess a shape.
            created = _data_derived_relation(stmt)
            if created is None:
                continue
            key = _relation_key(created, default_schema)
            if key is None or no_op_over(stmt, key, index):
                continue
            held = made.holds.get(key)
            current = by_made.get(held) if held is not None else None
            if current is not None:
                # As a re-CREATE below: the table now, unless an IF NOT
                # EXISTS skips while it is there.
                if not (getattr(stmt, "if_not_exists", False)
                        and not gone_between(current.created_at, index)):
                    if not _renamed_between(statements, key, current.created_at, index,
                                            default_schema):
                        # A table made from a query is no partition or child.
                        current.partition_of = None
                        current.inherits = []
                    current.created_at = index
                continue
            place(key, _TableBuilder(schema=key[0], name=key[1], created_at=index), index)
            continue
        key = _relation_key(stmt.relation, default_schema)
        if key is None or no_op_over(stmt, key, index):
            continue
        held = made.holds.get(key)
        current = by_made.get(held) if held is not None else None
        if current is not None:
            # A second CREATE for the same relation: `IF NOT EXISTS` (a no-op
            # in Postgres), a re-CREATE after an intervening DROP, or DDL that
            # would error outright. The first definition's COLUMNS stand —
            # re-walking `tableElts` would append them twice and hand every
            # column-keyed rule a duplicated list — but `created_at` advances
            # to this statement so the drop gate sees the LAST create. That
            # makes existence correct for every ordering: `CREATE; DROP;
            # CREATE` keeps the table, `CREATE; CREATE; DROP` removes it.
            # One `IF NOT EXISTS` skips while the table is there (with no
            # DROP since), so an ATTACH / DETACH before it still applies.
            if stmt.if_not_exists and not gone_between(current.created_at, index, key):
                continue
            previous = current.created_at
            current.created_at = index
            # A table made again is a partition or child only as this CREATE
            # says (the ATTACH / DETACH before it is the old one's); one that
            # may also be the old table (an IF NOT EXISTS after code, not
            # after a DROP of it) keeps only a link both would have.
            again = [p for p in (_relation_key(rel, default_schema)
                                 for rel in (stmt.inhRelations or ())) if p is not None]
            partition = bool(again) and getattr(stmt, "partbound", None) is not None
            new_parent = again[0] if partition else None
            new_inherits = [] if partition else again
            if stmt.if_not_exists and not _dropped_between(statements, key, previous, index,
                                                           default_schema):
                def same(p: tuple[str, str]) -> bool:
                    # (A parent name renamed away or dropped between names
                    # another table for each.)
                    return not (_renamed_between(statements, p, previous, index, default_schema)
                                or _dropped_between(statements, p, previous, index,
                                                    default_schema))
                if current.partition_of != new_parent or (
                        new_parent is not None and not same(new_parent)):
                    new_parent = None
                new_inherits = [p for p in new_inherits if p in current.inherits and same(p)]
            if new_parent is not None and _is_below(tables, new_parent, key):
                new_parent = None  # an ATTACH would refuse the cycle
            if _renamed_between(statements, key, previous, index, default_schema):
                # The model merges it with the table renamed away, whose
                # links these would wrongly become: keep the old ones.
                continue
            current.partition_of = new_parent
            current.inherits = [p for p in new_inherits if not _is_below(tables, p, key)]
            continue
        builder = _TableBuilder(schema=key[0], name=key[1], created_at=index)
        builder.partitioned = getattr(stmt, "partspec", None) is not None
        place(key, builder, index)
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
        # (Not itself, nor — for a name nothing held before, which an IF NOT
        # EXISTS over a table the SQL did not make may leave — one below
        # it: that may have been a no-op that set no link. A name dropped
        # or renamed away and made again has its link; pass 2 frees the old.)
        parents = [p for p in parents if p != key and not (
            key not in made.ever and _is_below(tables, p, key))]
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
            # The table the name holds as this CREATE runs (one made again
            # waits in `unborn`).
            held_parent = made.holds.get(parent_key)
            parent = (by_made.get(held_parent) if held_parent is not None
                      else tables.get(parent_key))
            if parent is None:
                continue
            for col in parent.columns:
                if not any(c.name == col.name for c in builder.columns):
                    if col.name in parent.no_inherit_not_null:
                        col = replace(col, is_nullable=True)
                    builder.columns.append(col)
            # An inherited NOT NULL keeps the parent's constraint name, which
            # the child can drop once detached.
            for conname, cols in parent.not_null_names.items():
                builder.not_null_names.setdefault(conname, set()).update(cols)
            builder.former_names.extend(parent.former_names)
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
                _record_not_null_names(builder, elt)
                if _only_no_inherit_not_null(getattr(elt, "constraints", None) or ()):
                    builder.no_inherit_not_null.add(colname)
        # A table-level `PRIMARY KEY (a, b)` constraint makes its columns NOT
        # NULL just as an inline `PRIMARY KEY` does, and so does PG18's
        # table-level `NOT NULL c`.
        for elt in stmt.tableElts or ():
            for col_name in _constraint_not_null_columns(elt, creating=True):
                builder.set_not_null(col_name)
                # Only a NOT NULL's name is recorded: dropping a primary key leaves
                # its columns NOT NULL.
                if elt.contype == ConstrType.CONSTR_NOTNULL and elt.conname:
                    builder.not_null_names.setdefault(elt.conname, set()).add(col_name)
                if _only_no_inherit_not_null([elt]):
                    builder.no_inherit_not_null.add(col_name)

    # Pass 2: ALTER TABLE (RLS toggles), CREATE POLICY, GRANT, RENAME.
    for index, raw in enumerate(statements):
        if index in unborn:
            # A table made again (dropped, or renamed away, before): what the
            # SQL did to the one before stays with it, gone or renamed.
            key, builder = unborn.pop(index)
            tables[key] = builder
        stmt = raw.stmt
        kind = type(stmt).__name__
        if kind == "AlterTableStmt":
            _apply_alter_table(stmt, tables, default_schema, non_tables=non_tables,
                               stmt_index=index)
        elif kind in ("CreatePolicyStmt", "AlterPolicyStmt"):
            # (A CREATE SCHEMA element's text is within its statement's.)
            start = raw.raw.stmt_location or 0
            source = sql[start:start + raw.raw.stmt_len] if raw.raw.stmt_len else sql[start:]
            apply = _apply_create_policy if kind == "CreatePolicyStmt" else _apply_alter_policy
            apply(stmt, tables, default_schema, source=source)
        elif kind == "DropStmt":
            _apply_drop(stmt, tables, default_schema, stmt_index=index)
        elif kind == "GrantStmt":
            _apply_grant(stmt, tables, default_schema)
        elif kind == "RenameStmt":
            _apply_rename(stmt, tables, default_schema, index)
        # Every other statement shape is skipped tolerantly.

    # An IF NOT EXISTS the model could not tell was a no-op may leave a link
    # that a rename closes into a cycle: break it rather than fail (the
    # table then reads as standalone, which only over-reports).
    for key, builder in tables.items():
        if builder.partition_of is not None and _is_below(tables, builder.partition_of, key):
            builder.partition_of = None
        builder.inherits = [p for p in builder.inherits if not _is_below(tables, p, key)]
    # Live lint does not see a table outside the linted schemas: a partition
    # keeps its link to such a parent, and its ancestor walk stops there.
    unseen: set[tuple[str, str]] = set()
    for key in [k for k in tables if k[0] in schemas]:
        up = tables[key].partition_of
        # A cycle (the replay can build one from valid DDL) ends the walk.
        while up is not None and up in tables and up[0] not in schemas and up not in unseen:
            unseen.add(up)
            up = tables[up].partition_of
    return Schema(tables=tuple(b.build() for k, b in tables.items()
                               if k not in unseen and k[0] != _NOWHERE))


class _Holds:
    """Which CREATE made the relation each name holds, as the statements
    run: one made (an IF NOT EXISTS, or a CREATE, of a name held is a
    no-op or an error), renamed, or dropped (with its schema too)."""

    def __init__(self, default_schema: str) -> None:
        self.default_schema = default_schema
        self.holds: dict[tuple[str, str], int] = {}
        # A name anything has held, or the SQL dropped or renamed away (one
        # there before it); a schema it dropped.
        self.ever: set[tuple[str, str]] = set()
        self.dropped_schemas: set[str] = set()

    def step(self, stmt: Any, index: int) -> None:
        for rel, creates in _named_relations(stmt):
            key = _relation_key(rel, self.default_schema) if creates else None
            if key is not None and key not in self.holds:
                self.holds[key] = index
                self.ever.add(key)
        if (isinstance(stmt, _pgast.RenameStmt) and stmt.relation is not None
                and stmt.renameType in _RELATION_KINDS and stmt.newname
                and (old := _relation_key(stmt.relation, self.default_schema)) in self.holds):
            self.holds[(old[0], stmt.newname)] = self.holds.pop(old)
            self.ever.add((old[0], stmt.newname))
        elif (isinstance(stmt, _pgast.RenameStmt) and stmt.relation is not None
                and stmt.renameType in _RELATION_KINDS and stmt.newname
                and (old := _relation_key(stmt.relation, self.default_schema)) is not None):
            self.ever.add(old)  # one the SQL did not make (or none: IF EXISTS)
        elif isinstance(stmt, _pgast.DropStmt) and stmt.removeType in _RELATION_KINDS:
            for n in stmt.objects or ():
                if _drop_name_parts(n):
                    key = _drop_table_key(_drop_name_parts(n), self.default_schema)
                    self.holds.pop(key, None)
                    if stmt.removeType == ObjectType.OBJECT_TABLE:
                        self.ever.add(key)
        elif isinstance(stmt, _pgast.DropStmt) and stmt.removeType == ObjectType.OBJECT_SCHEMA:
            gone = {getattr(item, "sval", None) for item in stmt.objects or ()}
            for key in [k for k in self.holds if k[0] in gone]:
                del self.holds[key]
            self.dropped_schemas |= {g for g in gone if g}


class _Stmt:
    """A statement the model replays: a top-level one, or an element of a
    `CREATE SCHEMA` (with the top-level `raw` it is part of)."""

    __slots__ = ("stmt", "raw")

    def __init__(self, stmt: Any, raw: Any) -> None:
        self.stmt = stmt
        self.raw = raw


# Where a relation the session cannot keep goes (a temporary one, or one
# created with no schema to go in): left out of the model.
_NOWHERE = "pg_temp"
_DEFAULT_SEARCH_PATH = ("$user", "public")
# Postgres cuts a name to NAMEDATALEN - 1 bytes.
_NAME_BYTES = 63


def _model_statements(statements: Any, *, after: Any) -> list[_Stmt]:
    """The statements the model replays — those no ROLLBACK undid, with the
    elements of a `CREATE SCHEMA` as statements of their own — with every
    relation they create or name qualified as Postgres resolves it on the
    search path the SQL sets (`SET [LOCAL] search_path` / `SET SCHEMA`,
    `RESET`, `DISCARD ALL`, a plain `SELECT set_config('search_path', …)`;
    `$user` after a `SET ROLE` / `SET SESSION AUTHORIZATION`). The settings
    of statements `after` rejects (before a `\\\\connect`) are another
    session's. SQL whose search path pgrls cannot follow is refused. One set
    by running code (a `DO` block, a function) is not seen."""
    void = _rolled_back(statements)
    live = [raw for index, raw in enumerate(statements) if index not in void]
    schemas = [raw.stmt for raw in live if isinstance(raw.stmt, _pgast.CreateSchemaStmt)]
    # A DROP TABLE takes a partitioned table's partitions with it, and a
    # DROP TABLE or COLUMN the sequences it owns (`serial`, identity,
    # `OWNED BY`).
    dependents = any(_makes_dependents(stmt) for raw in live
                     for stmt in (raw.stmt, *(getattr(raw.stmt, "schemaElts", None) or ())))
    if any(stmt.schemaname is None and getattr(stmt.authrole, "rolename", None) is None
           for stmt in schemas):
        raise SchemaSourceError(
            "bad_sql",
            "the SQL creates a schema named for the role psql connects as "
            "(CREATE SCHEMA AUTHORIZATION CURRENT_USER), which pgrls does not know.",
        )
    resolver = _Resolver(
        # `public` is in every new database; one created only IF NOT EXISTS
        # may have been there before.
        created={_schema_created(stmt) for stmt in schemas
                 if not stmt.if_not_exists} - {"public"},
        maybe={_schema_created(stmt) for stmt in schemas if stmt.if_not_exists} - {"public"},
        # A schema named as the role that owns it (`AUTHORIZATION r`, or
        # `OWNER TO r` as pg_dump writes it), or `AUTHORIZATION CURRENT_USER`:
        # that role's own, if psql connects as it.
        for_roles={_schema_created(stmt) for stmt in schemas
                   if stmt.authrole is not None
                   and getattr(stmt.authrole, "rolename", None) in (None, stmt.schemaname,
                                                                     _schema_created(stmt))}
        | {str(raw.stmt.object.sval) for raw in live
           if isinstance(raw.stmt, _pgast.AlterOwnerStmt)
           and raw.stmt.objectType == ObjectType.OBJECT_SCHEMA
           and getattr(raw.stmt.newowner, "rolename", None) in (None, raw.stmt.object.sval)},
        named={node.schemaname for raw in live for node in _subnodes(raw.stmt)
               if isinstance(node, _pgast.RangeVar) and node.schemaname})
    out: list[_Stmt] = []
    for raw in live:
        if not after(raw):
            # Another session's: what it leaves the next one is a database's
            # or role's search_path setting.
            path, role = _sets_for_next_session(raw.stmt)
            resolver.inherited |= path
            resolver.inherited_role |= role
            continue
        resolver.start()
        stmt = raw.stmt
        path, role = _sets_for_next_session(stmt)
        resolver.next_inherited |= path
        resolver.next_inherited_role |= role
        if isinstance(stmt, _pgast.CreateSchemaStmt):
            schema = _schema_created(stmt)
            if schema not in resolver.schemas or schema in resolver.unsure:
                # (An IF NOT EXISTS of one certainly there is a no-op.)
                # Its creator is the role it runs as, unless AUTHORIZATION
                # names one; IF NOT EXISTS of one the SQL never made may find
                # it there, owned by someone pgrls does not know.
                resolver.owners[schema] = (
                    _SOME_ROLE if stmt.if_not_exists and schema not in resolver.dropped
                    else resolver.role_of(stmt.authrole) if stmt.authrole is not None
                    else resolver.role_of(None))
            resolver.schemas.add(schema)
            resolver.unsure.discard(schema)
            for element in stmt.schemaElts or ():
                # Its elements go in it, and see it first.
                with resolver.first(schema):
                    resolver.track(element)
                    resolver.qualify(element)
                out.append(_Stmt(element, raw))
            out.append(_Stmt(stmt, raw))
            continue
        resolver.track(stmt)
        resolver.qualify(stmt)
        if _runs_code(stmt) or _may_drop_unseen(stmt, dependents):
            resolver.code_ran = True
        out.append(_Stmt(stmt, raw))
    return out


def _schema_created(stmt: Any) -> str:
    """The schema a `CREATE SCHEMA` creates (`AUTHORIZATION r` alone names
    it for the role)."""
    return _truncated(stmt.schemaname or getattr(stmt.authrole, "rolename", None) or "")


def _truncated(name: str) -> str:
    raw = name.encode()
    if len(raw) <= _NAME_BYTES:
        return name
    return raw[:_NAME_BYTES].decode(errors="ignore")


def ends_in_transaction(sql: str) -> bool:
    """Whether `sql` (a migration file) leaves a transaction open over a
    statement, which migration runners end otherwise: psql rolls it back,
    `psql -1` and a driver's `with` block (`lint --migrations`) commit it.
    False for SQL that does not parse (reading it all reports that)."""
    sql, _ = _split_psql_meta_commands(sql)
    try:
        statements = pglast.parse_sql(sql)
        start = _transaction_state(statements)[1]
    except (pglast.parser.ParseError, SchemaSourceError):
        return False
    if start is None:
        return False
    # The open transaction holds what follows its BEGIN, or (one an AND
    # CHAIN opened) what follows the COMMIT / ROLLBACK, at `start`.
    opener = statements[start].stmt if start < len(statements) else None
    if isinstance(opener, _pgast.TransactionStmt) and opener.kind in (
            TransactionStmtKind.TRANS_STMT_BEGIN, TransactionStmtKind.TRANS_STMT_START):
        start += 1
    return start < len(statements)


def _rolled_back(statements: Any) -> frozenset[int]:
    """The indexes of the statements a `ROLLBACK` (or `ROLLBACK TO
    SAVEPOINT`, or the end of the input in an open transaction) undoes."""
    void, start = _transaction_state(statements)
    if start is not None:
        # psql's session ends, and Postgres rolls the open transaction back.
        void |= set(range(start, len(statements)))
    return frozenset(void)


def _transaction_state(statements: Any) -> tuple[set[int], int | None]:
    """What the `ROLLBACK`s undo, and where a transaction still open at the
    end began."""
    void: set[int] = set()
    start: int | None = None
    savepoints: list[tuple[str, int]] = []
    for index, raw in enumerate(statements):
        stmt = raw.stmt
        if not isinstance(stmt, _pgast.TransactionStmt):
            continue
        kind = stmt.kind
        if kind in (TransactionStmtKind.TRANS_STMT_BEGIN, TransactionStmtKind.TRANS_STMT_START):
            if start is None:
                start = index
        elif kind == TransactionStmtKind.TRANS_STMT_COMMIT and start is not None:
            # AND CHAIN opens the next transaction after it.
            start, savepoints = (index + 1 if stmt.chain else None), []
        elif kind == TransactionStmtKind.TRANS_STMT_ROLLBACK and start is not None:
            # The ROLLBACK itself stands: it ends the transaction.
            void.update(range(start, index))
            start, savepoints = (index + 1 if stmt.chain else None), []
        elif kind == TransactionStmtKind.TRANS_STMT_SAVEPOINT and start is not None:
            savepoints.append((stmt.savepoint_name, index))
        elif kind in (TransactionStmtKind.TRANS_STMT_RELEASE,
                      TransactionStmtKind.TRANS_STMT_ROLLBACK_TO) and start is not None:
            names = [name for name, _ in savepoints]
            if stmt.savepoint_name not in names:
                continue
            at = len(names) - 1 - names[::-1].index(stmt.savepoint_name)
            if kind == TransactionStmtKind.TRANS_STMT_ROLLBACK_TO:
                void.update(range(savepoints[at][1] + 1, index + 1))
                del savepoints[at + 1:]
            else:
                del savepoints[at:]
        elif kind in (TransactionStmtKind.TRANS_STMT_PREPARE,
                      TransactionStmtKind.TRANS_STMT_COMMIT_PREPARED,
                      TransactionStmtKind.TRANS_STMT_ROLLBACK_PREPARED):
            raise SchemaSourceError(
                "bad_sql",
                "the SQL prepares a transaction (PREPARE TRANSACTION), whose "
                "effects pgrls cannot tell apart.",
            )
    return void, start


# A role pgrls cannot name: a schema's owner it does not know (one there
# before the SQL, or one a REASSIGN OWNED may have passed on), or the role
# CURRENT_USER is when a \connect'ed database or role sets `role`.
_SOME_ROLE = "\0some role"


def _may_be(owner: str | None, roles: AbstractSet[str | None]) -> bool:
    """Whether `owner` may be one of `roles` though not named so: the
    connecting role (None) may be any named one, and one pgrls cannot name
    any at all."""
    if owner == _SOME_ROLE or _SOME_ROLE in roles:
        return True
    return (owner is None and any(r is not None for r in roles)) or (
        owner is not None and None in roles)


def _sets_for_next_session(stmt: Any) -> tuple[bool, bool]:
    """Whether a statement sets the search_path, and the role, a session
    started after it begins with (a database's, a role's, or the server's
    once reloaded)."""
    if not isinstance(stmt, (_pgast.AlterDatabaseSetStmt, _pgast.AlterRoleSetStmt,
                             _pgast.AlterSystemStmt)):
        return False, False
    name = (stmt.setstmt.name or "").lower()
    reset_all = stmt.setstmt.kind == VariableSetKind.VAR_RESET_ALL
    # The role the next session runs as is `$user` too.
    return reset_all or name == "search_path", reset_all or name == "role"


class _Resolver:
    """The session state that decides where a relation name resolves, as the
    statements run in order."""

    def __init__(self, *, created: AbstractSet[str], maybe: AbstractSet[str],
                 for_roles: AbstractSet[str], named: AbstractSet[str]) -> None:
        # The schemas the SQL creates, and of those, the ones created so far.
        # One it never creates is taken to be there already (`public`, or
        # one a migration's earlier SQL made), unless it drops it; one it
        # does not even name a relation in may not be (see create_schema).
        self.created = created
        self.maybe = set(maybe) - set(created)
        self.for_roles = for_roles
        self.named = set(named) | {"public"}
        self.schemas: set[str] = set()
        self.dropped: set[str] = set()
        # A schema's owner as the SQL gives it (None: the connecting role),
        # and the schemas a `DROP OWNED` may have dropped.
        self.owners: dict[str, str | None] = {}
        self.unsure: set[str] = set()
        self.dropped_owned = False
        # `GRANT USAGE ON SCHEMA s TO r` (r None: PUBLIC), and the schemas
        # whose USAGE for PUBLIC the SQL revoked.
        self.usage: set[tuple[str, str | None]] = set()
        self.revoked: set[tuple[str, str | None]] = set()
        self.relations: set[tuple[str, str]] = set()
        self.temp: set[str] = set()
        self.commit_drop: set[str] = set()  # temporary, ON COMMIT DROP
        # Session settings, and the transaction's own (`SET LOCAL`) over
        # them: the search path, the role, the session user (None for the
        # connecting one, which pgrls does not know).
        self.session: dict[str, Any] = {
            "search_path": _DEFAULT_SEARCH_PATH, "role": None, "auth": None}
        self.local: dict[str, Any] = {}
        self.in_transaction = False
        self.inherited = False
        self.inherited_role = False
        # A database's or role's setting the SQL makes: a session after it
        # (`snapshot --migrations`' next file, from its DISCARD ALL) starts
        # with it.
        self.next_inherited = False
        self.next_inherited_role = False
        # Code ran (a DO block, a CALL, a function): it may have dropped a
        # relation the model still has.
        self.code_ran = False
        self.started = False
        self.override: list[str] = []

    def start(self) -> None:
        if not self.started:
            self.started = True
            if self.inherited:
                # The database or role it connects as may set it.
                self.session["search_path"] = None

    def _get(self, key: str) -> Any:
        return self.local[key] if key in self.local else self.session[key]

    def _set(self, key: str, value: Any, *, local: bool) -> None:
        if not local:
            self.session[key] = value
            self.local.pop(key, None)
        elif self.in_transaction:
            # Outside a transaction it lasts only its own statement.
            self.local[key] = value

    @property
    def path(self) -> tuple[str, ...] | None:
        path: tuple[str, ...] | None = self._get("search_path")
        if path is None:
            return None
        return tuple(self.override) + path

    @contextlib.contextmanager
    def first(self, schema: str) -> Any:
        self.override.insert(0, schema)
        try:
            yield
        finally:
            self.override.pop(0)

    def track(self, stmt: Any) -> None:
        """Follow what `stmt` sets."""
        if isinstance(stmt, _pgast.TransactionStmt):
            if stmt.kind in (TransactionStmtKind.TRANS_STMT_BEGIN,
                             TransactionStmtKind.TRANS_STMT_START):
                self.in_transaction = True
            elif stmt.kind in (TransactionStmtKind.TRANS_STMT_COMMIT,
                               TransactionStmtKind.TRANS_STMT_ROLLBACK):
                # A rolled-back transaction's BEGIN was left out, so AND
                # CHAIN alone says one is open.
                self.in_transaction = bool(stmt.chain)
                self.local.clear()
                self._discard_temp(set(self.commit_drop))
            return
        if isinstance(stmt, _pgast.DiscardStmt):
            if stmt.target in (DiscardMode.DISCARD_ALL, DiscardMode.DISCARD_TEMP):
                self._discard_temp(set(self.temp))
            if stmt.target == DiscardMode.DISCARD_ALL:
                # (In the same session its defaults are those it connected
                # with: taking a setting made since is only more cautious.)
                self.inherited |= self.next_inherited
                self.inherited_role |= self.next_inherited_role
                self._set("search_path", self._default(), local=False)
                self._set("role", None, local=False)
                self._set("auth", None, local=False)
            return
        if isinstance(stmt, _pgast.VariableSetStmt):
            name = (stmt.name or "").lower()
            local = bool(stmt.is_local)
            if stmt.kind == VariableSetKind.VAR_RESET_ALL:
                # Not the role or the session user: Postgres leaves those.
                self._set("search_path", self._default(), local=False)
            elif name == "search_path":
                if stmt.kind in (VariableSetKind.VAR_SET_DEFAULT, VariableSetKind.VAR_RESET):
                    self._set("search_path", self._default(), local=local)
                elif stmt.kind == VariableSetKind.VAR_SET_VALUE:
                    # Each item is one schema, a quoted string too (Postgres
                    # quotes it); an empty one (`SET search_path = ''`) names
                    # none, no schema having an empty name.
                    self._set("search_path", tuple(
                        item for a in stmt.args or ()
                        if (item := _truncated(str(getattr(a.val, "sval", ""))))
                    ), local=local)
            elif name in ("role", "session_authorization"):
                value = (str(getattr(stmt.args[0].val, "sval", ""))
                         if stmt.kind == VariableSetKind.VAR_SET_VALUE and stmt.args else None)
                value = None if value is None or value == "none" else _truncated(value)
                if name == "session_authorization":
                    # It sets the session user, and the role back to it.
                    self._set("auth", value, local=local)
                self._set("role", value if name == "role" else None, local=local)
            return
        if _only_defines(stmt):
            return  # a definition: its expressions run when it is used
        for node in _subnodes(stmt):
            if not (isinstance(node, _pgast.FuncCall)
                    and ast_utils.func_name_parts(node)[1] == "set_config"):
                continue
            args: tuple[Any, ...] = tuple(node.args or ())
            name = _uncast(args[0]) if args else None
            setting = str(getattr(getattr(name, "val", None), "sval", "")).lower()
            if setting not in ("search_path", "role", "session_authorization"):
                continue
            value, is_local = (_uncast(args[i]) if len(args) > i else None for i in (1, 2))
            if not (_is_plain_select_of(stmt, node)
                    and isinstance(value, _pgast.A_Const)
                    and isinstance(getattr(value.val, "sval", None), str)
                    and isinstance(is_local, _pgast.A_Const)
                    and isinstance(getattr(is_local.val, "boolval", None), bool)):
                raise SchemaSourceError(
                    "bad_sql",
                    f"the SQL sets {setting} with set_config() other than in "
                    "a plain SELECT of literals; pgrls cannot tell which schema "
                    "an unqualified name is in.",
                )
            if setting != "search_path":
                # As SET ROLE / SET SESSION AUTHORIZATION (for `$user`).
                role = value.val.sval
                # `none` exactly is no role (`'default'` is one so named).
                role = None if setting == "role" and role == "none" else _truncated(role)
                if setting == "session_authorization":
                    self._set("auth", role, local=is_local.val.boolval)
                self._set("role", role if setting == "role" else None,
                          local=is_local.val.boolval)
                continue
            names = _identifier_list(value.val.sval)
            if names is not None:  # else Postgres refuses it
                self._set("search_path", tuple(_truncated(n) for n in names),
                          local=is_local.val.boolval)

    def _default(self) -> tuple[str, ...] | None:
        # What RESET goes back to: the session's default.
        return None if self.inherited else _DEFAULT_SEARCH_PATH

    def _discard_temp(self, names: AbstractSet[str]) -> None:
        self.temp -= names
        self.commit_drop -= names
        self.relations -= {(_NOWHERE, name) for name in names}

    def role_of(self, spec: Any) -> str | None:
        """The role a RoleSpec names (None: the connecting one, which pgrls
        does not know); a missing one is the role the SQL runs as."""
        role: str | None
        if spec is None or spec.roletype in (RoleSpecType.ROLESPEC_CURRENT_USER,
                                             RoleSpecType.ROLESPEC_CURRENT_ROLE):
            role = self._get("role") or self._get("auth")
        elif spec.roletype == RoleSpecType.ROLESPEC_SESSION_USER:
            role = self._get("auth")
        else:
            role = getattr(spec, "rolename", None)
        if role is None and self.inherited_role:
            # The connecting role or the one its settings set, by turns.
            return _SOME_ROLE
        return role

    def exists(self, schema: str) -> bool:
        if schema in self.unsure or (
                self.dropped_owned and schema not in self.owners
                and schema not in ("public", "pg_catalog")):
            raise SchemaSourceError(
                "bad_sql",
                f"the SQL resolves a name on search_path schema {schema!r} after a "
                f"DROP OWNED that may have dropped it (pgrls does not know its owner, "
                f"or the role psql connects as); qualify the names.",
            )
        if schema in self.schemas:
            return True
        if schema in self.maybe and schema not in self.dropped:
            # Created only IF NOT EXISTS, later: it may have been there.
            raise SchemaSourceError(
                "bad_sql",
                f"the SQL resolves a name on search_path schema {schema!r} before "
                f"it creates it IF NOT EXISTS; pgrls cannot tell whether it was "
                f"there. Qualify the names.",
            )
        return schema not in self.created and schema not in self.dropped

    def _entries(self, *, check_usage: bool = True) -> Any:
        """The schemas on the path that exist, `$user` named, in order;
        refuses a path pgrls cannot follow."""
        path = self.path
        if path is None:
            raise SchemaSourceError(
                "bad_sql",
                "the SQL connects to a database or as a role that sets "
                "search_path (a \\connect, or a later migration file's session "
                "after an ALTER DATABASE / ALTER ROLE / ALTER SYSTEM … SET); pgrls cannot tell "
                "which schema an unqualified name is in. Set it after, or "
                "qualify the names.",
            )
        role = self._get("role") or self._get("auth")
        for entry in path:
            if entry == "$user":
                # A role is taken to have no schema of its own unless the
                # SQL creates one; the connecting role is not known.
                if role is None and self.inherited_role:
                    raise SchemaSourceError(
                        "bad_sql",
                        "the SQL connects to a database or as a role that sets the "
                        "role it runs as (a \\connect, or a later migration file's "
                        "session after an ALTER … SET role), and resolves a name on "
                        "\"$user\"; pgrls "
                        "cannot tell which schema that is. Qualify the names.",
                    )
                if role is None and self.for_roles & self.schemas:
                    raise SchemaSourceError(
                        "bad_sql",
                        "the SQL creates a schema for a role "
                        f"({sorted(self.for_roles & self.schemas)[0]!r}) and resolves a "
                        "name on \"$user\" with no SET ROLE; pgrls does not know the "
                        "role psql connects as. Qualify the names.",
                    )
                if role is None or role not in self.schemas:
                    continue
                entry = role
            if entry == "pg_temp":
                raise SchemaSourceError(
                    "bad_sql",
                    "the SQL puts pg_temp on search_path, which pgrls does not "
                    "follow; qualify the names.",
                )
            if self.exists(entry):  # Postgres skips one that does not
                if check_usage:
                    self._check_usage(entry)
                yield entry

    def _check_usage(self, schema: str) -> None:
        """Postgres also skips a schema the running role has no USAGE on;
        after a SET ROLE / SET SESSION AUTHORIZATION, refuse one the SQL does
        not show the role may use (owns it, or was granted USAGE on it)."""
        role = self._get("role") or self._get("auth")
        if role is None or role == _SOME_ROLE:
            return
        if (schema == "public" and (schema, None) not in self.revoked) or (
                self.owners.get(schema) == role and (schema, role) not in self.revoked) or (
                schema, role) in self.usage or (schema, None) in self.usage:
            return
        raise SchemaSourceError(
            "bad_sql",
            f"the SQL runs as role {role!r} and resolves a name on search_path schema "
            f"{schema!r}, which the role may have no USAGE on (Postgres then skips it); "
            f"pgrls cannot tell. Qualify the names.",
        )

    def create_schema(self, *, looking_up: bool = False) -> str:
        """Where an unqualified CREATE puts its relation (or where a name
        not found would be, `looking_up`)."""
        # (Only as far as the first entry: Postgres goes no further.)
        entries = iter(self._entries())
        if looking_up:
            # Postgres looks on past the catalog; with nothing else on the
            # path the name is not one the SQL made: a catalog's (pg_dump
            # leaves `pg_roles` unqualified under its empty path), an IF
            # EXISTS no-op, or an error.
            entries = (entry for entry in entries if entry != "pg_catalog")
        first: str | None = next(entries, None)
        if first is None and looking_up:
            return _NOWHERE
        if first == "pg_catalog":
            raise SchemaSourceError(
                "bad_sql",
                "the SQL creates a relation with pg_catalog first on search_path "
                "(Postgres refuses: permission denied to create in pg_catalog); "
                "qualify the names.",
            )
        if first is None:
            # "no schema has been selected to create in": the statement
            # errors, which pgrls cannot model as succeeding (a dump's empty
            # search_path left in force over SQL after it, say).
            raise SchemaSourceError(
                "bad_sql",
                "the SQL creates a relation with no schema on search_path to "
                "create it in (Postgres errors; a dump sets search_path to '' "
                "and SQL after it in the same psql session sees that); qualify "
                "the names, or give a migration directory to `snapshot "
                "--migrations`, which runs each file in a session of its own.",
            )
        if first not in self.schemas and first not in self.created and first not in self.named:
            # Postgres creates in it if it exists, else in the next one.
            raise SchemaSourceError(
                "bad_sql",
                f"the SQL {'names' if looking_up else 'creates'} a relation on a "
                f"search_path whose first schema ({first!r}) it neither creates nor "
                f"names a relation in; pgrls cannot tell whether it exists. Qualify "
                f"the names.",
            )
        return first

    def find(self, name: str) -> tuple[str, bool]:
        """The schema a reference to `name` finds it in, and whether it is
        one the SQL created (else where a CREATE would go)."""
        if name in self.temp and self.path is not None and "pg_temp" not in self.path:
            # Searched first unless the path names it.
            if self.code_ran and self._holders(name):
                raise SchemaSourceError(
                    "bad_sql",
                    f"the SQL runs code (a DO block, a CALL, a function) or a DROP "
                    f"that may have dropped a relation it does not name (a CASCADE, "
                    f"a partition, DROP OWNED), and then names {name!r}, which is a "
                    f"temporary table's and another's; pgrls cannot tell which "
                    f"remains. Qualify the name.",
                )
            return _NOWHERE, True
        holders = self._holders(name)
        if len(holders) > 1:
            # The first may be gone or moved by something pgrls does not
            # follow (a CASCADE, an extension's or an owned sequence's drop,
            # a view made temporary): Postgres would then find the next.
            raise SchemaSourceError(
                "bad_sql",
                f"the SQL names {name!r}, which more than one schema on its "
                f"search_path holds ({', '.join(map(repr, holders))}); pgrls cannot "
                f"tell whether the first is still there. Qualify the name.",
            )
        if holders:
            return holders[0], True
        entries = [entry for entry in self._entries() if entry != "pg_catalog"]
        if len(entries) == 1:
            return entries[0], False  # the one place it can be (else it errors)
        return self.create_schema(looking_up=True), False

    def _holders(self, name: str) -> list[str]:
        """The schemas on the path that hold `name`, in order, up to an
        entry pgrls cannot follow (refused only if none was found before
        it: Postgres stops at the first)."""
        found: list[str] = []
        entries = self._entries(check_usage=False)
        while True:
            try:
                entry = next(entries)
            except StopIteration:
                return found
            except SchemaSourceError:
                if found and not self.code_ran:
                    return found
                raise  # the first may be gone, and Postgres would go on
            if (entry, name) in self.relations:
                # One the running role may not use (so Postgres may skip it)
                # decides nothing.
                self._check_usage(entry)
                found.append(entry)

    def qualify(self, stmt: Any) -> None:
        """Qualify each relation `stmt` creates or names, and follow what it
        creates, drops and renames."""
        given = {id(rel) for rel, _ in _named_relations(stmt) if rel.schemaname}
        if isinstance(stmt, _pgast.ViewStmt) and stmt.view.relpersistence != "t" and any(
                isinstance(n, _pgast.RangeVar) and n.relname in self.temp
                and n.schemaname in (None, "", "pg_temp")
                for n in _subnodes(stmt.query)):
            # A view on a temporary table is temporary too.
            stmt.view.relpersistence = "t"
        for rel, creates in _named_relations(stmt):
            if creates:
                if rel.relpersistence == "t" or rel.schemaname == "pg_temp":
                    rel.schemaname = _NOWHERE
                    if rel.relname in self.temp and getattr(stmt, "if_not_exists", False):
                        continue  # IF NOT EXISTS: the one there stands
                    if _drops_on_commit(stmt):
                        if not self.in_transaction:
                            continue  # gone when its statement commits
                        self.commit_drop.add(rel.relname)
                    self.temp.add(rel.relname)
                elif not rel.schemaname:
                    rel.schemaname = self.create_schema()
                self.relations.add((rel.schemaname, rel.relname))
            elif not rel.schemaname:
                rel.schemaname = self.find(rel.relname)[0]
        if isinstance(stmt, (_pgast.CreatePolicyStmt, _pgast.AlterPolicyStmt)):
            self._qualify_policy(stmt)
        elif isinstance(stmt, _pgast.DropStmt):
            self._drop(stmt)
        elif (isinstance(stmt, _pgast.AlterOwnerStmt)
              and stmt.objectType == ObjectType.OBJECT_SCHEMA):
            schema = str(getattr(stmt.object, "sval", ""))
            self.owners[schema] = self.role_of(stmt.newowner)
            # The new owner takes the old one's privileges.
            self.revoked.discard((schema, self.owners[schema]))
        elif (isinstance(stmt, _pgast.GrantStmt) and stmt.objtype == ObjectType.OBJECT_SCHEMA
              and not (not stmt.is_grant and stmt.grant_option)  # GRANT OPTION FOR only
              and (stmt.privileges is None or any(
                  getattr(p, "priv_name", None) == "usage" for p in stmt.privileges))):
            for item in stmt.objects or ():
                schema = str(getattr(item, "sval", ""))
                for grantee in stmt.grantees or ():
                    who = (None if grantee.roletype == RoleSpecType.ROLESPEC_PUBLIC
                           else self.role_of(grantee))
                    (self.usage.add if stmt.is_grant else self.usage.discard)((schema, who))
                    # (An owner may revoke its own USAGE too.)
                    (self.revoked.discard if stmt.is_grant else self.revoked.add)((schema, who))
        elif isinstance(stmt, _pgast.ReassignOwnedStmt):
            # Their schemas pass to the new role; one that may be among them
            # (the connecting role is no name pgrls knows) passes to one
            # pgrls cannot name.
            from_roles = {self.role_of(r) for r in stmt.roles or ()}
            to_role = self.role_of(stmt.newrole)
            for schema, owner in list(self.owners.items()):
                if owner in from_roles and owner != _SOME_ROLE:
                    self.owners[schema] = to_role
                elif _may_be(owner, from_roles):
                    self.owners[schema] = _SOME_ROLE
        elif (isinstance(stmt, _pgast.RenameStmt)
              and stmt.renameType == ObjectType.OBJECT_ROLE and stmt.newname):
            for schema, owner in list(self.owners.items()):
                if owner is not None and owner == stmt.subname:
                    self.owners[schema] = stmt.newname
            rename = {stmt.subname: stmt.newname}
            self.usage = {(s, rename.get(r, r) if r is not None else None) for s, r in self.usage}
            self.revoked = {(s, rename.get(r, r) if r is not None else None)
                            for s, r in self.revoked}
        elif isinstance(stmt, _pgast.DropOwnedStmt):
            # It drops the schemas the roles own; one whose owner may be
            # among them is then unsure, and so is any schema the SQL gave
            # no owner (one there before it), `public` aside.
            roles = {self.role_of(r) for r in stmt.roles or ()}
            for schema, owner in list(self.owners.items()):
                if schema in self.dropped and schema not in self.schemas:
                    continue
                if owner in roles and owner is not None and owner != _SOME_ROLE:
                    self.schemas.discard(schema)
                    self.dropped.add(schema)
                    self.relations -= {r for r in self.relations if r[0] == schema}
                    self.usage = {u for u in self.usage if u[0] != schema}
                    self.revoked = {r for r in self.revoked if r[0] != schema} | {(schema, None)}
                elif owner == _SOME_ROLE or _may_be(owner, roles) or owner in roles:
                    self.unsure.add(schema)
            self.dropped_owned = True
            # It also revokes what was granted to them.
            self.usage = {u for u in self.usage
                          if not (u[1] in roles or (u[1] is not None and _may_be(u[1], roles)))}
        elif (isinstance(stmt, _pgast.AlterObjectSchemaStmt) and stmt.relation is not None
              and stmt.newschema):
            # A view, sequence, matview or foreign table moves (a table's
            # move is refused).
            if not stmt.relation.schemaname:
                stmt.relation.schemaname = self.find(stmt.relation.relname)[0]
            old = (stmt.relation.schemaname, stmt.relation.relname)
            if old in self.relations:
                self.relations.discard(old)
                self.relations.add((stmt.newschema, old[1]))
        elif (isinstance(stmt, _pgast.RenameStmt) and stmt.relation is not None
              # `ALTER INDEX app.t RENAME` renames a table too; an unqualified
              # name may be an index pgrls does not track.
              and (stmt.renameType in _RELATION_KINDS or (
                  stmt.renameType == ObjectType.OBJECT_INDEX and id(stmt.relation) in given))
              and stmt.newname):
            old = (stmt.relation.schemaname, stmt.relation.relname)
            if old in self.relations:
                self.relations.discard(old)
                self.relations.add((old[0], stmt.newname))
            if old[0] == _NOWHERE and old[1] in self.temp:
                # (Not a name found nowhere: an IF EXISTS no-op.)
                self.temp.discard(old[1])
                self.temp.add(stmt.newname)
                if old[1] in self.commit_drop:
                    self.commit_drop.discard(old[1])
                    self.commit_drop.add(stmt.newname)

    def _qualify_policy(self, stmt: Any) -> None:
        # A table a policy reads resolves when the policy is created; one
        # in another schema than the policy's own is named with it, which
        # is how the rules read an unqualified name.
        own = stmt.table.schemaname
        nodes = [n for clause in (stmt.qual, stmt.with_check) if clause is not None
                 for n in _subnodes(clause)]
        ctes = {n.ctename for n in nodes if isinstance(n, _pgast.CommonTableExpr)}
        for node in nodes:
            if isinstance(node, _pgast.RangeVar) and not node.schemaname \
                    and node.relname not in ctes:
                schema, found = self.find(node.relname)
                if schema == _NOWHERE and not found and not node.relname.startswith("pg_"):
                    # No schema on the path to find it in, and no catalog's
                    # (pg_dump leaves `pg_roles` unqualified): Postgres errors.
                    raise SchemaSourceError(
                        "bad_sql",
                        f"the SQL creates a policy reading {node.relname!r} with no "
                        f"schema on search_path to find it in (Postgres errors); "
                        f"qualify the names.",
                    )
                if found and schema != own:
                    node.schemaname = schema

    def _drop(self, stmt: Any) -> None:
        if stmt.removeType == ObjectType.OBJECT_SCHEMA:
            for item in stmt.objects or ():
                schema = str(getattr(item, "sval", ""))
                # Without CASCADE it errors unless it is empty, so what the
                # model holds there is already gone (taken with a parent, a
                # CASCADE or code).
                self.schemas.discard(schema)
                self.dropped.add(schema)
                self.unsure.discard(schema)
                self.relations -= {r for r in self.relations if r[0] == schema}
                # One made again grants USAGE to no one (`public` too), and
                # its owner has it.
                self.usage = {u for u in self.usage if u[0] != schema}
                self.revoked = {r for r in self.revoked if r[0] != schema} | {(schema, None)}
            return
        if stmt.removeType not in _RELATION_KINDS and stmt.removeType != ObjectType.OBJECT_POLICY:
            return
        objects = []
        for item in stmt.objects or ():
            parts = list(item) if isinstance(item, (list, tuple)) else []
            table = parts[:-1] if stmt.removeType == ObjectType.OBJECT_POLICY else parts
            if len(table) == 1 and isinstance(table[0], _pgast.String):
                schema = self.find(table[0].sval)[0]
                parts.insert(0, _pgast.String(sval=schema))
            if stmt.removeType != ObjectType.OBJECT_POLICY and len(parts) == 2:
                key = (parts[0].sval, parts[1].sval)
                self.relations.discard(key)
                if key[0] == _NOWHERE:
                    self.temp.discard(key[1])
                    self.commit_drop.discard(key[1])
            objects.append(tuple(parts) if parts else item)
        stmt.objects = tuple(objects)


def _uncast(node: Any) -> Any:
    """`node` through the casts that keep a literal as it is (`'x'::text`,
    as pg_dump writes one, `true::boolean`); one that may change it
    (`::varchar(3)`) is left, so the literal is not read."""
    while isinstance(node, _pgast.TypeCast) and _keeps_literal(node.typeName):
        node = node.arg
    return node


def _keeps_literal(typename: Any) -> bool:
    # The built-in type: a user type of the name is refused (`_type_named`).
    names = [getattr(n, "sval", None) for n in typename.names or ()]
    return (len(names) == 1 or (len(names) == 2 and names[0] == "pg_catalog")) \
        and names[-1] in _LITERAL_CASTS \
        and not typename.typmods and not typename.arrayBounds


_LITERAL_CASTS = frozenset({"text", "bool", "boolean", "varchar"})


def _type_named(stmt: Any) -> str | None:
    """The name of the type or domain `stmt` creates (or renames one to),
    else None."""
    if (isinstance(stmt, _pgast.RenameStmt)
            and stmt.renameType in (ObjectType.OBJECT_TYPE, ObjectType.OBJECT_DOMAIN)):
        return str(stmt.newname or "") or None
    if isinstance(stmt, (_pgast.CreateDomainStmt,)):
        names = stmt.domainname
    elif isinstance(stmt, (_pgast.CreateEnumStmt, _pgast.CreateRangeStmt)):
        names = stmt.typeName
    elif isinstance(stmt, _pgast.DefineStmt) and stmt.kind == ObjectType.OBJECT_TYPE:
        names = stmt.defnames
    elif isinstance(stmt, _pgast.CompositeTypeStmt):
        return str(stmt.typevar.relname)
    else:
        return None
    return str(getattr((names or (None,))[-1], "sval", "")) or None


def _drops_on_commit(stmt: Any) -> bool:
    on_commit = (stmt.oncommit if isinstance(stmt, _pgast.CreateStmt)
                 else getattr(getattr(stmt, "into", None), "onCommit", None))
    return bool(on_commit == OnCommitAction.ONCOMMIT_DROP)


def _makes_dependents(stmt: Any) -> bool:
    """Whether `stmt` makes a relation dropped with a table or column: a
    partitioned table, or a sequence a column owns."""
    if isinstance(stmt, _pgast.CreateStmt) and stmt.partspec is not None:
        return True
    if not isinstance(stmt, (_pgast.CreateStmt, _pgast.AlterTableStmt,
                             _pgast.CreateSeqStmt, _pgast.AlterSeqStmt)):
        return False
    for node in _subnodes(stmt):
        if isinstance(node, _pgast.DefElem) and node.defname == "owned_by":
            return True
        if isinstance(node, _pgast.Constraint) and node.contype == ConstrType.CONSTR_IDENTITY:
            return True
        if isinstance(node, _pgast.ColumnDef) and node.typeName is not None and any(
                getattr(n, "sval", "") in ("serial", "bigserial", "smallserial",
                                           "serial2", "serial4", "serial8")
                for n in node.typeName.names or ()):
            return True
    return False


def _may_drop_unseen(stmt: Any, dependents: bool) -> bool:
    """Whether `stmt` may drop a relation it does not name: a CASCADE (a view
    on the table), `DROP OWNED`, an extension's members; when the SQL makes
    relations that go with a table or column (`dependents`: a partition, a
    sequence it owns), a DROP TABLE or DROP COLUMN."""
    if isinstance(stmt, _pgast.DropOwnedStmt):
        return True
    if isinstance(stmt, _pgast.AlterTableStmt):
        return any(getattr(cmd, "subtype", None) == AlterTableType.AT_DropColumn
                   and (dependents or cmd.behavior == DropBehavior.DROP_CASCADE)
                   for cmd in stmt.cmds or ())
    return isinstance(stmt, _pgast.DropStmt) and (
        stmt.behavior == DropBehavior.DROP_CASCADE
        or stmt.removeType == ObjectType.OBJECT_EXTENSION
        or (dependents and stmt.removeType == ObjectType.OBJECT_TABLE))


def _runs_code(stmt: Any) -> bool:
    """Whether `stmt` runs code pgrls does not see into: a `DO` block, a
    `CALL`, an `EXECUTE`, a write or a read of a relation (which a trigger,
    rule or view may run code on), an event trigger, or a call of a function
    not `pg_catalog.`-named (pg_dump's own) in a statement that runs it now."""
    if isinstance(stmt, (_pgast.DoStmt, _pgast.CallStmt, _pgast.ExecuteStmt,
                         # A trigger or rule may fire, or (an event trigger)
                         # fire on every later statement.
                         _pgast.InsertStmt, _pgast.UpdateStmt, _pgast.DeleteStmt,
                         _pgast.MergeStmt, _pgast.TruncateStmt, _pgast.CopyStmt,
                         _pgast.RefreshMatViewStmt, _pgast.CreateEventTrigStmt)):
        return True
    if not _only_defines(stmt) and any(
            isinstance(n, _pgast.SelectStmt) and n.fromClause for n in _subnodes(stmt)):
        return True  # a view it reads may call a function
    return not _only_defines(stmt) and any(
        isinstance(n, _pgast.FuncCall)
        and not (ast_utils.func_name_parts(n)[0] or "").startswith("pg_catalog.")
        for n in _subnodes(stmt))


def _only_defines(stmt: Any) -> bool:
    """Whether `stmt` is a definition (a view, a new table's DEFAULT or
    CHECK, a column's SET DEFAULT, a policy, a rule, a trigger, a domain, a
    function, a matview WITH NO DATA) whose expressions run when it is used,
    not as it runs — anything else (a cursor, PREPARE, ALTER … USING, ADD
    COLUMN … DEFAULT on a table with rows) may run them now."""
    if isinstance(stmt, _pgast.CreateTableAsStmt):
        # `AS EXECUTE` evaluates its parameters even WITH NO DATA.
        return bool(stmt.into.skipData) and not isinstance(stmt.query, _pgast.ExecuteStmt)
    if isinstance(stmt, _pgast.AlterTableStmt):
        return all(getattr(cmd, "subtype", None) == AlterTableType.AT_ColumnDefault
                   for cmd in stmt.cmds or ())
    if isinstance(stmt, _pgast.CreateStmt) and stmt.partbound is not None:
        return False  # a partition bound is evaluated as the table is made
    return isinstance(stmt, (
        _pgast.ViewStmt, _pgast.CreateStmt, _pgast.CreatePolicyStmt, _pgast.AlterPolicyStmt,
        _pgast.RuleStmt, _pgast.CreateTrigStmt, _pgast.CreateDomainStmt,
        _pgast.CreateFunctionStmt, _pgast.AlterFunctionStmt))


# Relation kinds a name resolves among.
_RELATION_KINDS = frozenset({
    ObjectType.OBJECT_TABLE, ObjectType.OBJECT_VIEW, ObjectType.OBJECT_MATVIEW,
    ObjectType.OBJECT_SEQUENCE, ObjectType.OBJECT_FOREIGN_TABLE,
})


def _named_relations(stmt: Any) -> list[tuple[Any, bool]]:
    """The RangeVars `stmt` creates (True) or names as its target (False)."""
    out: list[tuple[Any, bool]] = []
    if isinstance(stmt, _pgast.CreateStmt):
        out.append((stmt.relation, True))
        out.extend((rel, False) for rel in stmt.inhRelations or ())
    elif isinstance(stmt, _pgast.CreateForeignTableStmt):
        out.append((stmt.base.relation, True))
    elif (created := _data_derived_relation(stmt) or _non_table_relation(stmt)) is not None:
        out.append((created, True))
    elif isinstance(stmt, _pgast.AlterTableStmt):
        out.append((stmt.relation, False))
        for cmd in stmt.cmds or ():
            name = getattr(getattr(cmd, "def_", None), "name", None)
            if isinstance(name, _pgast.RangeVar):
                out.append((name, False))
    elif isinstance(stmt, (_pgast.CreatePolicyStmt, _pgast.AlterPolicyStmt)):
        out.append((stmt.table, False))
    elif isinstance(stmt, _pgast.RenameStmt) and stmt.relation is not None:
        out.append((stmt.relation, False))
    elif isinstance(stmt, _pgast.GrantStmt):
        out.extend((obj, False) for obj in stmt.objects or ()
                   if isinstance(obj, _pgast.RangeVar))
    return [(rel, creates) for rel, creates in out if rel is not None]


def _is_plain_select_of(stmt: Any, call: Any) -> bool:
    """Whether `stmt` is a `SELECT` of `call` that runs it once: no FROM,
    WHERE or other clause that could skip or repeat it."""
    return (
        isinstance(stmt, _pgast.SelectStmt)
        and stmt.op == SetOperation.SETOP_NONE
        and not any(getattr(stmt, f, None) for f in (
            "fromClause", "whereClause", "groupClause", "havingClause", "limitCount",
            "limitOffset", "withClause", "valuesLists", "intoClause", "distinctClause",
            "windowClause"))
        and any(getattr(t, "val", None) is call for t in stmt.targetList or ())
    )


def _identifier_list(value: str) -> tuple[str, ...] | None:
    """The names in a comma-separated identifier list, as Postgres splits a
    search_path string (on ASCII whitespace; unquoted names downcased);
    None if malformed."""
    if "\v" in value:
        # Postgres 17 splits on a vertical tab, earlier ones do not.
        raise SchemaSourceError(
            "bad_sql",
            "the SQL sets search_path to a string holding a vertical tab, which "
            "Postgres versions split differently.",
        )
    names: list[str] = []
    i, n = 0, len(value)
    if not value.strip(_PG_SPACE):
        return ()
    while True:
        while i < n and value[i] in _PG_SPACE:
            i += 1
        if i < n and value[i] == '"':
            parts, j = [], i + 1
            while True:
                k = value.find('"', j)
                if k < 0:
                    return None
                if value[k + 1:k + 2] == '"':
                    parts.append(value[j:k + 1])
                    j = k + 2
                    continue
                parts.append(value[j:k])
                i = k + 1
                break
            names.append("".join(parts))
        else:
            j = i
            while i < n and value[i] != "," and value[i] not in _PG_SPACE:
                i += 1
            if i == j:
                return None
            names.append("".join(c.lower() if "A" <= c <= "Z" else c for c in value[j:i]))
        while i < n and value[i] in _PG_SPACE:
            i += 1
        if i == n:
            return tuple(names)
        if value[i] != ",":
            return None
        i += 1


class _TableBuilder:
    """Mutable accumulator for one table while walking the DDL statements."""

    def __init__(self, *, schema: str, name: str, created_at: int = -1) -> None:
        self.schema = schema
        self.name = name
        # Index of the statement that created this table, so a `DROP TABLE`
        # appearing EARLIER in the input cannot remove a LATER re-CREATE.
        self.created_at = created_at
        # The CREATE that made it: `created_at` advances to one merged into
        # it, this does not.
        self.made_at = created_at
        self.rls_enabled = False
        self.force_rls = False
        self.columns: list[Column] = []
        self.policies: list[Policy] = []
        self.grants: list[Grant] = []
        self.column_grants: list[ColumnGrant] = []
        self.partition_of: tuple[str, str] | None = None
        self.inherits: list[tuple[str, str]] = []
        # Whether its CREATE has `PARTITION BY`; None for a table the input
        # never created.
        self.partitioned: bool | None = None
        # Named NOT NULL constraints (PG18 can drop one by name) → columns.
        self.not_null_names: dict[str, set[str]] = {}
        # Every name the table, or a parent it inherits a NOT NULL from, has
        # had: an unnamed NOT NULL keeps the name it got at the time.
        self.former_names: list[str] = [name]
        # Columns NOT NULL only through a `NO INHERIT` constraint: an
        # `INHERITS` child does not get it.
        self.no_inherit_not_null: set[str] = set()
        # `NOT VALID` NOT NULL constraints → columns, until validated.
        self.invalid_not_null: dict[str, set[str]] = {}

    def set_not_null(self, colname: str, *, not_null: bool = True) -> None:
        """Flip one column's nullability in place (`SET`/`DROP NOT NULL`)."""
        for i, col in enumerate(self.columns):
            if col.name == colname:
                self.columns[i] = replace(col, is_nullable=not not_null)
                return

    def not_null_columns(self, conname: str) -> set[str]:
        """The columns a NOT NULL constraint of this name can be for: those it
        was named for, and — Postgres names an unnamed one
        `<table>_<column>_not_null`, shortening either name to fit and adding
        a digit on a clash — any column that name could be for. Erring wide
        only reads a column as nullable."""
        out = set(self.not_null_names.get(conname, ()))
        m = _AUTO_NOT_NULL.fullmatch(conname)
        if m is not None:
            stem = m.group(1)
            out.update(
                c.name for c in self.columns
                if any(any(t.startswith(stem[:cut]) for t in self.former_names)
                       and stem[cut + 1:] and c.name.startswith(stem[cut + 1:])
                       for cut, ch in enumerate(stem) if ch == "_")
            )
        return out

    def drop_constraint(self, conname: str) -> None:
        """`DROP CONSTRAINT`: a NOT NULL one makes its column nullable again."""
        for col in self.not_null_columns(conname):
            self.set_not_null(col, not_null=False)
        self.not_null_names.pop(conname, None)

    def rename_constraint(self, old: str, new: str) -> None:
        """`RENAME CONSTRAINT`: the NOT NULL keeps its column."""
        self.not_null_names.setdefault(new, set()).update(self.not_null_columns(old))
        self.not_null_names.pop(old, None)
        if old in self.invalid_not_null:
            self.invalid_not_null[new] = self.invalid_not_null.pop(old)

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
            grants=_merge_grants(self.grants),
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


def _only_no_inherit_not_null(constraints: Any) -> bool:
    """Whether `constraints` make a column NOT NULL only through a PG18
    `NOT NULL … NO INHERIT`, which an `INHERITS` child does not get."""
    kinds = [(getattr(c, "contype", None), bool(getattr(c, "is_no_inherit", False)))
             for c in constraints if type(c).__name__ == "Constraint"]
    return ((ConstrType.CONSTR_NOTNULL, True) in kinds
            and not any(k == ConstrType.CONSTR_PRIMARY
                        or (k == ConstrType.CONSTR_NOTNULL and not no_inherit)
                        for k, no_inherit in kinds))


_AUTO_NOT_NULL = re.compile(r"(.+)_not_null\d*")


def _record_not_null_names(builder: _TableBuilder, column_def: Any) -> None:
    """Remember the name of an inline `CONSTRAINT <name> NOT NULL`."""
    for con in getattr(column_def, "constraints", None) or ():
        if (getattr(con, "contype", None) == ConstrType.CONSTR_NOTNULL
                and getattr(con, "conname", None)):
            builder.not_null_names.setdefault(con.conname, set()).add(column_def.colname)


def _constraint_not_null_columns(con: Any, *, creating: bool = False) -> list[str]:
    """Column names a table-level constraint makes NOT NULL: a `PRIMARY KEY
    (...)`, or PG18's `NOT NULL c` (pglast 8). An `ALTER TABLE … NOT VALID`
    NOT NULL leaves existing NULLs in place, so its column stays nullable — as
    introspection reads it; in `CREATE TABLE` there are no rows, and Postgres
    stores it validated (measured on PG18)."""
    if type(con).__name__ != "Constraint":
        return []
    contype = getattr(con, "contype", None)
    if contype == ConstrType.CONSTR_NOTNULL:
        if getattr(con, "skip_validation", False) and not creating:
            return []
    elif contype != ConstrType.CONSTR_PRIMARY:
        return []
    out: list[str] = []
    for key in getattr(con, "keys", None) or ():
        name = getattr(key, "sval", None) or getattr(key, "str", None)
        if isinstance(name, str):
            out.append(name)
    return out


def _apply_rename(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
    index: int = -1,
) -> None:
    """Apply `ALTER TABLE <old> RENAME TO <new>`.

    Without this the model keeps the pre-rename name, so every finding on the
    table pointed at a relation that does not exist after the migration — a
    `pgrls pr` annotation naming a phantom table. Also applies `ALTER POLICY …
    RENAME TO` and `ALTER TABLE … RENAME CONSTRAINT` (so a later `DROP
    CONSTRAINT` of a NOT NULL still finds its column); other renames
    (columns, indexes, …) are left alone. A renamed parent takes the
    children created before it along.
    """
    rename_type = getattr(stmt, "renameType", None)
    if rename_type == ObjectType.OBJECT_TABCONSTRAINT:
        key = _relation_key(stmt.relation, default_schema)
        old_name = getattr(stmt, "subname", None)
        newname = getattr(stmt, "newname", None)
        builder = tables.get(key) if key is not None else None
        if key is not None and builder is not None and old_name and newname:
            builder.rename_constraint(old_name, newname)
            # The inherited copies on its children are renamed with it, and
            # so is a child's own constraint of that name (measured on PG18)
            # — a child that joined through `ALTER TABLE … INHERIT`, which
            # pgrls does not follow, included: every table holding the name
            # gets the new one too. A child that left (NO INHERIT / DETACH)
            # keeps the old name as well — erring wide only reads a column as
            # nullable.
            for other in tables.values():
                if other is not builder and old_name in other.not_null_names:
                    other.not_null_names.setdefault(newname, set()).update(
                        other.not_null_names[old_name])
            todo = [ck for ck, cb in tables.items()
                    if key in cb.inherits or cb.partition_of == key]
            seen: set[tuple[str, str]] = {key}
            while todo:
                k = todo.pop()
                if k in seen:
                    continue
                seen.add(k)
                if (b := tables.get(k)) is not None:
                    b.not_null_names.setdefault(newname, set()).update(
                        b.not_null_columns(old_name))
                todo.extend(ck for ck, cb in tables.items()
                            if k in cb.inherits or cb.partition_of == k)
        return
    if rename_type == ObjectType.OBJECT_POLICY:
        # `ALTER POLICY <old> ON <table> RENAME TO <new>`. Without this the
        # model kept the OLD name, so a later `ALTER POLICY <new> ON <table>
        # USING (true)` found no policy to loosen and the loosening was
        # silently discarded — an offline `pgrls pr` / `--sql-file verify`
        # kept proving the pre-rename predicate.
        key = _relation_key(stmt.relation, default_schema)
        old_name = getattr(stmt, "subname", None)
        newname = getattr(stmt, "newname", None)
        if key is None or not old_name or not newname:
            return
        builder = tables.get(key)
        if builder is None:
            return
        builder.policies = [
            dataclasses.replace(p, name=newname) if p.name == old_name else p
            for p in builder.policies
        ]
        return
    if rename_type != ObjectType.OBJECT_TABLE:
        return
    old = _relation_key(stmt.relation, default_schema)
    newname = getattr(stmt, "newname", None)
    if old is None or not newname:
        return
    _move_table(tables, old, (old[0], newname), index)


def _move_table(
    tables: dict[tuple[str, str], _TableBuilder],
    old: tuple[str, str],
    new: tuple[str, str],
    index: int = -1,
) -> None:
    """Give the table at `old` the name `new`, and its partitions and
    children their parent's new name."""
    builder = tables.get(old)
    # (Not one made after the rename: the rename was of the table there
    # before, one the SQL did not make, or none at all — whose partitions
    # and children follow it all the same.)
    if builder is not None and not builder.made_at > index >= 0:
        tables.pop(old)
        builder.schema, builder.name = new
        builder.former_names.append(new[1])
        # A rename onto an occupied name cannot happen in valid DDL; if the
        # input is invalid anyway, the later definition wins rather than
        # being dropped.
        tables[new] = builder
    # Its partitions and children follow it to the new name — those created
    # before the rename; a later one names a new table that took the old name.
    if builder is None or builder.made_at > index >= 0:
        # A rename onto a name a table already holds cannot run: there was
        # nothing to rename (`IF EXISTS`).
        held = tables.get(new)
        if held is not None and not held.made_at > index >= 0:
            return
    for key, other in tables.items():
        if other.made_at >= index >= 0 or key == new:
            continue
        if other.partition_of == old:
            other.partition_of = new
        other.inherits = [new if p == old else p for p in other.inherits]


def _merge_grants(grants: list[Grant]) -> tuple[Grant, ...]:
    """Merge table grants sharing a ``role`` into one with unioned privileges,
    preserving first-seen order.

    The table-level twin of `_merge_column_grants`, and it exists for the same
    reason: introspection groups a table's ACL per role, so
    ``GRANT SELECT ON t TO r;`` followed by ``GRANT INSERT ON t TO r;`` appears
    live as ONE `Grant` with both privileges. Without this the offline `sql=`
    path emitted two `Grant` rows for one role and every consumer that keys on
    role kept only the last — `diff` compared a base `{INSERT}` against a head
    `{INSERT}` and reported no change, silently passing a migration that had
    just granted `SELECT` on the table to `PUBLIC`.
    """
    merged: dict[str, set[str]] = {}
    order: list[str] = []
    for g in grants:
        if g.role not in merged:
            merged[g.role] = set()
            order.append(g.role)
        merged[g.role].update(g.privileges)
    return tuple(
        Grant(role=r, privileges=tuple(sorted(merged[r]))) for r in order
    )
def _data_derived_relation(stmt: Any) -> Any:
    """The target RangeVar of a `CREATE TABLE … AS` / `SELECT … INTO`, else None.

    pglast models the two differently: `CREATE TABLE x AS SELECT` is a
    `CreateTableAsStmt` carrying an `into` clause, while `SELECT … INTO x` stays
    a `SelectStmt` with an `intoClause`. Both create an ordinary table. A
    `CREATE MATERIALIZED VIEW`, which is also a `CreateTableAsStmt`, is excluded
    by its `objtype` — it is a different relkind with its own rules.
    """
    kind = type(stmt).__name__
    if kind == "CreateTableAsStmt":
        if getattr(stmt, "objtype", None) != ObjectType.OBJECT_TABLE:
            return None  # materialized view
        into = getattr(stmt, "into", None)
        return getattr(into, "rel", None)
    if kind == "SelectStmt":
        into = getattr(stmt, "intoClause", None)
        return getattr(into, "rel", None)
    return None


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


def _dropped_between(statements: Any, key: tuple[str, str], after: int, before: int,
                     default_schema: str) -> bool:
    """Whether a `DROP TABLE` of `key` (or a `DROP SCHEMA` of its schema)
    lies between the two statements."""
    return any(_drops(raw.stmt, key, default_schema) for raw in statements[after + 1:before])


def _drops(stmt: Any, key: tuple[str, str], default_schema: str) -> bool:
    if not isinstance(stmt, _pgast.DropStmt):
        return False
    if stmt.removeType == ObjectType.OBJECT_SCHEMA:
        return any(getattr(item, "sval", None) == key[0] for item in stmt.objects or ())
    return stmt.removeType == ObjectType.OBJECT_TABLE and any(
        _drop_table_key(_drop_name_parts(n), default_schema) == key
        for n in stmt.objects or () if _drop_name_parts(n))


def _renamed_between(statements: Any, key: tuple[str, str], after: int, before: int,
                     default_schema: str) -> bool:
    """Whether a rename of `key` away lies between the two statements."""
    return any(
        isinstance(raw.stmt, _pgast.RenameStmt) and raw.stmt.relation is not None
        and raw.stmt.renameType in _RELATION_KINDS
        and _relation_key(raw.stmt.relation, default_schema) == key
        for raw in statements[after + 1:before])


def _is_below(tables: dict[tuple[str, str], _TableBuilder], start: tuple[str, str],
              key: tuple[str, str]) -> bool:
    """Whether `key` is `start` or among its parents, its parents' parents
    and so on (so making `key` a child of `start` would close a cycle)."""
    pending, seen = [start], set()
    while pending:
        node = pending.pop()
        if node == key:
            return True
        if node in seen or node not in tables:
            continue
        seen.add(node)
        builder = tables[node]
        pending.extend([builder.partition_of] if builder.partition_of else [])
        pending.extend(builder.inherits)
    return False


def _apply_alter_table(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
    *,
    non_tables: AbstractSet[tuple[str, str]] = frozenset(),
    stmt_index: int,
) -> None:
    if getattr(stmt, "objtype", None) != ObjectType.OBJECT_TABLE:
        return  # ALTER SEQUENCE / VIEW / MATERIALIZED VIEW / INDEX / …
    key = _relation_key(stmt.relation, default_schema)
    if key is None:
        return
    builder = tables.get(key)
    if builder is None:
        # A DETACH from a parent the SQL did not make (or whose name a table
        # made later waits to take) still frees its partition.
        for cmd in stmt.cmds or ():
            if getattr(cmd, "subtype", None) == AlterTableType.AT_DetachPartition:
                child = tables.get(_relation_key(
                    getattr(getattr(cmd, "def_", None), "name", None), default_schema) or ("", ""))
                if child is not None and child.partition_of == key:
                    child.partition_of = None
        # An ALTER on a table we never saw a CREATE for (e.g. the agent pasted
        # only the ALTER). Create a shell so the RLS toggle still records — a
        # table with RLS on and no columns/policies is a legitimate (if
        # incomplete) thing to lint. Not for a relation the input created as
        # something else (Postgres takes `ALTER TABLE` on a view or a
        # sequence), nor for an ALTER that changes nothing modelled
        # (`OWNER TO`): either would invent a table.
        if key in non_tables or not any(
            getattr(cmd, "subtype", None) in _MODELLED_ALTER_SUBTYPES
            for cmd in stmt.cmds or ()
        ):
            return
        builder = _TableBuilder(schema=key[0], name=key[1])
        tables[key] = builder
    for cmd in stmt.cmds or ():
        subtype = getattr(cmd, "subtype", None)
        if subtype in (AlterTableType.AT_DropColumn, AlterTableType.AT_SetNotNull,
                       AlterTableType.AT_DropNotNull):
            # The column's NOT VALID NOT NULL, if any, is gone or moot —
            # `SET NOT NULL` validates it in place, keeping its name.
            target = getattr(cmd, "name", None) or ""
            for invalid, cols in builder.invalid_not_null.items():
                if target in cols and subtype == AlterTableType.AT_SetNotNull:
                    builder.not_null_names.setdefault(invalid, set()).add(target)
                cols.discard(target)
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
                    _record_not_null_names(builder, col)
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
        elif subtype in (AlterTableType.AT_AttachPartition, AlterTableType.AT_DetachPartition):
            # pg_dump writes each partition as a plain CREATE TABLE plus
            # `ALTER TABLE ONLY <parent> ATTACH PARTITION <child>`; without
            # this the child looked like a standalone table with RLS off.
            child = tables.get(_relation_key(
                getattr(getattr(cmd, "def_", None), "name", None), default_schema) or ("", ""))
            # Only the child and parent as they stood then: one created later
            # (after a DROP, or before which the ATTACH failed) is a table of
            # its own.
            if child is not None and subtype == AlterTableType.AT_DetachPartition:
                # A link it removes, whichever table it was: one a later
                # re-CREATE may or may not have made again stays off.
                if child.partition_of == key:
                    child.partition_of = None
                continue
            if (child is not None and child.created_at <= stmt_index
                    and builder.created_at <= stmt_index):
                if subtype == AlterTableType.AT_AttachPartition:
                    if child.inherits or child.partition_of is not None or (
                            builder.partitioned is False):
                        # Postgres refuses it: an inheritance child, a table
                        # already attached, or a parent not partitioned.
                        continue
                    # The replay merges a re-created table with its first
                    # CREATE, links and all, which can make this ATTACH close
                    # a cycle Postgres never has: leave it out.
                    up: tuple[str, str] | None = key
                    seen: set[tuple[str, str]] = set()
                    while up is not None and up in tables and up not in seen:
                        seen.add(up)
                        up = tables[up].partition_of
                    child_key = (child.schema, child.name)
                    if child_key in seen:
                        continue
                    child.partition_of = key
                elif child.partition_of == key:
                    child.partition_of = None
        elif (subtype in (AlterTableType.AT_AddConstraint,
                          AlterTableType.AT_ValidateConstraint)
              and stmt_index < builder.created_at):
            # Before the table's last CREATE (a DROP and re-CREATE): it
            # constrained the old table, not this one — skipping it only
            # reads a column as nullable.
            continue
        elif subtype == AlterTableType.AT_AddConstraint:
            con = getattr(cmd, "def_", None)
            builder.invalid_not_null.pop(getattr(con, "conname", None) or "", None)
            if (getattr(con, "contype", None) == ConstrType.CONSTR_NOTNULL
                    and getattr(con, "skip_validation", False)
                    and (conname := getattr(con, "conname", None))):
                builder.invalid_not_null[conname] = {
                    name for key in getattr(con, "keys", None) or ()
                    if isinstance(name := getattr(key, "sval", None), str)
                }
            for col_name in _constraint_not_null_columns(con):
                builder.set_not_null(col_name)
                # Only a NOT NULL's name is recorded: dropping a primary key leaves
                # its columns NOT NULL.
                conname = getattr(con, "conname", None)
                if getattr(con, "contype", None) == ConstrType.CONSTR_NOTNULL and conname:
                    builder.not_null_names.setdefault(conname, set()).add(col_name)
        elif subtype == AlterTableType.AT_DropConstraint:
            name = getattr(cmd, "name", None)
            if name:
                builder.invalid_not_null.pop(name, None)
                builder.drop_constraint(name)
        elif subtype == AlterTableType.AT_ValidateConstraint:
            # A validated `NOT VALID` NOT NULL makes its column NOT NULL.
            name = getattr(cmd, "name", None)
            if name:
                for col in builder.invalid_not_null.pop(name, set()):
                    builder.set_not_null(col)
                    builder.not_null_names.setdefault(name, set()).add(col)
        # Other ALTER subcommands are ignored.


# The `ALTER TABLE` subcommands `_apply_alter_table` applies.
_MODELLED_ALTER_SUBTYPES = frozenset({
    AlterTableType.AT_EnableRowSecurity, AlterTableType.AT_ForceRowSecurity,
    AlterTableType.AT_DisableRowSecurity, AlterTableType.AT_NoForceRowSecurity,
    AlterTableType.AT_AddColumn, AlterTableType.AT_DropColumn,
    AlterTableType.AT_SetNotNull, AlterTableType.AT_DropNotNull,
})


def _non_table_relation(stmt: Any) -> Any:
    """The RangeVar a `CREATE VIEW` / `MATERIALIZED VIEW` / `SEQUENCE` /
    `FOREIGN TABLE` statement creates, else None."""
    kind = type(stmt).__name__
    if kind == "ViewStmt":
        return getattr(stmt, "view", None)
    if kind == "CreateTableAsStmt" and getattr(stmt, "objtype", None) != ObjectType.OBJECT_TABLE:
        return getattr(getattr(stmt, "into", None), "rel", None)
    if kind == "CreateSeqStmt":
        return getattr(stmt, "sequence", None)
    if kind == "CreateForeignTableStmt":
        return getattr(getattr(stmt, "base", None), "relation", None)
    return None


# psql meta-commands that leave the SQL around them as it is: pg_dump's
# `\\restrict` pair, and settings or output that change no statement. Any
# other — `\\i` (another file), `\\if` (a branch not taken), `\\gexec`
# (generated SQL), `\\.` (the end of COPY data) — means the SQL pgrls would
# read is not the SQL that runs, so it is refused rather than blanked.
# `\\set` is not here: psql interpolates its variables into the SQL that
# follows (`:n`). `\\encoding` and `\\connect` are checked on their own.
# The whitespace psql splits a meta-command on (a vertical tab too since
# psql 17, so a line holding one is refused), and Postgres an identifier
# list.
_PSQL_SPACE = " \t\n\r\f"
_PG_SPACE = _PSQL_SPACE
_HARMLESS_PSQL_COMMANDS = frozenset({
    "restrict", "unrestrict", "echo", "qecho", "warn", "pset", "timing",
})


def _psql_accepts(name: str, rest: str, restricted: str | None) -> bool:
    """Whether psql runs harmless meta-command `name` with arguments `rest`
    without an error, which under ON_ERROR_STOP would stop the run there."""
    if name == "restrict":
        # pg_dump's key is alphanumeric; psql strips quotes (`''` is none).
        return re.fullmatch(r"[A-Za-z0-9]+", rest, re.ASCII) is not None and restricted is None
    if name == "unrestrict":
        return restricted is not None
    if name == "timing":
        return rest.lower() in ("", *_PSQL_BOOLEANS)
    if name == "pset":
        option, _, value = rest.partition(" ")
        value = value.strip(_PSQL_SPACE)
        if option in ("pager", "footer", "tuples_only", "t", "expanded", "x"):
            return value.lower() in ("", *_PSQL_BOOLEANS,
                                     *(("always",) if option == "pager" else ()),
                                     *(("auto",) if option in ("expanded", "x") else ()))
        if option == "format":
            return value.lower() in _PSQL_FORMATS
        if option == "border":
            return value.isascii() and value.isdigit()
        return option == "null"
    return True


_PSQL_BOOLEANS = ("on", "off", "true", "false", "yes", "no", "1", "0")
# psql's own settings that change no SQL, and the values each takes (a
# `:NAME` in the SQL is refused elsewhere); one psql rejects stops a run
# under ON_ERROR_STOP.
_PSQL_SETTINGS = {
    "ON_ERROR_STOP": _PSQL_BOOLEANS, "QUIET": _PSQL_BOOLEANS,
    "ECHO": ("none", "errors", "queries", "all"),
    "ECHO_HIDDEN": (*_PSQL_BOOLEANS, "noexec"),
    "VERBOSITY": ("default", "verbose", "terse", "sqlstate"),
    "SHOW_CONTEXT": ("never", "errors", "always"),
}


def _psql_sets(rest: str) -> bool:
    """Whether `\\set rest` sets one of `_PSQL_SETTINGS` to a value psql takes."""
    m = re.fullmatch(r"([A-Z_]+)(?:\s+([A-Za-z0-9_]+))?", rest, re.ASCII)
    if m is None:
        return False
    values = _PSQL_SETTINGS.get(m.group(1), ())
    # No value is the empty string, which a boolean one reads as on.
    return (m.group(2) or "").lower() in values or (m.group(2) is None and "on" in values)
_PSQL_FORMATS = frozenset({
    "aligned", "asciidoc", "csv", "html", "latex", "latex-longtable", "troff-ms",
    "unaligned", "wrapped",
})


# Client encodings in which a byte of a multibyte character can be a quote or
# a backslash (the client-only ones, by every name Postgres accepts): under
# one, Postgres and psql end strings where pgrls, reading UTF-8, does not.
_UNSAFE_CLIENT_ENCODINGS = frozenset({
    "sjis", "mskanji", "shiftjis", "win932", "windows932", "shiftjis2004",
    "big5", "win950", "windows950", "gbk", "win936", "windows936", "cp936",
    "gb18030", "uhc", "win949", "windows949", "cp949", "johab",
})
# Client encodings under which Postgres reads the UTF-8 text pgrls reads as
# pgrls does, against a UTF8 database (as a client encoding, SQL_ASCII
# converts nothing). Under any other, a non-ASCII
# character is read as other characters (`é` as `Ã©` under LATIN1).
_UTF8_ENCODINGS = frozenset({"utf8", "unicode", "sqlascii"})
_WRITES = (_pgast.InsertStmt, _pgast.UpdateStmt, _pgast.DeleteStmt, _pgast.MergeStmt)


def _open_at(statements: Any, offset: int, end: Any) -> bool:
    """Whether a transaction the statements before `offset` begin is still
    open there (pg_restore --transaction-size wraps CREATE DATABASE's
    neighbours in BEGIN / COMMIT)."""
    open_ = False
    for raw in statements:
        if end(raw) >= offset:
            break
        if isinstance(raw.stmt, _pgast.TransactionStmt):
            if raw.stmt.kind in (TransactionStmtKind.TRANS_STMT_BEGIN,
                                 TransactionStmtKind.TRANS_STMT_START):
                open_ = True
            elif raw.stmt.kind in (TransactionStmtKind.TRANS_STMT_COMMIT,
                                   TransactionStmtKind.TRANS_STMT_ROLLBACK):
                open_ = bool(raw.stmt.chain)
    return open_


def _clears_a_template_flag(stmt: Any) -> bool:
    """`UPDATE pg_catalog.pg_database SET datistemplate = false WHERE datname
    = '<name>'`, which `pg_dump --create --clean` writes to drop a template
    database: no setting of the next session."""
    target = stmt.targetList[0] if isinstance(stmt, _pgast.UpdateStmt) and len(
        stmt.targetList or ()) == 1 else None
    where = getattr(stmt, "whereClause", None)
    return (
        target is not None
        and stmt.relation.relname == "pg_database"
        and stmt.relation.schemaname in (None, "pg_catalog")
        and not stmt.fromClause and not stmt.withClause
        # pglast 7's returningList, 8's returningClause.
        and not getattr(stmt, "returningList", None)
        and not getattr(stmt, "returningClause", None)
        and target.name == "datistemplate" and not target.indirection
        and isinstance(target.val, _pgast.A_Const)
        and getattr(target.val.val, "boolval", None) is False
        and isinstance(where, _pgast.A_Expr) and where.kind == A_Expr_Kind.AEXPR_OP
        and [getattr(n, "sval", None) for n in where.name or ()] == ["="]
        and isinstance(where.lexpr, _pgast.ColumnRef)
        and [getattr(f, "sval", None) for f in where.lexpr.fields or ()] == ["datname"]
        and isinstance(where.rexpr, _pgast.A_Const)
        and isinstance(getattr(where.rexpr.val, "sval", None), str)
    )
# Statements `pg_dump --create` writes before its `\\connect`.
_DATABASE_LEVEL_STATEMENTS = frozenset({
    "VariableSetStmt", "SelectStmt", "CreatedbStmt", "AlterDatabaseStmt",
    "AlterDatabaseSetStmt", "AlterOwnerStmt", "CommentStmt", "DropdbStmt",
    "AlterRoleSetStmt",
})


def _holds_copy_data(sql: str) -> bool:
    """Whether `sql` is a dump with data: a line `COPY … FROM stdin;`, as
    pg_dump writes it, outside any string or comment (the text before it
    lexes whole), and a `\\.` line after it."""
    for i, m in enumerate(re.finditer(r"(?im)^COPY\b[^;\n]*\bFROM\s+stdin\b[^\n]*$", sql)):
        if i == 3:  # a dump's first COPY is the real one
            return False
        if not re.search(r"(?m)^\\\.[ \t\r]*$", sql[m.end():]):
            return False
        try:
            pglast.parser.scan(_without_psql_meta_commands(sql[:m.start()]))
        except pglast.parser.ParseError:
            continue
        return True
    return False


def _check_psql_meta_commands(commands: list[tuple[int, str]]) -> list[int]:
    """Refuse the meta-commands pgrls cannot model (raising
    `SchemaSourceError`); the offset of each `\\connect` — every one must
    name the same database (pg_dump --create repeats it after the
    database's settings), since pg_dumpall writes one per database, whose
    schemas must not merge.

    A line is skipped only when it is ONE known command and nothing else: a
    second backslash starts another command (`\\echo x \\i f`), and `\\\\`
    ends the command so the rest of the line runs as SQL; a backtick runs a
    shell command. Any of those is refused, as is any other command.

    A `\\connect` is skipped only in the forms pg_dump writes — a database
    name, bare or double-quoted (`\\connect "MyApp"`, as it quotes one that
    needs it, every one under `--quote-all-identifiers`), or
    `-reuse-previous=on "dbname='…'"` — since a conninfo
    string can also set `options` or `client_encoding`, which change how
    the server reads the strings after it; an `\\encoding` only to UTF8 or
    SQL_ASCII."""
    connects: list[tuple[int, str]] = []
    restricted: str | None = None
    for offset, line in commands:
        # psql splits a meta-command on ASCII whitespace only (a no-break
        # space is part of a word).
        m = re.match(r"\\([A-Za-z]+|\.)(?:\s+(.*))?$", line.strip(_PSQL_SPACE),
                     re.DOTALL | re.ASCII)
        name, rest = (m.group(1), (m.group(2) or "").strip(_PSQL_SPACE)) if m else ("", "")
        if name == ".":
            raise SchemaSourceError(
                "bad_sql",
                "the SQL holds COPY data (a pg_dump with data); dump the "
                "schema with pg_dump --schema-only.",
            )
        connect = name in ("c", "connect")
        target = None
        conninfo = False
        if connect and (c := re.fullmatch(
            r'([^\s"\'=:\\-][^\s"\'=:\\]*)|"((?:[^"\\=:]|"")+)"', rest, re.ASCII,
        )):
            # psql takes a double-quoted name as it is (`""` a quote); one
            # holding `=` or a URI's `:` would be a conninfo string.
            target = c.group(1) or (c.group(2) or "").replace('""', '"')
        elif connect and (c := re.fullmatch(r'-reuse-previous=on "((?:[^"]|"")*)"', rest)):
            # pg_dump's form for any other name: a conninfo string whose one
            # keyword is the name, quoted as conninfo quotes (`\'`, `\\`)
            # inside psql's double quotes; psql reads no variable there.
            value = re.fullmatch(r"dbname='((?:[^'\\]|\\.)*)'", c.group(1).replace('""', '"'))
            if value is not None:
                target = re.sub(r"\\(.)", r"\1", value.group(1))
                # Inside psql's double quotes a backslash or backtick is text.
                conninfo = True
        known = (name in _HARMLESS_PSQL_COMMANDS and _psql_accepts(name, rest, restricted)) \
            or target is not None or (
            name == "encoding"
            and re.sub(r"[^a-z0-9]", "", rest.lower()) in _UTF8_ENCODINGS
        ) or (
            # psql's own settings that change no SQL (a `:NAME` in the SQL
            # is refused below).
            name == "set" and _psql_sets(rest)
        )
        # psql reads a line to its LF: a CR is part of the command's arguments.
        if m is None or (("\\" in rest or "`" in rest) and not conninfo) \
                or "\r" in rest or "\v" in line or not known:
            raise SchemaSourceError(
                "bad_sql",
                f"the SQL uses the psql command {line.strip()[:60]!r}, which pgrls "
                "does not model (the SQL it reads would not be the SQL that runs).",
            )
        if restricted is not None and not (name == "unrestrict" and rest == restricted):
            # psql then runs no meta-command but `\\unrestrict` with its key
            # (a `\\connect` there does not reconnect), and an error stops a
            # run under ON_ERROR_STOP.
            raise SchemaSourceError(
                "bad_sql",
                f"the SQL uses the psql command {line.strip()[:60]!r} inside a "
                "\\restrict, where psql refuses it; pgrls does not model that.",
            )
        if name == "restrict":
            restricted = rest
        elif name == "unrestrict":
            restricted = None
        if connect:
            assert target is not None  # `known` above
            connects.append((offset, target))
    if len({target for _, target in connects}) > 1:
        raise SchemaSourceError(
            "bad_sql",
            "the SQL connects to more than one database (pg_dumpall output); "
            "dump each database with pg_dump and lint each file.",
        )
    return [offset for offset, _ in connects]


def _check_blanked_lines(sql: str, commands: list[tuple[int, str]]) -> None:
    """Refuse when Postgres's own lexer reads a blanked meta-command line as
    part of a string, quoted name or comment — psql, which lexes the same way,
    would then not have run it as a command — or when the SQL names one of
    psql's own variables (`:ROW_COUNT`), which psql interpolates before
    sending it. Raises `pglast.parser.ParseError` on SQL that does not lex."""
    tokens = pglast.parser.scan(sql)
    k = 0
    for offset, line in commands:
        while k < len(tokens) and tokens[k].end < offset:
            k += 1
        if k < len(tokens) and tokens[k].start < offset:
            raise SchemaSourceError(
                "bad_sql",
                f"the psql command {line[:60]!r} sits inside a string, quoted "
                "name or comment, where psql would not run it; pgrls cannot "
                "tell which lines psql runs.",
            )
    for colon, name in zip(tokens, tokens[1:]):
        text = sql[name.start:name.end + 1].strip("'\"")
        # psql takes the name up to the first character outside
        # `[A-Za-z0-9_]` and non-ASCII (`:USER$x` is `:USER`, then `$x`);
        # `:USER` lexes as a keyword, not an identifier.
        var = re.match(r"[A-Za-z0-9_\x80-\U0010ffff]*", text)
        if (colon.name == "ASCII_58" and name.start == colon.end + 1
                and var is not None and re.fullmatch(r"[A-Z][A-Z0-9_]*", var.group())):
            raise SchemaSourceError(
                "bad_sql",
                f"the SQL holds {sql[colon.start:name.end + 1]!r}, which psql "
                "replaces with the value of its own variable; pgrls cannot "
                "tell what SQL psql sends.",
            )


def _check_lexer_settings(statements: Any, *, non_ascii: bool) -> None:
    """Refuse SQL that sets what changes how Postgres reads the SQL after it
    — a client encoding whose characters can hold a quote or backslash byte,
    `standard_conforming_strings` off, or `transform_null_equals` on (which
    stores `x = NULL` as `x IS NULL`) — by `SET`, `ALTER DATABASE /
    ROLE … SET` (which a `\\connect` brings in) or `set_config()`. pgrls
    reads the SQL as UTF-8 with standard strings, so it would end strings
    where Postgres does not. With `non_ascii`, any client encoding but UTF-8
    or SQL_ASCII is refused: Postgres reads those characters as others.
    An UPDATE of `pg_settings`, or of a view the SQL defines over it (or a
    rename of one), is refused too. A setting changed by code (a `DO` block, a function) is not
    seen."""
    trees = [list(_subnodes(raw.stmt)) for raw in statements]
    # A rule on pg_settings sets what an UPDATE of it names, through a view
    # over it too: the relations the SQL defines over it, by name.
    over: set[str] = set()

    def reaches(rel: Any) -> bool:
        # `pg_catalog.pg_settings` (first on every search path), or a view
        # the SQL defines over it.
        return rel is not None and (
            rel.relname in over
            or (rel.relname == "pg_settings" and rel.schemaname in (None, "pg_catalog")))

    # A view inside CREATE SCHEMA counts too.
    views = [(view.view.relname, list(_subnodes(view.query)))
             for nodes in trees for view in nodes if isinstance(view, _pgast.ViewStmt)]
    while True:
        more = {
            name for name, reads in views
            if name not in over
            and any(isinstance(n, _pgast.RangeVar) and reaches(n) for n in reads)
        }
        if not more:
            break
        over |= more
    for raw, nodes in zip(statements, trees):
        if isinstance(raw.stmt, (_pgast.CreateFunctionStmt, _pgast.AlterFunctionStmt)):
            # A function's SET clause applies while it runs, and its body only
            # when called: neither changes how the file is read.
            continue
        if any(
            isinstance(n, (_pgast.UpdateStmt, _pgast.RenameStmt)) and reaches(n.relation)
            for n in nodes
        ):
            raise SchemaSourceError(
                "bad_sql",
                "the SQL updates pg_settings, or a view over it, which sets "
                "what pgrls cannot follow.",
            )
        for node in nodes:
            if isinstance(node, _pgast.VariableSetStmt) and node.args:
                # Postgres looks a setting up ignoring case, even quoted.
                name, arg = (node.name or "").lower(), node.args[0]
            elif (isinstance(node, _pgast.FuncCall)
                  and ast_utils.func_name_parts(node)[1] == "set_config"):
                # pg_dump writes a literal in an expression as `'x'::text`.
                args = tuple(_uncast(arg) for arg in node.args or ())
                if not args or not isinstance(args[0], _pgast.A_Const):
                    raise SchemaSourceError(
                        "bad_sql",
                        "the SQL calls set_config() on a setting it does not name; "
                        "pgrls cannot tell how Postgres reads the strings after it.",
                    )
                name = str(getattr(args[0].val, "sval", "")).lower()
                arg = args[1] if len(args) > 1 else None
            else:
                continue
            if name not in ("client_encoding", "standard_conforming_strings",
                            "transform_null_equals"):
                continue
            val = arg.val if isinstance(arg, _pgast.A_Const) else None
            value = str(getattr(val, "sval", None) or getattr(val, "ival", "")).lower()
            encoding = re.sub(r"[^a-z0-9]", "", value)
            true = value in ("on", "1") or bool(value) and (
                "true".startswith(value) or "yes".startswith(value))
            unsafe = val is None or (
                name == "client_encoding"
                and (encoding in _UNSAFE_CLIENT_ENCODINGS
                     or (non_ascii and encoding not in _UTF8_ENCODINGS))
            ) or (name == "standard_conforming_strings" and not true) or (
                # It stores `x = NULL` as `x IS NULL`.
                name == "transform_null_equals" and true
            )
            if unsafe:
                raise SchemaSourceError(
                    "bad_sql",
                    f"the SQL sets {name} to {value or 'a computed value'!r}, under "
                    "which Postgres reads its text differently from how pgrls "
                    "reads it.",
                )


def _subnodes(node: Any) -> Any:
    """`node` and every node beneath it, in pre-order. A loop, not
    recursion: a view of a few thousand `UNION ALL` branches is valid."""
    stack = [node]
    while stack:
        node = stack.pop()
        if isinstance(node, (list, tuple)):
            stack.extend(reversed(node))
        elif isinstance(node, _pgast.Node):
            yield node
            stack.extend(reversed([getattr(node, field, None) for field in node]))


def _without_psql_meta_commands(sql: str) -> str:
    """`sql` with each psql meta-command line (one whose first non-blank
    character is a backslash, outside a string, quoted identifier, dollar
    quote or comment) blanked to spaces, so statement offsets are kept."""
    return _split_psql_meta_commands(sql)[0]


def _split_psql_meta_commands(sql: str) -> tuple[str, list[tuple[int, str]]]:
    """`_without_psql_meta_commands`'s text, and each meta-command line it
    blanked, with its offset. A UTF-8 byte-order mark opening the file,
    which psql skips, is blanked too."""
    if sql.startswith("\ufeff"):
        sql = " " + sql[1:]
    out = list(sql)
    commands: list[tuple[int, str]] = []
    i, n = 0, len(sql)
    line_start = True
    while i < n:
        c = sql[i]
        if c == "\n":
            line_start = True
            i += 1
            continue
        if c in " \t\r\f" and line_start:
            i += 1
            continue
        if c == "\\" and line_start:
            j = sql.find("\n", i)
            j = n if j < 0 else j
            commands.append((i, sql[i:j].strip(_PSQL_SPACE)))
            out[i:j] = " " * (j - i)
            i = j
            continue
        line_start = False
        if sql.startswith("--", i):
            m = _LINE_END.search(sql, i)
            i = n if m is None else m.start()
        elif sql.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if sql.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif sql.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif c in "'\"":
            # `E'…'` takes backslash escapes; `date'…'` does not.
            escapes = c == "'" and i > 0 and sql[i - 1] in "eE" and not (
                i > 1 and _is_ident_char(sql[i - 2]))
            i += 1
            while i < n:
                if escapes and sql[i] == "\\":
                    i += 2
                elif sql.startswith(c * 2, i):
                    i += 2
                elif sql[i] == c:
                    i += 1
                    break
                else:
                    i += 1
        elif (m := _DOLLAR_QUOTE.match(sql, i)) is not None and not (
            i and _is_ident_char(sql[i - 1])
        ):
            j = sql.find(m.group(0), m.end())
            i = n if j < 0 else j + len(m.group(0))
        else:
            i += 1
    return "".join(out), commands


_DOLLAR_QUOTE = re.compile(r"\$(?:[A-Za-z_\x80-\U0010ffff][A-Za-z_0-9\x80-\U0010ffff]*)?\$")
_LINE_END = re.compile(r"[\r\n]")


def _is_ident_char(c: str) -> bool:
    # Postgres takes every non-ASCII character as part of an identifier.
    return not c.isascii() or c.isalnum() or c in "_$"


def _apply_create_policy(
    stmt: Any,
    tables: dict[tuple[str, str], _TableBuilder],
    default_schema: str,
    *,
    source: str = "",
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

    written = _clause_source(source)
    using_sql = _deparse_or_none(getattr(stmt, "qual", None), written.get("USING"))
    check_sql = _deparse_or_none(getattr(stmt, "with_check", None), written.get("WITH CHECK"))
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
    *,
    source: str = "",
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
            using_sql = _deparse_or_none(qual, _clause_source(source).get("USING"))
            updates["using_sql"] = using_sql
            updates["using_ast"] = (
                _parse_clause(using_sql, location=location, clause="USING")
                if using_sql is not None
                else None
            )
        with_check = getattr(stmt, "with_check", None)
        if with_check is not None:
            check_sql = _deparse_or_none(
                with_check, _clause_source(source).get("WITH CHECK"),
            )
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
    *,
    stmt_index: int = 1 << 30,
) -> None:
    """Apply ``DROP POLICY`` / ``DROP TABLE`` — remove the object from the model
    so a dropped RLS guard (or whole table) is reflected offline. Other ``DROP``
    object types (index, function, view, sequence, …) are not modeled and are
    skipped, as before.

    ``DROP TABLE`` is ORDER-AWARE. `CREATE TABLE` is resolved in pass 1 and
    drops in pass 2, so without a guard a `DROP TABLE t;` that PRECEDES a
    `CREATE TABLE t (…)` — the ordinary shape of a rebuild migration — removed
    the table the later CREATE had just established, and the model reported no
    table at all. That is a false clear: nothing lints a table that exists.
    Comparing `stmt_index` against the builder's `created_at` drops only when
    the DROP genuinely follows the CREATE.
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
    elif remove_type == ObjectType.OBJECT_SCHEMA:
        # Its tables go with it (CASCADE; without it, only an empty one
        # drops): one made again later stands.
        gone = {getattr(item, "sval", None) for item in stmt.objects or ()}
        for key in [k for k, b in tables.items() if k[0] in gone and b.created_at < stmt_index]:
            tables.pop(key, None)
    elif remove_type == ObjectType.OBJECT_TABLE:
        for namelist in stmt.objects or ():
            parts = _drop_name_parts(namelist)
            if not parts:
                continue
            key = _drop_table_key(parts, default_schema)
            builder = tables.get(key)
            if builder is None:
                continue
            if builder.created_at > stmt_index:
                # The CREATE comes LATER in the input — this DROP removed a
                # previous incarnation, and the table survives the migration.
                continue
            tables.pop(key, None)


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


def _deparse_or_none(node: Any, written: str | None = None) -> str | None:
    """Render a policy USING / WITH CHECK expression node back to SQL text.

    Returns the deparsed fragment (which `parse_expr` then re-parses into the
    canonical AST shape the rules expect), or `None` when the clause is absent.
    When no rendering parses back to the node — pglast's printer drops
    parentheses it needs, or (pglast 7, ``x OPERATOR(s.op) ANY / ALL (…)``) cannot
    print it at all — the clause as the statement wrote it (`written`) is
    used instead, so the rules see the predicate the SQL wrote. Without a
    `written` that parses back to the node it falls back to pglast's
    rendering, or `None` when pglast cannot print the node.
    """
    if node is None:
        return None
    exact = ast_utils.exact_sql(node)
    if exact is not None:
        return exact
    if written and ast_utils._same_tree(written, node):
        return written
    if written and (qualified := _qualified_written(written, node)) is not None:
        return qualified
    try:
        return ast_utils.faithful_sql(node)
    except ValueError:
        return None


def _qualified_written(written: str, node: Any) -> str | None:
    """`written` with the schema the search path resolved each table it
    reads to (`_Resolver._qualify_policy`, which qualified `node` in place)
    written in, when that parses back to `node`; else None."""
    prefix = "SELECT ("
    try:
        parsed = pglast.parse_sql(f"{prefix}{written}) AS _expr")[0].stmt
    except pglast.parser.ParseError:
        return None
    mine = [n for n in _subnodes(parsed) if isinstance(n, _pgast.RangeVar)]
    theirs = [n for n in _subnodes(node) if isinstance(n, _pgast.RangeVar)]
    if len(mine) != len(theirs):
        return None
    edits = []
    for a, b in zip(mine, theirs):
        if a.relname != b.relname:
            return None
        if not a.schemaname and b.schemaname:
            if a.location is None or a.location < len(prefix):
                return None
            edits.append((a.location - len(prefix), '"' + b.schemaname.replace('"', '""') + '".'))
    if not edits:
        return None
    text = written
    for at, schema in sorted(edits, reverse=True):
        text = text[:at] + schema + text[at:]
    return text if ast_utils._same_tree(text, node) else None


def _clause_source(source: str) -> dict[str, str]:
    """The text of a `CREATE` / `ALTER POLICY` statement's ``USING (…)`` and
    ``WITH CHECK (…)`` expressions, keyed ``"USING"`` / ``"WITH CHECK"``.
    Before the clauses the statement holds only names and keywords, so the
    first top-level ``USING (`` / ``WITH CHECK (`` opens each."""
    try:
        tokens = [t for t in pglast.parser.scan(source)
                  if t.name not in ("SQL_COMMENT", "C_COMMENT")]
    except pglast.parser.ParseError:
        return {}
    found: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        name = tokens[i].name
        if name == "USING":
            key, j = "USING", i + 1
        elif name == "WITH" and i + 1 < len(tokens) and tokens[i + 1].name == "CHECK":
            key, j = "WITH CHECK", i + 2
        else:
            i += 1
            continue
        if j >= len(tokens) or tokens[j].name != "ASCII_40":
            i = j
            continue
        depth = 0
        for k in range(j, len(tokens)):
            if tokens[k].name == "ASCII_40":
                depth += 1
            elif tokens[k].name == "ASCII_41":
                depth -= 1
                if depth == 0:
                    break
        else:
            return found
        if k > j + 1:
            found.setdefault(key, _without_comments(source, tokens[j + 1:k]))
        i = k + 1
    return found


def _without_comments(source: str, tokens: list[Any]) -> str:
    """The text `tokens` span in `source`, each gap between two of them (a
    comment is one) written as a newline when it holds a line break — a
    string literal continues across one — and a space otherwise. A snapshot
    refuses a predicate that carries a comment."""
    parts = [source[tokens[0].start:tokens[0].end + 1]]
    for prev, tok in zip(tokens, tokens[1:]):
        gap = source[prev.end + 1:tok.start]
        if gap:
            parts.append("\n" if "\n" in gap or "\r" in gap else " ")
        parts.append(source[tok.start:tok.end + 1])
    return "".join(parts)


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


# pg_dump writes an extension's own tables as `CREATE EXTENSION` alone.
_EXTENSION_CAVEAT = (
    "Tables an extension creates (PostGIS's spatial_ref_sys, say) are not seen: "
    "the SQL shows only its CREATE EXTENSION, and a GRANT on one is dropped."
)


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
            _EXTENSION_CAVEAT,
        ]
    return [
        "Analysis is of the provided SQL only — no live database. Rules that "
        "depend on catalog state not expressible in CREATE/ALTER/GRANT DDL "
        "cannot fire here, so an absence of findings is NOT a proof of safety. "
        "For full coverage, run pgrls against a live database_url or a "
        "snapshot.",
        f"Inert on sql= input (catalog-only): {inert}.",
        _EXTENSION_CAVEAT,
    ]
