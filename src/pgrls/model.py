"""Normalized representation of a Postgres schema's RLS state.

Snapshot format is versioned via a single int (`SNAPSHOT_VERSION`); bump
on any change that adds, removes, or restructures an emitted field.
Currently version 8 (v8 added ``search_path`` to ``SecdefFunction``
for SEC015; v7 added per-table ``indexes`` for PERF003; v6
added per-table ``triggers`` for SEC013; v5 added per-column type
info via the new ``column_details`` per table; v4 added top-level
``views``; v3 added ``grants`` to each table entry; v2 added
``partition_of``).
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Literal

__all__ = [
    "Column",
    "Grant",
    "Index",
    "Policy",
    "PolicyCommand",
    "SNAPSHOT_VERSION",
    "Schema",
    "SecdefFunction",
    "Snapshot",
    "Table",
    "Trigger",
    "View",
]

PolicyCommand = Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
Snapshot = dict[str, Any]

SNAPSHOT_VERSION = 8


@dataclass(frozen=True)
class Policy:
    name: str
    command: Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
    permissive: bool
    roles: tuple[str, ...]
    using_sql: str | None
    with_check_sql: str | None
    using_ast: Any | None = None
    with_check_ast: Any | None = None

    @property
    def is_permissive(self) -> bool:
        return self.permissive


@dataclass(frozen=True)
class Column:
    """A column captured by snapshot v5+.

    Captured fields are the minimum the Schema-to-SQL emitter needs
    to reconstruct ``CREATE TABLE`` statements compatible with a
    migration: name, Postgres-canonical data type, nullability.

    ``data_type`` is the Postgres type expression as it would appear
    in ``CREATE TABLE`` — e.g. ``text``, ``integer``, ``timestamp
    with time zone``, ``jsonb``, ``uuid``, ``numeric(10,2)``.
    Generated columns, identity columns, defaults, check constraints,
    and foreign keys are deliberately NOT captured — the emitter
    targets the minimum DDL needed to make the migration apply.

    Snapshot v3/v4 baselines round-trip into v5 with empty
    ``column_details`` per table; the legacy ``columns`` field
    (tuple of names) keeps working for every existing rule.
    """

    name: str
    data_type: str
    is_nullable: bool = True


@dataclass(frozen=True)
class Grant:
    """A privilege grant on a table.

    Captured in snapshot v3+. Privileges use Postgres's canonical
    string forms: SELECT, INSERT, UPDATE, DELETE, TRUNCATE,
    REFERENCES, TRIGGER. PUBLIC pseudo-role is represented as
    `role="PUBLIC"`, mirroring the Policy.roles convention.
    """

    role: str
    privileges: tuple[str, ...]


@dataclass(frozen=True)
class View:
    """A view or materialized view captured by introspection.

    Captured in snapshot v4+. `is_materialized` distinguishes
    `pg_class.relkind = 'v'` (regular view) from `'m'`
    (materialized view). `security_invoker` and `security_barrier`
    correspond to `pg_class.reloptions` entries; both default to
    False on PG15+ unless explicitly set via
    `WITH (security_invoker = true)` / `WITH (security_barrier = true)`.

    `references` is the sorted, de-duplicated set of `(schema, name)`
    table pairs the view body reads from (resolved via `pg_depend`).
    `security_definer_calls` is the sorted, de-duplicated tuple of
    qualified function names called by the view body that have
    `pg_proc.prosecdef = true`. Both default to empty.
    """

    schema: str
    name: str
    is_materialized: bool
    security_invoker: bool
    security_barrier: bool
    definition: str
    references: tuple[tuple[str, str], ...]
    security_definer_calls: tuple[str, ...]

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True)
class Index:
    """An index captured by snapshot v7+.

    PERF003 uses ``Table.indexes`` to check whether columns
    referenced in a policy predicate have a leading-column B-tree
    index (or any leading-column index in v0.5.10). Without one,
    every query against the RLS-enabled table does a sequential
    scan to filter rows — fine for small tables, catastrophic for
    multi-tenant tables with millions of rows.

    Captured fields are the minimum PERF003 needs to evaluate
    "does this column have an index that helps the planner with
    the policy predicate":

    * ``name`` — the index name (``pg_class.relname`` for the
      index relation). Used in violation messages so the operator
      can locate the index in their schema.
    * ``access_method`` — ``btree``, ``hash``, ``gin``, ``gist``,
      ``brin``, etc. PERF003 v1 treats any access method as
      "indexed" (the operator picked the right method for their
      query shape); future versions may narrow to btree/hash for
      equality predicates.
    * ``columns`` — ordered tuple of column names. Expression
      index positions (where ``pg_index.indkey`` carries 0) become
      the empty string in this tuple, preserving positional
      alignment without misleading callers into thinking a column
      is indexed when it isn't. PERF003 checks only the leading
      column; trailing-column matches don't help an equality
      predicate without the leading column also being part of the
      query.
    * ``is_unique`` — informational; a unique index is still a
      B-tree on the captured columns.
    * ``is_partial`` — ``pg_index.indpred IS NOT NULL``. Partial
      indexes only help when the partial predicate is satisfied
      by the query predicate; pgrls can't statically prove that
      compatibility, so PERF003 v1 treats partial indexes as
      "indexed" and trusts the operator's intent. The flag is
      captured so a future rule can warn on partial-but-mismatched
      cases.

    Only valid + ready indexes (``indisvalid AND indisready``) are
    captured. A half-built index from a failed ``CREATE INDEX
    CONCURRENTLY`` doesn't help the planner and shouldn't make
    PERF003 silent.
    """

    name: str
    access_method: str
    columns: tuple[str, ...]
    is_unique: bool
    is_partial: bool


@dataclass(frozen=True)
class Trigger:
    """A trigger captured by snapshot v6+.

    Triggers are the focus of SEC013 — they run as the table OWNER
    (not the invoking role), so any SELECT/INSERT/UPDATE/DELETE in
    the trigger function body bypasses the invoker's RLS policies.
    A poorly-audited trigger function on an RLS-protected table is
    a silent privilege-escalation vector: tenant A's INSERT can fire
    a trigger that reads tenant B's rows (or worse, writes to them)
    without any policy violation surfacing.

    Captured fields are the minimum SEC013 needs to message clearly
    and the operator needs to triage:

    * ``name`` — the trigger's identity; combined with the owning
      table's qualified name it forms the allowlist key
      ``schema.table.trigger_name``. Postgres scopes triggers per
      table, not per schema (``pg_trigger`` has no ``tgnamespace``
      column), so a separate trigger-schema field would always
      duplicate the table's schema — omitted for clarity.
    * ``function_schema`` + ``function_name`` — the function this
      trigger calls. SEC013's message names it explicitly so the
      operator knows what code to audit. The function CAN live in
      a different schema than the table (cross-schema callouts are
      legal and common with audit-functions in an ``audit`` schema),
      so this is captured separately.
    * ``event`` — the event mask rendered as Postgres syntax (e.g.
      ``INSERT``, ``UPDATE``, ``INSERT OR UPDATE``, ``TRUNCATE``).
    * ``timing`` — ``BEFORE``, ``AFTER``, or ``INSTEAD OF``.
    * ``enabled`` — false iff ``pg_trigger.tgenabled = 'D'`` (the
      trigger is disabled and can't fire under any session_replication_
      role). Disabled triggers are still captured so a snapshot diff
      surfaces a re-enable as a change; SEC013 skips them.

    Internal system triggers (``pg_trigger.tgisinternal = true`` —
    foreign-key check triggers, RI constraint helpers, etc.) are
    filtered at the SQL layer; they're not user-authored and don't
    represent an audit target.

    Trigger captures the audit-relevant subset of ``pg_trigger``,
    not the DDL-regeneration-complete shape. Fields NOT captured:
    ``WHEN`` clauses, ``REFERENCING NEW TABLE`` / ``OLD TABLE``
    transition tables, ``UPDATE OF column_list`` filters, and the
    ROW vs STATEMENT axis (``tgtype`` bit 0). ``Schema.to_sql()``
    does NOT emit ``CREATE TRIGGER`` statements; the migration-as-
    input flow (``pgrls diff --apply``) treats triggers as
    pre-existing on the live DB and doesn't replicate them into
    the ephemeral baseline container. A future release that wants
    DDL regeneration would need a snapshot bump to capture these.
    """

    name: str
    function_schema: str
    function_name: str
    event: str
    timing: str
    enabled: bool

    @property
    def function_qualified_name(self) -> str:
        return f"{self.function_schema}.{self.function_name}"


@dataclass(frozen=True)
class Table:
    schema: str
    name: str
    rls_enabled: bool
    force_rls: bool
    policies: tuple[Policy, ...]
    columns: tuple[str, ...] = ()
    # Immediate parent for declarative partition children — `(schema, name)`
    # of the partitioned table this row is `PARTITION OF`. None for
    # standalone tables, partitioned-table parents themselves, and classic
    # `INHERITS` children. The chain may be deeper than one level; rules
    # walk it via the resolved Schema.
    partition_of: tuple[str, str] | None = None
    # Privilege grants on this table — populated from `pg_class.relacl` in
    # snapshot v3+. Default `()` keeps existing call sites that construct
    # `Table(...)` without grants working unchanged. A v2 baseline loaded
    # via `Schema.from_snapshot` always yields `grants=()` because the
    # field didn't exist in that format.
    grants: tuple[Grant, ...] = ()
    # Column type / nullability info — populated in snapshot v5+. The
    # ordered tuple parallels `columns` (same length, same order) so
    # callers that need full column info iterate this; callers that
    # need only names continue to read `columns`. v3/v4 baselines
    # round-trip with `column_details=()` since the field didn't exist.
    # The `Schema.to_sql()` emitter requires `column_details` to be
    # populated; otherwise it raises `ValueError`.
    column_details: tuple[Column, ...] = ()
    # User-authored triggers on this table — populated in snapshot v6+.
    # SEC013 inspects this on every `rls_enabled=True` table; internal
    # system triggers (FK constraint helpers etc.) are filtered at the
    # introspection-SQL layer via `pg_trigger.tgisinternal = false`.
    # Default `()` keeps callers that construct `Table(...)` without
    # triggers (e.g. unit tests) working unchanged; v3/v4/v5 baselines
    # round-trip with `triggers=()` since the field didn't exist.
    triggers: tuple[Trigger, ...] = ()
    # Indexes on this table — populated in snapshot v7+. PERF003
    # walks this on every policy to check whether referenced columns
    # have a leading-column index. Only valid + ready indexes are
    # captured (a failed CREATE INDEX CONCURRENTLY produces an
    # invalid index that doesn't help the planner). Default `()`
    # keeps test fixtures working unchanged; v3/v4/v5/v6 baselines
    # round-trip with `indexes=()` so PERF003 simply finds nothing
    # to flag against older snapshots until they're re-captured.
    indexes: tuple[Index, ...] = ()

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True)
class SecdefFunction:
    """A SECURITY DEFINER function captured by introspection.

    Captured in snapshot v4+ alongside `Schema.views`. VIEW004
    inspects the `body` (parsed via pglast against `pg_proc.prosrc`)
    to detect SELECT/INSERT/UPDATE/DELETE references against an
    RLS-protected table — a SECDEF call from a non-invoker view body
    bypasses the caller's RLS via the function owner's privileges.

    `language` is the `pg_language.lanname` for the function (e.g.
    `sql`, `plpgsql`). VIEW004 only attempts pglast parsing for
    `sql` bodies; PL/pgSQL bodies start with `DECLARE`/`BEGIN`
    which pglast can't parse as a top-level statement, so they're
    skipped explicitly with a stderr warning.

    `search_path` is the value of the function's `SET search_path`
    clause (`pg_proc.proconfig`'s `search_path=` entry), or `None`
    when the function pins no search_path at all. SEC015 (snapshot
    v8+) reads this: a SECDEF function whose effective search_path
    lets `pg_temp` be searched before the legitimate schemas is
    exploitable via temp-object shadowing. `None` means the
    function inherits the caller's search_path — attacker-
    controlled, `pg_temp`-first — which is the unsafe default.
    A non-`None` value is the raw GUC string as Postgres stores
    it (e.g. `"pg_catalog, public, pg_temp"`); SEC015 tokenizes
    it to check whether `pg_temp` is pinned last.
    """

    qualified_name: str
    body: str
    language: str
    # None = no `SET search_path` clause (inherits caller's path).
    # Snapshot v8+; v4–v7 snapshots load with search_path=None.
    search_path: str | None = None


@dataclass(frozen=True)
class Schema:
    tables: tuple[Table, ...] = ()
    views: tuple[View, ...] = ()
    security_definer_functions: tuple[SecdefFunction, ...] = ()

    @cached_property
    def _by_qname(self) -> dict[str, Table]:
        # Built once per Schema instance — `ancestors_of` would otherwise
        # rebuild it on every call, which is O(N²) when SEC001 walks N
        # partition children. `cached_property` writes to `__dict__`,
        # bypassing the frozen dataclass's `__setattr__`. The cache is
        # never invalidated because the dataclass is immutable.
        return {t.qualified_name: t for t in self.tables}

    def ancestors_of(self, table: Table) -> Iterator[Table]:
        """Yield partition-of ancestors of `table`, immediate parent first.

        Stops at the root partitioned table or when an ancestor is outside
        the schemas we introspected (whichever comes first). Rules use this
        to walk inheritance for declarative partitioning — e.g. SEC001
        skips a child when an ancestor has `rls_enabled = True`. A child
        whose parent is in an unscoped schema gets a (possibly partial)
        walk that terminates at the gap; rules check `child.partition_of`
        themselves to distinguish "no ancestor" from "ancestor outside
        scope" when the messaging differs.

        Raises ValueError on a cycle. Postgres does not allow cycles in
        `pg_inherits`, so the only path here is corrupted state — silent
        truncation would mask the bug; raising surfaces it loudly.
        """
        current = table
        # Seed with the starting table so a self-cycle (or a chain
        # whose first ancestor points back to `table`) is caught
        # before yielding `table` to the caller. Without this seed,
        # a cycle of length 1 would emit the starting table as if it
        # were its own ancestor before raising.
        seen: set[str] = {table.qualified_name}
        while current.partition_of is not None:
            qname = (
                f"{current.partition_of[0]}.{current.partition_of[1]}"
            )
            if qname in seen:
                raise ValueError(
                    f"partition_of cycle detected at {qname!r}; "
                    "Postgres does not produce cycles in pg_inherits — "
                    "this indicates corrupted introspection state."
                )
            seen.add(qname)
            parent = self._by_qname.get(qname)
            if parent is None:
                return
            yield parent
            current = parent

    def to_snapshot(self) -> Snapshot:
        return {
            "version": SNAPSHOT_VERSION,
            "tables": [
                {
                    "schema": t.schema,
                    "name": t.name,
                    "rls_enabled": t.rls_enabled,
                    "force_rls": t.force_rls,
                    "columns": list(t.columns),
                    "partition_of": (
                        list(t.partition_of)
                        if t.partition_of is not None
                        else None
                    ),
                    "grants": [
                        {"role": g.role, "privileges": list(g.privileges)}
                        for g in t.grants
                    ],
                    # v5 extension — emit per-column type info when
                    # populated. v3/v4 baselines round-trip with
                    # `column_details=()` so this becomes an empty
                    # array, which `from_snapshot` interprets as
                    # "no type info" rather than re-creating Column
                    # rows with placeholder types.
                    "column_details": [
                        {
                            "name": c.name,
                            "data_type": c.data_type,
                            "is_nullable": c.is_nullable,
                        }
                        for c in t.column_details
                    ],
                    # v6 extension — emit user-authored triggers. SEC013
                    # reads this on every `rls_enabled=True` table. The
                    # ordering matches `Table.triggers`, which the
                    # introspection layer sorts by trigger name for
                    # snapshot determinism. v3/v4/v5 baselines round-trip
                    # with `triggers=()` → empty array.
                    "triggers": [
                        {
                            "name": tr.name,
                            "function_schema": tr.function_schema,
                            "function_name": tr.function_name,
                            "event": tr.event,
                            "timing": tr.timing,
                            "enabled": tr.enabled,
                        }
                        for tr in t.triggers
                    ],
                    # v7 extension — emit valid+ready indexes. PERF003
                    # reads this on every policy. Order matches
                    # `Table.indexes` (sorted by name at introspection
                    # time) for snapshot determinism. v3-v6 baselines
                    # round-trip with `indexes=()` → empty array.
                    "indexes": [
                        {
                            "name": idx.name,
                            "access_method": idx.access_method,
                            "columns": list(idx.columns),
                            "is_unique": idx.is_unique,
                            "is_partial": idx.is_partial,
                        }
                        for idx in t.indexes
                    ],
                }
                for t in self.tables
            ],
            "policies": [
                {
                    "id": f"{t.schema}.{t.name}.{p.name}",
                    "table_schema": t.schema,
                    "table_name": t.name,
                    "policy_name": p.name,
                    "command": p.command,
                    "permissive": p.permissive,
                    "roles": list(p.roles),
                    "using_sql": p.using_sql,
                    "with_check_sql": p.with_check_sql,
                }
                for t in self.tables
                for p in t.policies
            ],
            "views": [
                {
                    "schema": v.schema,
                    "name": v.name,
                    "is_materialized": v.is_materialized,
                    "security_invoker": v.security_invoker,
                    "security_barrier": v.security_barrier,
                    "definition": v.definition,
                    "references": [list(ref) for ref in v.references],
                    "security_definer_calls": list(v.security_definer_calls),
                }
                for v in self.views
            ],
            "security_definer_functions": [
                {
                    "qualified_name": f.qualified_name,
                    "body": f.body,
                    "language": f.language,
                    "search_path": f.search_path,
                }
                for f in self.security_definer_functions
            ],
        }

    @classmethod
    def from_snapshot(cls, payload: dict[str, Any]) -> Schema:
        """Reconstruct a Schema from a v3-v8 snapshot dict.

        v8 (current): adds ``search_path`` to each SECDEF function
        for SEC015. v4-v7 snapshots' SECDEF functions load with
        ``search_path=None`` (v3 has no SECDEF functions at all —
        ``security_definer_functions`` is a v4+ field).
        v7: adds per-table ``indexes`` for PERF003.
        v6: adds per-table ``triggers`` for SEC013.
        v5: adds per-column type info via the new ``column_details``
        array on each table. Required for ``Schema.to_sql()`` and
        the migration-as-input flow (``pgrls diff --apply``).
        v4: full fidelity for views and SECDEF functions; no
        column type info.
        v3: legacy — views come back as ``()``, no column type info.

        v1 / v2 / unknown versions: raises ValueError with a clear
        "snapshot version N is not supported" message naming the
        supported set.

        AST fields (`using_ast`, `with_check_ast`) are NOT serialized
        AND are NOT eagerly re-parsed on load. v0.2+ leaves both as
        `None` after `from_snapshot`. Callers that need ASTs must
        parse on demand via `pgrls.ast_utils.parse_expr(policy.using_sql)`.

        Rationale: the only consumer that reads ASTs from a loaded
        snapshot is `pgrls.diff._diff_columns` (column-reference
        extraction); the predicate-diff path re-parses raw SQL via
        `compare_predicates` anyway. Eager parsing on load was
        wasted work for every diff that doesn't drop columns. The
        lint path (`pgrls lint`) doesn't use `from_snapshot` — it
        introspects directly, which still parses ASTs on capture.
        """
        version = payload.get("version")
        if version not in (3, 4, 5, 6, 7, 8):
            raise ValueError(
                f"snapshot version {version!r} is not supported by this "
                f"pgrls release. Supported versions: 3, 4, 5, 6, 7, 8. "
                "v1 / v2 snapshots must be regenerated against the current "
                "schema."
            )

        # Build a {(schema, name): [policy_dict, ...]} index from the
        # top-level "policies" array that to_snapshot() produces.
        # Per-table embedded policies (used in manual test fixtures and
        # the legacy v2 format) are also accepted as a fallback.
        top_level_policies: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for p in payload.get("policies", []):
            key = (p["table_schema"], p["table_name"])
            top_level_policies.setdefault(key, []).append(p)

        tables: list[Table] = []
        for t in payload.get("tables", []):
            key = (t["schema"], t["name"])
            # Prefer top-level policies (canonical format); fall back to
            # per-table embedded policies (legacy / manual test fixtures).
            # When BOTH paths have data, top-level wins (Python `or` short-
            # circuits on the truthy first list); the embedded list is
            # silently ignored. This is a defensive choice — to_snapshot
            # only writes top-level — but a malformed snapshot mixing
            # both should not silently merge them.
            raw_policies = top_level_policies.get(key) or t.get("policies", [])
            # ASTs are intentionally left as None here — the v0.2.1
            # contract documents that callers parse on demand. The
            # only in-tree consumer that needs them is
            # pgrls.diff._diff_columns, which now lazy-parses.
            policies = tuple(
                Policy(
                    # Top-level format uses "policy_name"; embedded uses "name".
                    name=p.get("policy_name") or p["name"],
                    command=p["command"],
                    permissive=p["permissive"],
                    roles=tuple(p["roles"]),
                    using_sql=p.get("using_sql"),
                    with_check_sql=p.get("with_check_sql"),
                    using_ast=None,
                    with_check_ast=None,
                )
                for p in raw_policies
            )
            grants_raw = t.get("grants", [])
            grants = tuple(
                Grant(role=g["role"], privileges=tuple(g["privileges"]))
                for g in grants_raw
            )
            partition_of_raw = t.get("partition_of")
            partition_of = (
                tuple(partition_of_raw) if partition_of_raw else None
            )
            # v5 extension — `column_details` gives full type info per
            # column. v3/v4 baselines have it absent or empty; that
            # path leaves `column_details=()` and `Schema.to_sql()`
            # later raises ValueError if the user tries to restore.
            column_details_raw = t.get("column_details", [])
            column_details = tuple(
                Column(
                    name=c["name"],
                    data_type=c["data_type"],
                    is_nullable=c.get("is_nullable", True),
                )
                for c in column_details_raw
            )
            # v6 extension — `triggers` holds the user-authored triggers
            # captured for SEC013. v3/v4/v5 baselines have the field
            # absent (`.get(...) → []`), which round-trips into an empty
            # tuple — SEC013 simply finds nothing to flag.
            triggers_raw = t.get("triggers", [])
            triggers = tuple(
                Trigger(
                    name=tr["name"],
                    function_schema=tr["function_schema"],
                    function_name=tr["function_name"],
                    event=tr["event"],
                    timing=tr["timing"],
                    enabled=tr["enabled"],
                )
                for tr in triggers_raw
            )
            # v7 extension — `indexes` holds the valid+ready indexes
            # captured for PERF003. v3-v6 baselines round-trip with
            # the field absent (`.get(...) → []`), which yields an
            # empty tuple — PERF003 finds nothing to flag against
            # older snapshots until they're re-captured.
            indexes_raw = t.get("indexes", [])
            indexes = tuple(
                Index(
                    name=idx["name"],
                    access_method=idx["access_method"],
                    columns=tuple(idx["columns"]),
                    is_unique=idx["is_unique"],
                    is_partial=idx["is_partial"],
                )
                for idx in indexes_raw
            )
            tables.append(
                Table(
                    schema=t["schema"],
                    name=t["name"],
                    rls_enabled=t["rls_enabled"],
                    force_rls=t["force_rls"],
                    policies=policies,
                    columns=tuple(t.get("columns", ())),
                    partition_of=partition_of,
                    grants=grants,
                    column_details=column_details,
                    triggers=triggers,
                    indexes=indexes,
                )
            )
        # v3 has no "views" array; treat as empty tuple.
        raw_views = payload.get("views", []) if version >= 4 else []
        views = tuple(
            View(
                schema=v["schema"],
                name=v["name"],
                is_materialized=v["is_materialized"],
                security_invoker=v["security_invoker"],
                security_barrier=v["security_barrier"],
                definition=v["definition"],
                references=tuple(tuple(r) for r in v["references"]),
                security_definer_calls=tuple(v["security_definer_calls"]),
            )
            for v in raw_views
        )
        # `security_definer_functions` is a v4+ field. `.get(..., [])`
        # keeps older snapshots loadable — they get an empty tuple,
        # which means VIEW004 / SEC014 / SEC015 find nothing to flag
        # (correct, since the snapshot didn't capture the functions).
        #
        # `search_path` on each function is a v8 addition for SEC015.
        # v4–v7 snapshots have no `search_path` key; `.get(...,
        # None)` loads them with `search_path=None`. That maps to
        # "no SET search_path clause" — which SEC015 treats as
        # unsafe. A pre-v8 snapshot can't distinguish "function
        # pinned a safe search_path" from "function pinned nothing",
        # so SEC015 on a stale snapshot conservatively flags every
        # SECDEF function. Re-snapshot against a live database (v8)
        # to get the real search_path values.
        raw_secdef_funcs = (
            payload.get("security_definer_functions", []) if version >= 4 else []
        )
        secdef_funcs = tuple(
            SecdefFunction(
                qualified_name=f["qualified_name"],
                body=f["body"],
                language=f["language"],
                search_path=f.get("search_path"),
            )
            for f in raw_secdef_funcs
        )

        return cls(
            tables=tuple(tables),
            views=views,
            security_definer_functions=secdef_funcs,
        )

    def to_sql(self) -> str:
        """Emit DDL that re-creates this Schema in an empty Postgres.

        Used by ``pgrls diff --apply migration.sql`` (v0.5+) to spin
        up a baseline-equivalent state in a throwaway testcontainer
        before applying the user's migration. The output covers the
        minimum DDL needed to make the migration apply against the
        captured shape:

        * ``CREATE SCHEMA IF NOT EXISTS <schema>`` per distinct schema
          referenced by tables. Idempotent so it can be re-run.
        * ``CREATE TABLE <qname> (<col1 type1>, <col2 type2>, ...)``
          per table. Constraints, defaults, generated columns,
          indexes, and foreign keys are NOT emitted — the diff target
          is RLS-state changes, not data integrity. A migration that
          ALTERs a column's type, drops a column, or adds a CHECK
          constraint will still apply correctly because the column
          exists with a compatible type.
        * ``ALTER TABLE … ENABLE ROW LEVEL SECURITY`` /
          ``FORCE ROW LEVEL SECURITY`` as captured.
        * ``CREATE POLICY`` per policy with ``AS RESTRICTIVE`` /
          ``FOR <command>`` / ``TO <roles>`` / ``USING (...)`` /
          ``WITH CHECK (...)`` mirroring the captured fields.
        * ``GRANT <privs> ON <qname> TO <role>`` per (role, table)
          pair.

        Roles referenced by policies and grants are NOT created here
        — Postgres rejects ``CREATE POLICY ... TO <role>`` if the
        role doesn't exist. The caller (``pgrls diff --apply``) wraps
        each ``CREATE POLICY`` and ``GRANT`` in a
        ``DO $$ ... CREATE ROLE IF NOT EXISTS ... $$`` preamble, so
        the testcontainer has the named roles before this DDL runs.
        That keeps ``Schema.to_sql()`` itself a pure function of the
        Schema object — no role-creation side effects.

        Raises ValueError if any table is missing ``column_details``
        — the emitter cannot fabricate types. v3/v4 baselines need
        to be re-captured against a live database before they can
        be used for ``--apply``.

        The emitted SQL is multi-statement; safe to feed to a single
        ``cur.execute()`` call against a Postgres connection.
        """
        # Pre-flight: every table must have column_details populated.
        # Surface a single error listing all missing tables so the
        # user fixes the snapshot once instead of replay-hunting.
        tables_missing_details = [
            t.qualified_name for t in self.tables if not t.column_details
        ]
        if tables_missing_details:
            raise ValueError(
                "Schema.to_sql() requires every table to have "
                "column_details populated. The following tables are "
                "missing it: "
                + ", ".join(tables_missing_details)
                + ". Snapshots from pgrls v0.4 or earlier don't "
                "capture column types; re-capture against a live "
                "database with pgrls v0.5+ to populate the field."
            )

        from pgrls.fixers._idents import quote_ident

        out: list[str] = []

        # 1. Schemas. Emit a CREATE SCHEMA IF NOT EXISTS for every
        # distinct schema referenced. Idempotent so applying twice
        # is a no-op.
        schemas = sorted({t.schema for t in self.tables})
        for schema in schemas:
            out.append(
                f"CREATE SCHEMA IF NOT EXISTS {quote_ident(schema)};"
            )

        # 2. Tables (CREATE TABLE).
        for t in self.tables:
            qname = (
                f"{quote_ident(t.schema)}.{quote_ident(t.name)}"
            )
            cols = ", ".join(
                f"{quote_ident(c.name)} {c.data_type}"
                + ("" if c.is_nullable else " NOT NULL")
                for c in t.column_details
            )
            out.append(f"CREATE TABLE {qname} ({cols});")

        # 3. RLS toggles.
        for t in self.tables:
            qname = (
                f"{quote_ident(t.schema)}.{quote_ident(t.name)}"
            )
            if t.rls_enabled:
                out.append(f"ALTER TABLE {qname} ENABLE ROW LEVEL SECURITY;")
            if t.force_rls:
                out.append(f"ALTER TABLE {qname} FORCE ROW LEVEL SECURITY;")

        # 4. Policies. Emitted in a fixed order: by table then by
        # policy name, so two `to_sql()` calls on the same Schema
        # produce byte-identical output (helpful for smoke-tests
        # and golden-file comparisons).
        for t in self.tables:
            qname = (
                f"{quote_ident(t.schema)}.{quote_ident(t.name)}"
            )
            for p in t.policies:
                out.append(_policy_to_sql(p, qname))

        # 5. Grants. PUBLIC pseudo-role keeps its bare-PUBLIC form;
        # named roles are quoted via quote_ident.
        for t in self.tables:
            qname = (
                f"{quote_ident(t.schema)}.{quote_ident(t.name)}"
            )
            for g in t.grants:
                privs = ", ".join(g.privileges)
                role_sql = (
                    "PUBLIC"
                    if g.role == "PUBLIC"
                    else quote_ident(g.role)
                )
                out.append(
                    f"GRANT {privs} ON {qname} TO {role_sql};"
                )

        return "\n".join(out) + "\n"


def _policy_to_sql(p: Policy, qname: str) -> str:
    """Render a single CREATE POLICY statement for `Schema.to_sql()`.

    Mirrors the canonical Postgres syntax: AS PERMISSIVE/RESTRICTIVE
    (omit if PERMISSIVE — that's the default), FOR <command> (omit
    if ALL), TO <roles>, USING (...) and/or WITH CHECK (...).
    Roles are emitted bare-comma-separated, matching pg_policy
    output — Postgres parses both quoted and unquoted forms in
    most cases, but we follow the dump style for predictability.
    """
    from pgrls.fixers._idents import quote_ident

    parts = ["CREATE POLICY", quote_ident(p.name), "ON", qname]
    if not p.permissive:
        parts.append("AS RESTRICTIVE")
    if p.command != "ALL":
        parts.append(f"FOR {p.command}")
    role_strs = [
        "PUBLIC" if r == "PUBLIC" else quote_ident(r) for r in p.roles
    ]
    parts.append(f"TO {', '.join(role_strs)}")
    if p.using_sql:
        parts.append(f"USING ({p.using_sql})")
    if p.with_check_sql:
        parts.append(f"WITH CHECK ({p.with_check_sql})")
    return " ".join(parts) + ";"
