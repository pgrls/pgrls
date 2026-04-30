"""Normalized representation of a Postgres schema's RLS state.

Snapshot format is versioned via a single int (`SNAPSHOT_VERSION`); bump
on any change that adds, removes, or restructures an emitted field.
Currently version 3 (v3 added `grants` to each table entry; v2 added
`partition_of`).
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Literal

__all__ = [
    "Grant",
    "Policy",
    "PolicyCommand",
    "SNAPSHOT_VERSION",
    "Schema",
    "Snapshot",
    "Table",
]

PolicyCommand = Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
Snapshot = dict[str, Any]

SNAPSHOT_VERSION = 3


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

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True)
class Schema:
    tables: tuple[Table, ...] = ()

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
        }

    @classmethod
    def from_snapshot(cls, payload: dict[str, Any]) -> Schema:
        """Reconstruct a Schema from a v2 or v3 snapshot dict.

        v3 (current): full fidelity. v2 (legacy): grants come back
        as `()` per table — v2 didn't capture grants. **Caveat:** the
        diff layer doesn't know which side is v2-shaped, so any
        per-table grant present in the v3 head will look like a
        GRANT_ADDED (or, in the PUBLIC + no-RLS shape, a
        GRANT_PUBLIC_NO_RLS) when diffed against a v2 baseline,
        even when the actual cluster state was unchanged. Treat
        v2 baselines as ground-truth-incomplete on the grants axis;
        re-capture as v3 once available.

        v1 / unknown versions: raises ValueError with a clear
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
        if version not in (2, 3):
            raise ValueError(
                f"snapshot version {version!r} is not supported by this "
                f"pgrls release. Supported versions: 2, 3. v1 snapshots "
                "must be regenerated against the current schema."
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
            grants_raw = t.get("grants", []) if version >= 3 else []
            grants = tuple(
                Grant(role=g["role"], privileges=tuple(g["privileges"]))
                for g in grants_raw
            )
            partition_of_raw = t.get("partition_of")
            partition_of = (
                tuple(partition_of_raw) if partition_of_raw else None
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
                )
            )
        return cls(tables=tuple(tables))
