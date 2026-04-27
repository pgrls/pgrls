"""Normalized representation of a Postgres schema's RLS state.

Snapshot format is versioned via a single int (`SNAPSHOT_VERSION`); bump
on any change that adds, removes, or restructures an emitted field.
Currently version 2 (v2 added `partition_of` to each table entry).
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Literal

PolicyCommand = Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
Snapshot = dict[str, Any]

SNAPSHOT_VERSION = 2


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
        seen: set[str] = set()
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
