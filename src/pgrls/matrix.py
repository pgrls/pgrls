"""Effective access matrix for `pgrls matrix`.

`pgrls report` answers "what's each table's RLS posture?"; `pgrls matrix`
answers the audit question **"who can reach which rows?"** — a grid of role x
table x command (SELECT, INSERT, UPDATE, DELETE, TRUNCATE), one verdict per
cell, from the engine in `pgrls.access`:

* ``open``        — every row: the role holds the privilege and RLS lets every
  row through (RLS off; superuser; BYPASSRLS; the owner's privileges on a table
  that is not ``FORCE``d; TRUNCATE, which RLS never applies to; an applicable
  permissive policy that is unconditionally true with no restrictive policy
  narrowing it) — directly or through a door.
* ``conditional`` — some rows: the predicate is the OR of the applicable
  permissive clauses (``WITH CHECK`` for INSERT, ``USING`` otherwise) AND-ed
  with the restrictive ones. A cell reached through a door names the door in
  its note and carries the door's predicate.
* ``denied``      — no privilege on any path pgrls models, or RLS on with no
  applicable permissive policy (Postgres default-denies).
* ``undecided``   — the rows cannot be bounded: a materialized view over the
  table, a foreign-key action, two different filtered paths whose union is
  unknown, or — for a schema built without a role-membership graph —
  memberships that were not captured. Treat it as possibly reachable.

Doors widen a cell for the command they run: definer views (writes when
auto-updatable), SECURITY DEFINER functions (per statement of an SQL or
PL/pgSQL body), SECURITY DEFINER triggers (fired by writing their table),
rewrite rules, partition / inheritance parents, and foreign-key actions. A
door whose SQL cannot be traced is listed on its own. Each role is a session
running as that role: ``SET ROLE`` and DDL are not modelled; the rest of what
is not is in `pgrls.access`'s docstring and the README.

"Unconditionally true" is lexical — a literal ``true`` disjunct. A tautology
such as ``1 = 1`` shows as ``conditional`` with that predicate even though
every row is reachable.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pgrls._html_common import html_page, resolve_generated_at, to_iso_z
from pgrls._render_common import make_dispatcher, pluralize, render_text_table
from pgrls.access import (
    COMMANDS,
    AccessPath,
    Cell,
    RoleReach,
    Verdict,
    _derived_roles,
    _reachable_columns,
    _sensitive,
    principal_of,
    role_reach,
)
from pgrls.formatters._common import safe_location
from pgrls.model import Schema, Table
from pgrls.rules.sec045 import _DEFAULT_PATTERNS

__all__ = [
    "COMMANDS", "Cell", "Exposure", "MATRIX_FORMATS", "Matrix", "MatrixRow",
    "Untraced", "Verdict", "build_matrix", "introspect_for_matrix", "render",
    "render_html", "render_json", "render_markdown", "render_text",
]

# Roles shown even when they reach nothing — the Supabase / PostgREST audit
# baseline. With the role catalogue, anon and authenticated only if they exist.
_DEFAULT_ROLES = ("PUBLIC", "anon", "authenticated")

_VERDICT_LABEL = {
    "open": "OPEN", "denied": "DENIED", "conditional": "COND", "undecided": "UNDECIDED",
}

_MATRIX_CSS = """    tr:nth-child(even) td { background: #0d1117; }
    tr:nth-child(odd) td { background: #161b22; }
    code { background: #161b22; }
  }
  header { margin-bottom: 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem 0; }
  .meta { color: #57606a; font-size: .85rem; }
  .summary { margin: 1rem 0 .5rem; }
  .pills { display: flex; flex-wrap: wrap; gap: .5rem; margin: 0 0 1.5rem 0; }
  .pill { display: inline-block; padding: .15rem .55rem; border-radius: 999px;
           font-size: .85rem; border: 1px solid currentColor; }
  .v-open        { color: #cf222e; }
  .v-denied      { color: #1a7f37; }
  .v-conditional { color: #9a6700; }
  .v-undecided   { color: #8250df; }
  .v-empty       { color: #57606a; }
  table { width: 100%; border-collapse: collapse; border: 1px solid #d0d7de; }
  thead th { text-align: left; padding: .5rem .75rem; background: #f6f8fa;
              border-bottom: 1px solid #d0d7de; font-weight: 600; }
  tbody td { padding: .5rem .75rem; border-bottom: 1px solid #d0d7de;
              vertical-align: top; }
  tbody tr:last-child td { border-bottom: 0; }
  code { background: #f6f8fa; padding: .1rem .35rem; border-radius: 4px;
          font: .9em ui-monospace, Menlo, monospace; }"""


@dataclass(frozen=True)
class MatrixRow:
    qualified_name: str
    command: str
    cells: tuple[Cell, ...]  # aligned with Matrix.roles


@dataclass(frozen=True)
class Exposure:
    """A sensitive column (by name, SEC045's patterns) a role can read.

    `verdict` is the role's merged SELECT verdict for the TABLE — never
    ``denied``. It can over-state one column: when the widest path does not
    reach that column (a column grant elsewhere), the column's own reach may be
    narrower. `via` names how, crediting only the paths that reach this
    column: a grant, ownership, a data role, a definer view, a SECURITY DEFINER
    function or trigger, a rewrite rule, or a parent. A door is credited with
    every column of the table — column lineage through a view or a function
    is not traced — which is an over-report, the safe direction for an audit.
    """

    role: str
    table: str
    column: str
    verdict: Verdict
    via: str


@dataclass(frozen=True)
class Untraced:
    """A door some analysed role can open whose SQL could not be fully traced
    — a SECURITY DEFINER function, trigger or rule running dynamic SQL,
    another language, a call pgrls cannot see into, or a statement it does
    not trace. It may reach tables no cell credits it with. `reached_by`
    names who can open it — a function's EXECUTE holders, or the write that
    fires a trigger or rule — whether or not they are shown as columns."""

    door: str
    owner: str
    reason: str
    reached_by: str


@dataclass(frozen=True)
class Matrix:
    roles: tuple[str, ...]
    rows: tuple[MatrixRow, ...]
    exposures: tuple[Exposure, ...] = ()
    untraced: tuple[Untraced, ...] = ()

    @property
    def summary(self) -> dict[str, int]:
        counts = {"open": 0, "denied": 0, "conditional": 0, "undecided": 0}
        for row in self.rows:
            for cell in row.cells:
                counts[cell.verdict] += 1
        return {
            "tables": len({r.qualified_name for r in self.rows}),
            "roles": len(self.roles),
            "cells": sum(len(r.cells) for r in self.rows),
            "open": counts["open"],
            "denied": counts["denied"],
            "conditional": counts["conditional"],
            "undecided": counts["undecided"],
        }


def _is_system_role(role: str) -> bool:
    # Postgres-reserved (`pg_*`) and the introspect `oid:N` fallback for a
    # dropped/unresolved role.
    return role.startswith("pg_") or role.startswith("oid:")


def _order(role: str) -> tuple[int, str]:
    return ({"PUBLIC": 0, "anon": 1, "authenticated": 2}.get(role, 3), role)


def _candidate_roles(
    schema: Schema, *, include_system: bool
) -> tuple[tuple[str, ...], frozenset[str]]:
    """The roles to analyse, and the ones shown whatever they reach.

    With the role catalogue (live introspection, snapshot v27+) that is every
    role in it; without it, every name the schema mentions. PUBLIC is always
    shown, and anon / authenticated when they exist (always, without a
    catalogue to say otherwise).
    """
    if schema.roles is not None:
        names = {r.name for r in schema.roles}
        always = {"PUBLIC"} | (names & {"anon", "authenticated"})
    else:
        names = {r.name for r in _derived_roles(schema)}
        always = set(_DEFAULT_ROLES)
    names |= always
    if not include_system:
        names = {n for n in names if not _is_system_role(n)} | always
    return tuple(sorted(names, key=_order)), frozenset(always)


def build_matrix(
    schema: Schema,
    *,
    roles: tuple[str, ...] | None = None,
    include_system: bool = False,
    grid: frozenset[str] | None = None,
    sensitive_patterns: frozenset[str] | None = None,
) -> Matrix:
    """Build the effective access matrix from an introspected `schema`.

    `grid` names the tables shown as rows (default: every table); the others
    are analysed only as the far end of a door — a parent, a view's base, a
    function's, trigger's or rule's target. `roles` fixes the columns.
    Otherwise every candidate is analysed and the columns are PUBLIC; anon and
    authenticated when they exist; and every other role whose reach DIFFERS
    from PUBLIC's in the grid — a cell with another verdict or predicate, a
    sensitive column PUBLIC cannot read, or an untraced door PUBLIC cannot
    open. A role that can do exactly what everyone
    can adds nothing (measured: one PUBLIC-executable helper function made
    every role in a Supabase cluster a column). `pg_*` roles are left out
    unless `include_system`. Rows are sorted by (table, command).
    `sensitive_patterns` replaces SEC045's default patterns; `pgrls matrix`
    passes the defaults plus `[lint.rules.SEC045].patterns`, as SEC045 reads
    its own config.

    Role attributes come from `schema.roles` (live introspection) or, without
    it, from `bypassrls_roles`. A schema from an offline source carries
    neither reliably, so an exempt role there shows as an ordinary one;
    `pgrls matrix` itself reads only a live database.
    """
    catalogue = schema.roles if schema.roles is not None else _derived_roles(schema)
    attrs = {r.name: r for r in catalogue}
    shown = sorted(
        (t for t in schema.tables if grid is None or t.qualified_name in grid),
        key=lambda t: t.qualified_name,
    )
    if roles is not None:
        candidates, always = tuple(roles), frozenset(roles)
    else:
        candidates, always = _candidate_roles(schema, include_system=include_system)
    cache: dict[Any, Any] = {}  # lookups and function bodies, once per build
    reaches: dict[str, RoleReach] = {}
    for name in dict.fromkeys((*candidates, "PUBLIC")):
        role, closure = principal_of(schema, name, attrs)
        reaches[name] = role_reach(schema, role, closure, attrs, cache)
    public = reaches["PUBLIC"]
    public_untraced = {(u.door, u.reason) for u in public.untraced}
    patterns = sensitive_patterns or _DEFAULT_PATTERNS
    exposed: dict[str, set[tuple[str, str, str]]] = {}
    for e in _exposures(shown, tuple(reaches), reaches, patterns):
        exposed.setdefault(e.role, set()).add((e.table, e.column, e.verdict))

    def differs(name: str) -> bool:
        mine = reaches[name]
        for t in shown:
            for command in COMMANDS:
                a = mine.cells[(t.qualified_name, command)]
                b = public.cells[(t.qualified_name, command)]
                if (a.verdict, a.predicate) != (b.verdict, b.predicate):
                    return True
        # A column grant can leave every cell as PUBLIC's while the role reads
        # a sensitive column PUBLIC cannot (measured: `ssn`).
        if exposed.get(name, set()) != exposed.get("PUBLIC", set()):
            return True
        return bool({(u.door, u.reason) for u in mine.untraced} - public_untraced)

    role_list = tuple(n for n in candidates if n in always or differs(n))
    rows = [
        MatrixRow(
            qualified_name=table.qualified_name,
            command=command,
            cells=tuple(reaches[n].cells[(table.qualified_name, command)] for n in role_list),
        )
        for table in shown
        for command in COMMANDS
    ]
    return Matrix(
        roles=role_list,
        rows=tuple(rows),
        exposures=tuple(e for e in _exposures(shown, tuple(reaches), reaches, patterns)
                        if e.role in role_list),
        untraced=_untraced(candidates, reaches),
    )


def introspect_for_matrix(conn: Any, schemas: list[str]) -> tuple[Schema, frozenset[str]]:
    """Introspect every user schema, and name the tables of `schemas` as the
    grid. A door can live anywhere, and so can the far end of one: measured, a
    definer view in `api` over `public.t`, and a partitioned `api.events` over
    `public.events_a`, each handed rows to a role that a `--schemas public`
    matrix said was DENIED."""
    from psycopg.rows import dict_row  # noqa: PLC0415

    from pgrls.introspect import _list_user_schemas, introspect  # noqa: PLC0415

    with conn.cursor(row_factory=dict_row) as cur:
        everywhere = _list_user_schemas(cur)
    # `schemas` stays in the list so a misspelt one still fails loudly.
    schema = introspect(conn, schemas=sorted(set(everywhere) | set(schemas)))
    grid = frozenset(t.qualified_name for t in schema.tables if t.schema in schemas)
    return schema, grid


def _via(paths: tuple[AccessPath, ...], principal: str, column: str) -> str:
    """The paths that reach `column` specifically. A column grant covers only
    its own columns, so crediting it for every sensitive column on the table
    misstated how a column was reached — measured: `ssn`, reachable only
    through a definer view, was listed as reached via a column grant on
    `email`. A path with no column list (a table grant, a door) reaches every
    column."""
    labels = []
    for p in paths:
        if p.columns is not None and column not in p.columns:
            continue
        if p.kind == "view":
            labels.append(f"view {p.via}")
        elif p.kind == "function":
            labels.append(f"SECURITY DEFINER {p.via}")
        elif p.kind in ("trigger", "rule"):
            labels.append(p.via or p.kind)
        elif p.kind == "parent":
            labels.append(f"parent {p.via}")
        elif p.kind == "foreign_key":
            labels.append(f"foreign key {p.via}")
        elif p.kind == "data_role":
            labels.append(p.via or "data role")
        elif p.kind in ("grant", "column_grant", "owner_member") and p.via:
            label = p.kind.replace("_", " ")
            labels.append(label if p.via == principal else f"{label} via {p.via}")
        else:
            labels.append(p.kind.replace("_", " "))
    return "; ".join(dict.fromkeys(labels)) or "-"


def _exposures(
    shown: list[Table],
    role_list: tuple[str, ...],
    reaches: dict[str, RoleReach],
    patterns: frozenset[str],
) -> tuple[Exposure, ...]:
    """Every sensitive column each shown role can read with at least some
    rows, from the same merged verdicts as the cells. A direct path whose RLS
    admits no row is not a way in, so it is not credited."""
    out: list[Exposure] = []
    for name in role_list:
        reach = reaches[name]
        for table in shown:
            q = table.qualified_name
            cell = reach.cells[(q, "SELECT")]
            if cell.verdict == "denied":
                continue
            direct_cell, direct_paths = reach.direct_select[q]
            paths = (direct_paths if direct_cell.verdict != "denied" else ()) + reach.door_paths[q]
            cols = _reachable_columns(paths) if paths else None
            for col in _sensitive(table, cols, patterns):
                out.append(Exposure(
                    role=name, table=q, column=col, verdict=cell.verdict,
                    via=_via(paths, name, col),
                ))
    return tuple(sorted(out, key=lambda e: (e.table, e.column, e.role)))


def _untraced(
    candidates: tuple[str, ...], reaches: dict[str, RoleReach]
) -> tuple[Untraced, ...]:
    seen = {
        (u.door, u.owner, u.reason, u.reached_by)
        for name in candidates
        for u in reaches[name].untraced
    }
    return tuple(Untraced(*k) for k in sorted(seen))


def _summary_line(matrix: Matrix) -> str:
    s = matrix.summary
    return (
        f"{s['tables']} {pluralize(s['tables'], 'table')} x "
        f"{s['roles']} {pluralize(s['roles'], 'role')}: "
        f"{s['open']} open, {s['conditional']} conditional, {s['denied']} denied"
        + (f", {s['undecided']} undecided" if s["undecided"] else "")
        + "."
    )


def _exposure_rows(matrix: Matrix) -> list[list[str]]:
    return [
        [
            safe_location(f"{e.table}.{e.column}"),
            safe_location(e.role),
            _VERDICT_LABEL[e.verdict],
            safe_location(e.via),
        ]
        for e in matrix.exposures
    ]


_UNTRACED_TITLE = "Doors not traced — each may reach tables no cell credits it with"


def _untraced_rows(matrix: Matrix) -> list[list[str]]:
    return [
        [
            safe_location(u.door),
            safe_location(u.owner),
            safe_location(u.reached_by),
            safe_location(u.reason),
        ]
        for u in matrix.untraced
    ]


def render_text(matrix: Matrix) -> str:
    if not matrix.rows:
        return "No tables found in the scanned schemas."
    headers = ("TABLE", "CMD", *(safe_location(r) for r in matrix.roles))
    rows = [
        (
            safe_location(row.qualified_name),
            row.command,
            *(_VERDICT_LABEL[c.verdict] for c in row.cells),
        )
        for row in matrix.rows
    ]
    out = render_text_table(headers, rows)
    if matrix.exposures:
        out += ["", "Sensitive columns reachable:"]
        out += ["  " + ln for ln in render_text_table(
            ("COLUMN", "ROLE", "ROWS", "VIA"), _exposure_rows(matrix)
        )]
    if matrix.untraced:
        out += ["", _UNTRACED_TITLE + ":"]
        out += ["  " + ln for ln in render_text_table(
            ("DOOR", "OWNER", "REACHED BY", "WHY"), _untraced_rows(matrix)
        )]
    out.append("")
    out.append(_summary_line(matrix))
    return "\n".join(out)


def render_json(matrix: Matrix) -> str:
    payload = {
        "summary": matrix.summary,
        "roles": list(matrix.roles),
        "rows": [
            {
                "table": row.qualified_name,
                "command": row.command,
                "access": {
                    role: {
                        "verdict": cell.verdict,
                        "predicate": cell.predicate,
                        "note": cell.note,
                    }
                    for role, cell in zip(matrix.roles, row.cells, strict=True)
                },
            }
            for row in matrix.rows
        ],
        # Always present (possibly empty) so the document's shape does not
        # depend on what the schema happens to contain.
        "sensitive_exposures": [
            {
                "role": e.role,
                "table": e.table,
                "column": e.column,
                "verdict": e.verdict,
                "via": e.via,
            }
            for e in matrix.exposures
        ],
        "untraced_doors": [
            {
                "door": u.door,
                "owner": u.owner,
                "reached_by": u.reached_by,
                "reason": u.reason,
            }
            for u in matrix.untraced
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_markdown(matrix: Matrix) -> str:
    if not matrix.rows:
        return "# Access matrix\n\nNo tables found in the scanned schemas."
    # safe_location strips newlines/tabs/control chars (a role name from
    # pg_roles can carry them via a quoted identifier) so they cannot split the
    # GFM row; the pipe-escape then guards column boundaries — same composition
    # the body cells use.
    cols = ["Table", "Command", *(safe_location(r) for r in matrix.roles)]
    header = "| " + " | ".join(c.replace("|", "\\|") for c in cols) + " |"
    sep = "|" + "---|" * len(cols)
    body = []
    for row in matrix.rows:
        cells = [
            safe_location(row.qualified_name).replace("|", "\\|"),
            row.command,
            *(_VERDICT_LABEL[c.verdict] for c in row.cells),
        ]
        body.append("| " + " | ".join(cells) + " |")
    tail: list[str] = []
    if matrix.exposures:
        tail = ["", "## Sensitive columns reachable", "",
                "| Column | Role | Rows | Via |", "|---|---|---|---|"]
        tail.extend(
            "| " + " | ".join(c.replace("|", "\\|") for c in r) + " |"
            for r in _exposure_rows(matrix)
        )
    if matrix.untraced:
        tail += ["", f"## {_UNTRACED_TITLE}", "",
                 "| Door | Owner | Reached by | Why |", "|---|---|---|---|"]
        tail.extend(
            "| " + " | ".join(c.replace("|", "\\|") for c in r) + " |"
            for r in _untraced_rows(matrix)
        )
    return "\n".join(
        ["# Access matrix", "", _summary_line(matrix), "", header, sep, *body, *tail]
    )


def render_html(matrix: Matrix, *, generated_at: datetime | None = None) -> str:
    generated_at = resolve_generated_at(generated_at, caller_name="render_html")
    now = to_iso_z(generated_at)
    s = matrix.summary

    chips = []
    for verdict in ("open", "conditional", "denied", "undecided"):
        if verdict == "undecided" and not s["undecided"]:
            continue
        chips.append(
            f'<span class="pill v-{verdict}"><strong>{s[verdict]}</strong>'
            f"&nbsp;{verdict}</span>"
        )
    chips_html = "\n      ".join(chips)

    if not matrix.rows:
        rows_html = (
            f'<tr><td colspan="{2 + len(matrix.roles)}" class="empty">'
            "No tables found in the scanned schemas.</td></tr>"
        )
    else:
        lines = []
        for row in matrix.rows:
            tds = [
                f"<td><code>{html.escape(row.qualified_name)}</code></td>",
                f"<td>{row.command}</td>",
            ]
            for cell in row.cells:
                tip = cell.predicate or cell.note
                title = f' title="{html.escape(tip)}"' if tip else ""
                tds.append(
                    f'<td class="v-{cell.verdict}"{title}>'
                    f"{_VERDICT_LABEL[cell.verdict]}</td>"
                )
            lines.append("      <tr>" + "".join(tds) + "</tr>")
        rows_html = "\n".join(lines)

    role_ths = "".join(f"<th>{html.escape(r)}</th>" for r in matrix.roles)
    body = f"""  <table>
    <thead>
      <tr><th>Table</th><th>Command</th>{role_ths}</tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>"""
    if matrix.exposures:
        exp_rows = "\n".join(
            "      <tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in r) + "</tr>"
            for r in _exposure_rows(matrix)
        )
        body += f"""
  <h2>Sensitive columns reachable</h2>
  <table>
    <thead>
      <tr><th>Column</th><th>Role</th><th>Rows</th><th>Via</th></tr>
    </thead>
    <tbody>
{exp_rows}
    </tbody>
  </table>"""
    if matrix.untraced:
        unt_rows = "\n".join(
            "      <tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in r) + "</tr>"
            for r in _untraced_rows(matrix)
        )
        body += f"""
  <h2>{html.escape(_UNTRACED_TITLE)}</h2>
  <table>
    <thead>
      <tr><th>Door</th><th>Owner</th><th>Reached by</th><th>Why</th></tr>
    </thead>
    <tbody>
{unt_rows}
    </tbody>
  </table>"""

    header_extra = (
        f'    <p class="summary"><strong>{s["tables"]}</strong> '
        f'{pluralize(s["tables"], "table")} x '
        f'<strong>{s["roles"]}</strong> {pluralize(s["roles"], "role")}.</p>\n'
        '    <div class="pills">\n'
        f"      {chips_html}\n"
        "    </div>"
    )

    return html_page(
        title="pgrls access matrix",
        heading="Effective access matrix",
        command="pgrls matrix --format html",
        generated_at_iso=html.escape(now),
        extra_css=_MATRIX_CSS,
        header_extra=header_extra,
        body=body,
    )


render, MATRIX_FORMATS = make_dispatcher(
    {
        "text": render_text,
        "json": render_json,
        "markdown": render_markdown,
        "html": render_html,
    }
)
