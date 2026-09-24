"""Effective access matrix for `pgrls matrix`.

`pgrls report` answers "what's each table's RLS posture?"; `pgrls matrix`
answers the audit question **"who can actually access what?"** — a grid of
role x table x command collapsing table GRANTs, the RLS enabled/forced flags,
and the permissive(OR) / restrictive(AND) policy combination into one verdict
per cell:

* ``open``        — the role can access every row (it holds the privilege, and
  either RLS is off, the role is exempt — superuser, BYPASSRLS, or holding the
  table owner's privileges on a table that is not ``FORCE``d — or an applicable
  permissive policy is unconditionally true with nothing restrictive narrowing
  it).
* ``denied``      — no privilege for that command, or RLS is on with no
  applicable *permissive* policy (Postgres default-denies).
* ``conditional`` — granted and gated by a row predicate (shown): the OR of
  applicable permissive policy clauses, AND-ed with any restrictive ones.
* ``undecided``   — the role-membership graph was not captured and the answer
  turns on it (a grant the role may inherit, a policy it may fall under).
  Reported instead of ``denied``, which would be a guess in the unsafe
  direction. Live introspection always captures the graph.

Privileges, exemption and policy applicability come from `pgrls.access`, the
engine `verify` uses. So a grant held through an INHERIT membership, ownership
or owner-equivalence, ``pg_read_all_data`` (SELECT) / ``pg_write_all_data``
(writes), and a policy targeting a group the role belongs to all count. The
SELECT column is also widened by doors: a definer view or a SECURITY DEFINER
function the role can open, whose body then runs as its owner. A separate
section lists sensitive columns (SEC045's name patterns) each role can read.

Per command the relevant clause is the one Postgres applies: ``WITH CHECK`` for
INSERT, ``USING`` for SELECT / UPDATE / DELETE. (UPDATE additionally has a
write-side ``WITH CHECK``; v1 shows the read-side ``USING`` — the "who can see
which rows" question.)

Before this engine, cells matched role names literally, and reported DENIED
for a role that read every row in three measured ways: a grant held through a
group, a table it owns without FORCE, a policy TO a group it belongs to.

"Unconditionally true" is detected lexically (a literal ``true``
disjunct), matching the rest of the rule set — ``1=1``-style tautologies that
are not the literal ``true`` show as ``conditional`` (the safe direction: it
under-claims openness, never falsely reports ``open``).
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pgrls._html_common import html_page, resolve_generated_at, to_iso_z
from pgrls._render_common import make_dispatcher, pluralize, render_text_table
from pgrls.ast_utils import flatten_or_disjuncts, is_literal_true, parse_expr
from pgrls.formatters._common import safe_location
from pgrls.access import (
    _applicability,
    _derived_roles,
    _function_doors,
    _merge,
    _privilege_paths,
    _view_doors,
    role_accesses,
)
from pgrls.model import Policy, Role, Schema, Table
from pgrls.verify import _inherit_closure

Verdict = Literal["open", "denied", "conditional", "undecided"]

COMMANDS: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")

# Roles always shown even with no grant/policy referencing them — the
# Supabase / PostgREST audit baseline.
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
class Cell:
    """One role x table x command verdict."""

    verdict: Verdict
    predicate: str | None = None  # shown for "conditional"
    note: str | None = None  # e.g. "RLS off", "bypasses RLS"


@dataclass(frozen=True)
class MatrixRow:
    qualified_name: str
    command: str
    cells: tuple[Cell, ...]  # aligned with Matrix.roles


@dataclass(frozen=True)
class Exposure:
    """A sensitive column (by name, SEC045's patterns) a role can read.

    `verdict` is the widest row reach the role has to the TABLE — never
    ``denied``. It can over-state one column: if the widest path does not
    reach that column (a column grant elsewhere), the column's own reach may be
    narrower. That only ever over-reports, the safe direction for an audit.
    `via` names how, crediting only the paths that reach this column: a grant,
    ownership, a definer view or a SECURITY DEFINER function. A
    column reached through a view is *possibly* reachable: column lineage
    through the view body is not traced, so the base table's sensitive columns
    are reported — over-reporting sensitivity is the safe direction.
    """

    role: str
    table: str
    column: str
    verdict: Verdict
    via: str


@dataclass(frozen=True)
class Matrix:
    roles: tuple[str, ...]
    rows: tuple[MatrixRow, ...]
    exposures: tuple[Exposure, ...] = ()

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


def _collect_roles(schema: Schema, *, include_system: bool) -> tuple[str, ...]:
    roles: set[str] = set(_DEFAULT_ROLES)
    for table in schema.tables:
        for grant in table.grants:
            roles.add(grant.role)
        for cgrant in table.column_grants:
            roles.add(cgrant.role)
        for policy in table.policies:
            roles.update(policy.roles)
    for brole in schema.bypassrls_roles:
        roles.add(brole.name)
    if not include_system:
        roles = {r for r in roles if not _is_system_role(r)} | set(_DEFAULT_ROLES)

    def key(role: str) -> tuple[int, str]:
        order = {"PUBLIC": 0, "anon": 1, "authenticated": 2}
        return (order.get(role, 3), role)

    return tuple(sorted(roles, key=key))


def _resolve_role(
    schema: Schema, name: str
) -> tuple[Role, frozenset[str] | None, frozenset[str], bool]:
    """A role name as ``(Role, privilege closure, policy-applicability set,
    whether that set is complete)``.

    Attributes come from the role catalogue when one was captured, else from
    the names the schema mentions (``_derived_roles``). ``PUBLIC`` is the
    pseudo-role every session is in: it has no memberships of its own, so both
    of its closures are ``{PUBLIC}`` and always complete — even with no
    captured graph.
    """
    if name == "PUBLIC":
        public = frozenset({"PUBLIC"})
        return Role("PUBLIC", False, False, False), public, public, True
    catalogue = schema.roles if schema.roles is not None else _derived_roles(schema)
    attrs = {r.name: r for r in catalogue}
    role = attrs.get(name, Role(name, False, False, False))
    applies_to, complete = _applicability(schema, name)
    return role, _inherit_closure(schema, name), applies_to, complete


def _effective_clause(policy: Policy, command: str) -> str | None:
    """The clause Postgres actually applies for `command` on this policy.

    SELECT/UPDATE/DELETE are gated by USING; INSERT by WITH CHECK. A ``FOR ALL``
    policy with no explicit WITH CHECK reuses its USING expression as the
    implicit WITH CHECK (Postgres semantics), so INSERT falls back to USING for
    an ALL policy. Returns None when the policy imposes no clause for this
    command — for an applicable *permissive* policy that means a missing
    required clause and therefore default-deny, so callers treat None as
    non-granting, never as "open" (e.g. a ``FOR SELECT`` policy with no USING
    denies, and a non-ALL ``FOR INSERT`` policy with no WITH CHECK denies).
    """
    if command == "INSERT":
        if policy.with_check_sql is not None:
            return policy.with_check_sql
        return policy.using_sql if policy.command == "ALL" else None
    return policy.using_sql


def _policy_applies(
    policy: Policy, command: str, applies_to: frozenset[str], complete: bool
) -> bool | None:
    """Whether `policy` applies to a session whose role reaches `applies_to`.

    Postgres applies a policy ``TO R`` to a session that holds ``R``'s
    privileges — ``R`` itself or an INHERIT member, the same rule as a grant
    (``has_privs_of_role``). Matching the role name literally missed that:
    measured, a ``TO grp`` policy reported an INHERIT member as DENIED while it
    read every row. A NOINHERIT member is bound by neither a permissive nor a
    restrictive ``TO grp`` policy (measured on PG15-17).
    ``None`` = undecidable (the membership graph was not captured and the
    policy names a role outside what we can see).
    """
    if policy.command not in ("ALL", command):
        return False
    # A policy with no explicit TO defaults to PUBLIC (applies to everyone).
    roles = set(policy.roles) or {"PUBLIC"}
    if roles & applies_to:
        return True
    return None if not complete else False


def _clause_is_open(clause: str) -> bool:
    """Whether a present, non-empty clause imposes no restriction — a literal
    ``true`` somewhere in its top-level OR. Callers pass only non-empty clauses;
    an absent clause is handled upstream as default-deny, not as openness."""
    node = parse_expr(clause)
    if node is None:
        return False
    return any(is_literal_true(d) for d in flatten_or_disjuncts(node))


def _narrowing_restrictive(restrictive: list[Policy], command: str) -> list[str]:
    """Restrictive clauses that actually narrow rows.

    A restrictive policy whose clause is unconditionally true (``USING(true)``)
    is a no-op floor — it imposes no condition (pgrls flags it as SEC031). Such
    clauses are dropped so an all-true floor collapses to OPEN rather than a
    misleading ``conditional`` with a ``true`` predicate, and a mixed floor
    (``true`` AND a real predicate) shows only the predicate that matters.
    """
    return [
        c
        for p in restrictive
        if (c := _effective_clause(p, command)) and not _clause_is_open(c)
    ]


def _cell(
    schema: Schema,
    table: Table,
    role: Role,
    command: str,
    closure: frozenset[str] | None,
    applies_to: frozenset[str],
    complete: bool,
) -> Cell:
    """One role x table x command verdict.

    Privilege, exemption and policy applicability come from the same engine
    `verify` uses (via `pgrls.access`), rather than a literal role-name match.
    Measured on PG16, the literal match reported DENIED for a role that read
    every row in three ways: a grant held through an INHERIT membership, a
    table the role owns without FORCE, and a policy TO a group it belongs to.
    """
    paths, known = _privilege_paths(schema, role, table, closure, command)
    if not paths:
        if not known:
            return Cell(
                "undecided",
                note="role-membership graph not captured; a grant to a role "
                "this one inherits cannot be ruled out",
            )
        return Cell("denied")
    if role.superuser:
        return Cell("open", note="superuser")
    if role.bypassrls:
        return Cell("open", note="bypasses RLS")
    if not table.rls_enabled:
        return Cell("open", note="RLS off")
    if (
        any(p.kind in ("owner", "owner_member") for p in paths)
        and not table.force_rls
    ):
        return Cell("open", note="owner; RLS not FORCE'd")

    verdicts = {p.name: _policy_applies(p, command, applies_to, complete)
                for p in table.policies}
    applicable = [p for p in table.policies if verdicts[p.name] is True]
    # An undecidable PERMISSIVE policy might grant rows, so it can only widen;
    # an undecidable RESTRICTIVE one might narrow, so it is left out rather
    # than let it turn a true OPEN into COND. Both lean toward over-reporting
    # access, which is the safe direction for an audit.
    unknown_permissive = [
        p for p in table.policies if verdicts[p.name] is None and p.permissive
    ]
    permissive = [p for p in applicable if p.permissive]
    restrictive = [p for p in applicable if not p.permissive]
    if not permissive:
        if unknown_permissive:
            return Cell(
                "undecided",
                note="role-membership graph not captured; cannot tell whether "
                + ", ".join(sorted(p.name for p in unknown_permissive))
                + " apply",
            )
        return Cell("denied", note="no permissive policy")

    # A permissive policy admits rows only through the clause Postgres applies
    # for this command; a missing required clause is default-deny, so it does
    # not contribute openness.
    perm = [c for p in permissive if (c := _effective_clause(p, command))]
    if not perm:
        return Cell("denied", note="no applicable permissive clause")

    restr = _narrowing_restrictive(restrictive, command)
    # A permissive clause that is unconditionally true admits every row.
    if any(_clause_is_open(c) for c in perm):
        # Open unless a restrictive floor actually narrows rows.
        return Cell("conditional", predicate=" AND ".join(restr)) if restr else Cell("open")
    if unknown_permissive:
        # A known conditional read, plus policies that might widen it.
        return Cell(
            "undecided",
            note="role-membership graph not captured; "
            + ", ".join(sorted(p.name for p in unknown_permissive))
            + " may also apply",
        )

    # Permissive is conditional: effective predicate is (OR permissive) AND restr.
    parts = [f"({' OR '.join(perm)})" if len(perm) > 1 else perm[0]]
    parts.extend(restr)
    return Cell("conditional", predicate=" AND ".join(parts))


# Widest-first, as in `pgrls.access`: `undecided` outranks `conditional` so a
# known partial read never masks a door that cannot be bounded.
_RANK: dict[str, int] = {"open": 3, "undecided": 2, "conditional": 1, "denied": 0}
_ROWS_TO_VERDICT: dict[str, Verdict] = {
    "all": "open", "filtered": "conditional", "none": "denied", "undecided": "undecided",
}


def _door_cells(
    schema: Schema, role: Role, closure: frozenset[str] | None
) -> dict[str, Cell]:
    """SELECT verdicts reached through a definer view or a SECURITY DEFINER
    function, keyed by table. A door runs as its OWNER, so the rows are the
    owner's row reach — the predicate shown on a direct cell would describe the
    wrong role here, so a door cell carries a note instead."""
    catalogue = schema.roles if schema.roles is not None else _derived_roles(schema)
    attrs = {r.name: r for r in catalogue}
    reaches = _view_doors(schema, role, closure, attrs)
    fn_reach, _ = _function_doors(schema, role, closure, attrs)
    for qname, rs in fn_reach.items():
        reaches.setdefault(qname, []).extend(rs)
    out: dict[str, Cell] = {}
    for qname, rs in reaches.items():
        _, _, rows, pols, reason = _merge(rs)
        note = reason or "through a door"
        if rows == "filtered" and pols:
            note += f" — filtered by {', '.join(pols)}"
        out[qname] = Cell(_ROWS_TO_VERDICT[rows], note=note)
    return out


def build_matrix(
    schema: Schema,
    *,
    roles: tuple[str, ...] | None = None,
    include_system: bool = False,
) -> Matrix:
    """Build the effective access matrix from an introspected `schema`.

    `roles` overrides role discovery (else: the defaults plus every role
    referenced by a grant/policy, minus `pg_*` system roles unless
    `include_system`). Rows are sorted by (table, command) for determinism.
    """
    role_list = roles if roles is not None else _collect_roles(
        schema, include_system=include_system
    )
    resolved = {name: _resolve_role(schema, name) for name in role_list}
    doors = {
        name: _door_cells(schema, resolved[name][0], resolved[name][1])
        for name in role_list
    }
    rows: list[MatrixRow] = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        for command in COMMANDS:
            cells_list = []
            for name in role_list:
                cell = _cell(schema, table, resolved[name][0], command, *resolved[name][1:])
                # Doors are read paths: they can widen a SELECT cell, never
                # narrow it, and never touch a write command.
                door = doors[name].get(table.qualified_name) if command == "SELECT" else None
                if door is not None and _RANK[door.verdict] > _RANK[cell.verdict]:
                    cell = door
                cells_list.append(cell)
            cells = tuple(cells_list)
            rows.append(
                MatrixRow(
                    qualified_name=table.qualified_name,
                    command=command,
                    cells=cells,
                )
            )
    return Matrix(
        roles=tuple(role_list),
        rows=tuple(rows),
        exposures=_exposures(schema, role_list, resolved),
    )


def _via(paths: tuple[object, ...], principal: str, column: str) -> str:
    """The paths that reach `column` specifically. A column grant covers only
    its own columns, so crediting it for every sensitive column on the table
    misstated how a column was reached — measured: `ssn`, reachable only
    through a definer view, was listed as reached via a column grant on
    `email`. A path with no column list (a table grant, a view, a function)
    reaches every column."""
    labels = []
    for p in paths:
        cols = getattr(p, "columns", None)
        if cols is not None and column not in cols:
            continue
        kind, via = getattr(p, "kind", ""), getattr(p, "via", None)
        if kind == "view":
            labels.append(f"view {via}")
        elif kind == "function":
            labels.append(f"SECURITY DEFINER {via}")
        elif kind in ("grant", "column_grant", "owner_member", "pg_read_all_data") and via:
            label = kind.replace("_", " ")
            labels.append(label if via == principal else f"{label} via {via}")
        else:
            labels.append(kind.replace("_", " "))
    return "; ".join(dict.fromkeys(labels)) or "-"


def _exposures(
    schema: Schema,
    role_list: tuple[str, ...],
    resolved: dict[str, tuple[Role, frozenset[str] | None, frozenset[str], bool]],
) -> tuple[Exposure, ...]:
    """Every sensitive column each shown role can read with at least some
    rows, from the same engine that decides the cells."""
    catalogue = schema.roles if schema.roles is not None else _derived_roles(schema)
    attrs = {r.name: r for r in catalogue}
    out: list[Exposure] = []
    for name in role_list:
        role, closure = resolved[name][0], resolved[name][1]
        accesses, _ = role_accesses(schema, role, closure, attrs)
        for a in accesses:
            if a.rows == "none":
                continue
            for col in a.sensitive:
                out.append(Exposure(
                    role=name,
                    table=a.relation,
                    column=col,
                    verdict=_ROWS_TO_VERDICT[a.rows],
                    via=_via(a.paths, name, col),
                ))
    return tuple(sorted(out, key=lambda e: (e.table, e.column, e.role)))


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


def render_text(matrix: Matrix) -> str:
    if not matrix.rows:
        return "No tables found in the scanned schemas."
    head: list[str] = []
    if matrix.exposures:
        head = ["Sensitive columns reachable:"]
        head.extend("  " + ln for ln in render_text_table(
            ("COLUMN", "ROLE", "ROWS", "VIA"), _exposure_rows(matrix)
        ))
        head.append("")
    headers = ("TABLE", "CMD", *(safe_location(r) for r in matrix.roles))
    rows = [
        (
            safe_location(row.qualified_name),
            row.command,
            *(_VERDICT_LABEL[c.verdict] for c in row.cells),
        )
        for row in matrix.rows
    ]
    out = head + render_text_table(headers, rows)
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
