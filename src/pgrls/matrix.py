"""Effective access matrix for `pgrls matrix`.

`pgrls report` answers "what's each table's RLS posture?"; `pgrls matrix`
answers the audit question **"who can actually access what?"** — a grid of
role x table x command collapsing table GRANTs, the RLS enabled/forced flags,
and the permissive(OR) / restrictive(AND) policy combination into one verdict
per cell:

* ``open``        — the role can access every row (granted, and either RLS is
  off, the role bypasses RLS, or an applicable permissive policy is
  unconditionally true with nothing restrictive narrowing it).
* ``denied``      — no table privilege for that command, or RLS is on with no
  applicable *permissive* policy (Postgres default-denies).
* ``conditional`` — granted and gated by a row predicate (shown): the OR of
  applicable permissive policy clauses, AND-ed with any restrictive ones.

Per command the relevant clause is the one Postgres applies: ``WITH CHECK`` for
INSERT, ``USING`` for SELECT / UPDATE / DELETE. (UPDATE additionally has a
write-side ``WITH CHECK``; v1 shows the read-side ``USING`` — the "who can see
which rows" question.)

Caveats it does not model per-cell (noted in output/docs): a table *owner*
bypasses RLS on a table that is not ``FORCE``d, and a superuser bypasses
everything. "Unconditionally true" is detected lexically (a literal ``true``
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
from pgrls.model import Policy, Schema, Table

Verdict = Literal["open", "denied", "conditional"]

COMMANDS: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")

# Roles always shown even with no grant/policy referencing them — the
# Supabase / PostgREST audit baseline.
_DEFAULT_ROLES = ("PUBLIC", "anon", "authenticated")

_VERDICT_LABEL = {"open": "OPEN", "denied": "DENIED", "conditional": "COND"}

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
class Matrix:
    roles: tuple[str, ...]
    rows: tuple[MatrixRow, ...]

    @property
    def summary(self) -> dict[str, int]:
        counts = {"open": 0, "denied": 0, "conditional": 0}
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


def _role_has_privilege(table: Table, role: str, privilege: str) -> bool:
    """Whether `role` (directly or via PUBLIC) holds `privilege` on `table`.

    Column-level grants count too: a `GRANT SELECT (col) ON t` lets the role
    read rows (of that column), so for the "can this role reach rows" question
    it confers the command. DELETE has no column-level form in Postgres, so
    only table grants apply there — checking column grants for it would be a
    false grant.
    """
    for grant in table.grants:
        if grant.role in (role, "PUBLIC") and privilege in grant.privileges:
            return True
    if privilege != "DELETE":
        for cgrant in table.column_grants:
            if cgrant.role in (role, "PUBLIC") and privilege in cgrant.privileges:
                return True
    return False


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


def _policy_applies(policy: Policy, role: str, command: str) -> bool:
    if policy.command not in ("ALL", command):
        return False
    # A policy with no explicit TO defaults to PUBLIC (applies to everyone).
    if not policy.roles:
        return True
    return role in policy.roles or "PUBLIC" in policy.roles


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


def _cell(table: Table, role: str, command: str, bypass: frozenset[str]) -> Cell:
    if not _role_has_privilege(table, role, command):
        return Cell("denied")
    if role in bypass:
        return Cell("open", note="bypasses RLS")
    if not table.rls_enabled:
        return Cell("open", note="RLS off")

    applicable = [p for p in table.policies if _policy_applies(p, role, command)]
    permissive = [p for p in applicable if p.permissive]
    restrictive = [p for p in applicable if not p.permissive]
    if not permissive:
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

    # Permissive is conditional: effective predicate is (OR permissive) AND restr.
    parts = [f"({' OR '.join(perm)})" if len(perm) > 1 else perm[0]]
    parts.extend(restr)
    return Cell("conditional", predicate=" AND ".join(parts))


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
    bypass = frozenset(b.name for b in schema.bypassrls_roles)
    rows: list[MatrixRow] = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        for command in COMMANDS:
            cells = tuple(
                _cell(table, role, command, bypass) for role in role_list
            )
            rows.append(
                MatrixRow(
                    qualified_name=table.qualified_name,
                    command=command,
                    cells=cells,
                )
            )
    return Matrix(roles=tuple(role_list), rows=tuple(rows))


def _summary_line(matrix: Matrix) -> str:
    s = matrix.summary
    return (
        f"{s['tables']} {pluralize(s['tables'], 'table')} x "
        f"{s['roles']} {pluralize(s['roles'], 'role')}: "
        f"{s['open']} open, {s['conditional']} conditional, {s['denied']} denied."
    )


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
    return "\n".join(
        ["# Access matrix", "", _summary_line(matrix), "", header, sep, *body]
    )


def render_html(matrix: Matrix, *, generated_at: datetime | None = None) -> str:
    generated_at = resolve_generated_at(generated_at, caller_name="render_html")
    now = to_iso_z(generated_at)
    s = matrix.summary

    chips = []
    for verdict in ("open", "conditional", "denied"):
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
