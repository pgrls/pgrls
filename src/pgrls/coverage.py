"""RLS test coverage — which policies a `pgrls.testing` suite exercised.

`pgrls lint` answers "is this policy *wrong*?"; coverage answers "did any
test ever *exercise* this policy?" The `pgrls.testing` pytest plugin
records, per test, the `(schema, relation, role, command)` tuples its
queries touch and writes them to a coverage artifact (`.pgrls-coverage.json`)
on session finish. This module loads that artifact, cross-references it
against an introspected schema, and reports which policies were never
covered. The same matching powers the `pgrls coverage` command and the
HYG004 lint rule — `is_policy_covered` is the single source of truth.

Coverage model (role + command + table): a policy is covered iff a test
queried its table, under a role the policy targets (or PUBLIC), with a
matching command. It under-credits rather than over-credits — role
inheritance is not resolved, and an unqualified relation in test SQL
credits a table by bare name only when that name is unique across the
scanned schemas (a same-named table in another tenant's schema requires
a schema-qualified query to credit). Both are the safe direction: a
missed match prompts a test rather than falsely claiming coverage.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

import pglast
from pglast.ast import MergeStmt, Node, RangeVar
from pglast.enums import CmdType

from pgrls._html_common import html_page, resolve_generated_at, to_iso_z
from pgrls._render_common import (
    make_dispatcher,
    markdown_table,
    pluralize,
    render_text_table,
)
from pgrls.ast_utils import statement_command
from pgrls.formatters._common import safe_location
from pgrls.model import Policy, Schema, Table

_COVERAGE_CSS = """    tr:nth-child(even) td { background: #0d1117; }
    tr:nth-child(odd) td { background: #161b22; }
    code { background: #161b22; }
  }
  header { margin-bottom: 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem 0; }
  .meta { color: #57606a; font-size: .85rem; }
  .summary { margin: 1rem 0 .5rem; }
  .pill { display: inline-block; padding: .15rem .55rem;
           border-radius: 999px; font-size: .85rem;
           border: 1px solid currentColor; }
  .status-covered   { color: #1a7f37; }
  .status-uncovered { color: #cf222e; }
  table { width: 100%; border-collapse: collapse;
           border: 1px solid #d0d7de; }
  thead th { text-align: left; padding: .5rem .75rem;
              background: #f6f8fa; border-bottom: 1px solid #d0d7de;
              font-weight: 600; }
  tbody td { padding: .5rem .75rem; border-bottom: 1px solid #d0d7de; }
  tbody tr:last-child td { border-bottom: 0; }
  td.num { font-variant-numeric: tabular-nums; }
  code { background: #f6f8fa; padding: .1rem .35rem;
          border-radius: 4px; font: .9em ui-monospace, Menlo, monospace; }"""

ARTIFACT_VERSION = 1
DEFAULT_ARTIFACT_PATH = ".pgrls-coverage.json"


@dataclass(frozen=True)
class ExercisedTuple:
    """One (relation, role, command) access a test performed.

    `schema` is None when the test SQL referenced the relation
    without a schema qualifier; matching then falls back to bare
    relation-name comparison.
    """

    schema: str | None
    relation: str
    role: str
    command: str  # SELECT | INSERT | UPDATE | DELETE


@dataclass(frozen=True)
class CoverageData:
    exercised: frozenset[ExercisedTuple]
    generated_at: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CoverageData":
        # Everything that can go wrong with a hand-edited / truncated /
        # wrong-shape artifact is funneled to ValueError so the CLI's
        # load guards turn it into a clean ToolError, never a traceback.
        if not isinstance(payload, dict):
            raise ValueError("coverage artifact must be a JSON object")
        version = payload.get("pgrls_coverage_version")
        if version != ARTIFACT_VERSION:
            raise ValueError(
                f"unsupported coverage artifact version {version!r} "
                f"(expected {ARTIFACT_VERSION})"
            )
        rows = payload.get("exercised") or []
        try:
            exercised = frozenset(
                ExercisedTuple(
                    schema=row.get("schema"),
                    relation=row["relation"],
                    role=row["role"],
                    command=row["command"],
                )
                for row in rows
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"malformed coverage artifact: {exc}") from exc
        return cls(exercised=exercised, generated_at=payload.get("generated_at"))


def load_artifact(path: str) -> CoverageData:
    """Read and validate a coverage artifact JSON file."""
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    return CoverageData.from_dict(payload)


def write_artifact(
    path: str,
    exercised: Iterable[ExercisedTuple],
    *,
    generated_at: datetime,
) -> None:
    """Write the coverage artifact. `generated_at` must be tz-aware."""
    rows = sorted(
        (
            {
                "schema": t.schema,
                "relation": t.relation,
                "role": t.role,
                "command": t.command,
            }
            for t in set(exercised)
        ),
        key=lambda r: (r["schema"] or "", r["relation"], r["role"], r["command"]),
    )
    payload = {
        "pgrls_coverage_version": ARTIFACT_VERSION,
        "generated_at": to_iso_z(generated_at),
        "exercised": rows,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def _own_range_vars(stmt: Any) -> list[tuple[str | None, str]]:
    """RangeVars referenced *directly* by `stmt`, without descending into
    its `WITH` clause (CTE bodies are attributed separately by
    `_collect_accesses`) or its `INTO` target (a `SELECT INTO` creates a
    table, it does not read one). Mirrors `ast_utils.extract_range_vars`'s
    walk but skips those two fields on every node it visits."""
    found: list[tuple[str | None, str]] = []

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                walk(item)
            return
        if isinstance(node, RangeVar):
            relname = getattr(node, "relname", None)
            if isinstance(relname, str) and relname:
                found.append((getattr(node, "schemaname", None), relname))
            return
        if isinstance(node, Node):
            for field_name in node:
                if field_name in ("withClause", "intoClause"):
                    continue
                walk(getattr(node, field_name, None))

    walk(stmt)
    return found


# MERGE WHEN-clause command types that touch an RLS-governed command.
# (CMD_NOTHING — `WHEN ... THEN DO NOTHING` — has no command and is
# omitted.)
_MERGE_CMD_TYPES: dict[Any, str] = {
    CmdType.CMD_INSERT: "INSERT",
    CmdType.CMD_UPDATE: "UPDATE",
    CmdType.CMD_DELETE: "DELETE",
}


def _write_commands(stmt: Any) -> set[str] | None:
    """The RLS write command(s) a statement applies to its target.

    Returns an empty set for a plain SELECT (recognized; every relation
    it touches is a read), a singleton for INSERT/UPDATE/DELETE, the set
    of UPDATE/INSERT/DELETE a MERGE's WHEN clauses perform (MERGE is
    multi-command — a single `statement_command` can't express it, which
    is why a MERGE previously contributed zero coverage and HYG004
    reported an exercised write policy as uncovered), or None when the
    statement carries no RLS command (DDL, SET, …).
    """
    if isinstance(stmt, MergeStmt):
        cmds: set[str] = set()
        for when in getattr(stmt, "mergeWhenClauses", None) or ():
            name = _MERGE_CMD_TYPES.get(getattr(when, "commandType", None))
            if name:
                cmds.add(name)
        return cmds
    base = statement_command(stmt)
    if base is None:
        return None
    return set() if base == "SELECT" else {base}


def _collect_accesses(
    stmt: Any, cte_scope: frozenset[str] = frozenset()
) -> list[tuple[str | None, str, str]]:
    """`(schema, relation, command)` accesses for one statement node.

    Recurses into data-modifying CTEs (`WITH x AS (DELETE/UPDATE/INSERT
    … )`) so the CTE's write target is credited with *its own* command,
    not the outer query's — Postgres applies the write-command policies to
    that table, so crediting it as a `SELECT` read would falsely mark the
    table's SELECT policy covered. CTE names are dropped (they are query
    aliases, not real relations): `cte_scope` carries the names visible
    from enclosing WITH clauses, and a statement's own CTE names are added
    to the scope passed to its bodies — so a sibling reference
    (`WITH a AS (…), b AS (SELECT … FROM a)`) drops `a` too. The
    statement's own write target gets the write command; every other
    directly-referenced relation is a `SELECT` read.
    """
    write_commands = _write_commands(stmt)
    if write_commands is None:
        return []
    out: list[tuple[str | None, str, str]] = []

    own_cte_names: set[str] = set()
    with_clause = getattr(stmt, "withClause", None)
    if with_clause is not None:
        for cte in getattr(with_clause, "ctes", None) or ():
            name = getattr(cte, "ctename", None)
            if isinstance(name, str) and name:
                own_cte_names.add(name)
    # A WITH clause's CTEs can reference each other (and themselves, when
    # RECURSIVE), so every name in this clause — plus any inherited from an
    # enclosing query — is in scope for both this statement's body and its
    # CTE bodies.
    scope = cte_scope | own_cte_names
    if with_clause is not None:
        for cte in getattr(with_clause, "ctes", None) or ():
            out.extend(
                _collect_accesses(getattr(cte, "ctequery", None), scope)
            )

    target_key: tuple[str | None, str] | None = None
    if write_commands:
        target = getattr(stmt, "relation", None)
        target_relname = getattr(target, "relname", None)
        if isinstance(target_relname, str) and target_relname:
            target_key = (getattr(target, "schemaname", None), target_relname)

    for (s, r) in _own_range_vars(stmt):
        # A bare reference to a CTE name is a query alias, not a table.
        if s is None and r in scope:
            continue
        if (s, r) == target_key:
            # Credit the write target with every command it receives —
            # one for INSERT/UPDATE/DELETE, the full set for a MERGE
            # whose WHEN clauses perform several.
            for cmd in sorted(write_commands):
                out.append((s, r, cmd))
        else:
            out.append((s, r, "SELECT"))
    return out


def exercised_from_sql(sql: str) -> list[tuple[str | None, str, str]]:
    """Parse a SQL statement into `(schema, relation, command)` accesses.

    The statement's command credits its *target* relation
    (`INSERT`/`UPDATE`/`DELETE` write target); every other relation it
    references (joins, `FROM`/`USING` sources, sub-selects) is credited
    as a `SELECT` read. A bare `SELECT` credits all referenced relations
    as `SELECT`. Data-modifying CTEs are recursed into so their write
    targets get the write command (not a spurious `SELECT`). Statements
    with no RLS command (DDL, SET, …) yield nothing. Returns `[]` on a
    parse failure — coverage is best-effort and must never break the test
    that issued the SQL.
    """
    try:
        parsed = pglast.parse_sql(sql)
    except pglast.parser.ParseError:
        return []
    out: list[tuple[str | None, str, str]] = []
    for raw in parsed:
        out.extend(_collect_accesses(getattr(raw, "stmt", None)))
    return out


def ambiguous_relation_names(schema: Schema) -> frozenset[str]:
    """Bare table names that occur in more than one scanned schema.

    A coverage tuple whose ``schema is None`` (an unqualified relation in
    the test SQL, resolved through ``search_path`` at run time) cannot
    safely credit a table whose name is shared across schemas. In a
    one-schema-per-tenant layout (``tenant_a.events`` / ``tenant_b.events``)
    a single unqualified ``FROM events`` would otherwise mark *every*
    tenant's same-named policy covered off one test — a false "covered",
    the dangerous direction for a security-coverage tool. Names in this
    set therefore require a schema-qualified match (see
    `is_policy_covered`).
    """
    counts: dict[str, int] = {}
    for table in schema.tables:
        counts[table.name] = counts.get(table.name, 0) + 1
    return frozenset(name for name, count in counts.items() if count > 1)


def is_policy_covered(
    table: Table,
    policy: Policy,
    data: CoverageData,
    *,
    ambiguous_relations: frozenset[str] = frozenset(),
) -> bool:
    """True iff some exercised tuple matches this policy (role+command+table).

    - relation: same name, and same schema when the tuple captured one.
      An unqualified tuple (``schema is None``) matches by bare name —
      *unless* the name is in `ambiguous_relations` (shared across scanned
      schemas), in which case only a schema-qualified tuple matching this
      table's schema counts. This keeps the "never over-credit" guarantee
      in one-schema-per-tenant databases: an unqualified test query can't
      certify a same-named table in another tenant's schema as tested.
    - command: the policy's command equals the exercised command, or the
      policy is `ALL` (which every command exercises);
    - role: the exercised role is one the policy targets, or the policy
      targets `PUBLIC` (which every role exercises).

    Pass `ambiguous_relations=ambiguous_relation_names(schema)` (both
    `build_coverage` and HYG004 do); the default empty set treats every
    name as unambiguous, which is correct for a single-table check.
    """
    name_is_ambiguous = table.name in ambiguous_relations
    for ex in data.exercised:
        if ex.relation != table.name:
            continue
        if ex.schema is None:
            # Unqualified test query: safe to credit only when this bare
            # name unambiguously identifies one table among scanned schemas.
            if name_is_ambiguous:
                continue
        elif ex.schema != table.schema:
            continue
        if not (policy.command == ex.command or policy.command == "ALL"):
            continue
        if ex.role in policy.roles or "PUBLIC" in policy.roles:
            return True
    return False


@dataclass(frozen=True)
class PolicyCoverage:
    schema: str
    table: str
    policy: str
    command: str
    roles: tuple[str, ...]
    covered: bool

    @property
    def location(self) -> str:
        return f"{self.schema}.{self.table}.{self.policy}"


@dataclass(frozen=True)
class CoverageReport:
    policies: tuple[PolicyCoverage, ...]

    @property
    def summary(self) -> dict[str, float | int]:
        total = len(self.policies)
        covered = sum(1 for p in self.policies if p.covered)
        # No policies → nothing to cover → 100% (vacuously). Avoids a
        # division-by-zero and reads as "no gaps" in CI gates.
        pct = 100.0 if total == 0 else round(100.0 * covered / total, 1)
        return {
            "policies": total,
            "covered": covered,
            "uncovered": total - covered,
            "coverage_pct": pct,
        }


def build_coverage(schema: Schema, data: CoverageData) -> CoverageReport:
    """Cross-reference every policy in `schema` against `data`.

    Policies are sorted by (table, policy name) for deterministic output.
    """
    ambiguous = ambiguous_relation_names(schema)
    rows: list[PolicyCoverage] = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        for policy in sorted(table.policies, key=lambda p: p.name):
            rows.append(
                PolicyCoverage(
                    schema=table.schema,
                    table=table.name,
                    policy=policy.name,
                    command=policy.command,
                    roles=policy.roles,
                    covered=is_policy_covered(
                        table, policy, data, ambiguous_relations=ambiguous
                    ),
                )
            )
    return CoverageReport(policies=tuple(rows))


def _summary_line(report: CoverageReport) -> str:
    s = report.summary
    n = s["policies"]
    noun = pluralize(int(n), "policy", "policies")
    return (
        f"{n} {noun}: {s['covered']} covered, "
        f"{s['uncovered']} uncovered ({s['coverage_pct']}%)."
    )


def render_text(report: CoverageReport) -> str:
    if not report.policies:
        return "No policies found in the scanned schemas."
    rows = [
        (
            # `safe_location` keeps the row single-line and the
            # fixed-width columns aligned: a quoted Postgres
            # identifier (location) or role name can legally carry
            # `\n` / `\t` / zero-width chars, which would otherwise
            # split the row. Each role is sanitized before the join
            # so a newline inside one role can't break the cell.
            # No-op on clean identifiers; mirrors the lint/diff text
            # formatters.
            safe_location(p.location),
            p.command,
            ",".join(safe_location(r) for r in p.roles),
            "yes" if p.covered else "no",
        )
        for p in report.policies
    ]
    headers = ("POLICY", "COMMAND", "ROLES", "COVERED")
    out = render_text_table(headers, rows)
    out.append("")
    out.append(_summary_line(report))
    return "\n".join(out)


def render_json(report: CoverageReport) -> str:
    payload = {
        "summary": report.summary,
        "policies": [
            {
                "location": p.location,
                "schema": p.schema,
                "table": p.table,
                "policy": p.policy,
                "command": p.command,
                "roles": list(p.roles),
                "covered": p.covered,
            }
            for p in report.policies
        ],
    }
    return json.dumps(payload, indent=2)


def render_markdown(report: CoverageReport) -> str:
    # `safe_location` neutralizes newlines / zero-width chars; the
    # manual `|` -> `\|` escape stops a pipe inside a quoted Postgres
    # identifier or role name from splitting the cell. Each role is
    # sanitized before the join. All no-ops on well-formed input, so
    # existing output is unchanged. Mirrors the lint/diff markdown
    # cell sanitization.
    body_rows = []
    for p in report.policies:
        location = safe_location(p.location).replace("|", "\\|")
        roles = ",".join(
            safe_location(r).replace("|", "\\|") for r in p.roles
        )
        body_rows.append(
            f"| {location} | {p.command} | {roles} | "
            f"{'yes' if p.covered else 'no'} |"
        )
    return markdown_table(
        heading="# RLS test coverage",
        summary=_summary_line(report),
        header_row="| Policy | Command | Roles | Covered |",
        separator_row="|---|---|---|---|",
        body_rows=body_rows,
    )


def render_html(
    report: CoverageReport,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Standalone HTML coverage page — mirrors `report.render_html`.

    Every user-influenced cell value is `html.escape`-d (Postgres
    identifiers can legally contain markup characters). `generated_at`
    must be timezone-aware; a naive datetime raises `ValueError` rather
    than being coerced through the host's local zone (see
    `pgrls._html_common`). Only the HTML renderer embeds a timestamp.
    """
    generated_at = resolve_generated_at(generated_at, caller_name="render_html")
    now = to_iso_z(generated_at)
    s = report.summary

    if not report.policies:
        rows_html = (
            '<tr><td colspan="4" class="empty">'
            "No policies found in the scanned schemas."
            "</td></tr>"
        )
    else:
        row_lines: list[str] = []
        for p in report.policies:
            state = "covered" if p.covered else "uncovered"
            row_lines.append(
                f'      <tr class="row-{state}">'
                f"<td><code>{html.escape(p.location)}</code></td>"
                f"<td>{html.escape(p.command)}</td>"
                f"<td><code>{html.escape(','.join(p.roles))}</code></td>"
                f'<td class="num"><span class="pill status-{state}">'
                f"{'yes' if p.covered else 'no'}</span></td>"
                "</tr>"
            )
        rows_html = "\n".join(row_lines)

    total = s["policies"]
    noun = pluralize(int(total), "policy", "policies")

    body = f"""  <table>
    <thead>
      <tr>
        <th>Policy</th>
        <th>Command</th>
        <th>Roles</th>
        <th>Covered</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>"""

    return html_page(
        title="pgrls RLS test coverage",
        heading="RLS test coverage",
        command="pgrls coverage --format html",
        generated_at_iso=html.escape(now),
        extra_css=_COVERAGE_CSS,
        header_extra=(
            f'    <p class="summary"><strong>{s["covered"]}</strong> of '
            f"<strong>{total}</strong> {noun} covered ({s['coverage_pct']}%).</p>"
        ),
        body=body,
    )


render, COVERAGE_FORMATS = make_dispatcher({
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
})
