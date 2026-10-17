"""Isolation proofs for `pgrls matrix --prove`.

The matrix says which rows a role *reaches*; this module asks whether that
reach is *safe*, cell by cell, with the same Z3 provers `pgrls verify` uses —
SELECT only:

* an **anonymous** column (the anon roles and ``PUBLIC``) gets the anon
  threat model: can an unauthenticated session read any row?
* every **other** column gets the cross-tenant model: can a session of that
  role read a row belonging to another tenant?

Each cell ends up ``proven``, ``leak`` (with the leaking row when one
characterizes it), ``possible``, ``unknown`` or ``exempt``. The rules that keep
the verdicts honest:

* **proven** only when the prover proves it and no door could change the
  answer — the predicate is the role's own, or it cannot depend on who
  evaluates it (`pgrls.access._dependence`): a door evaluates the filter as
  its owner, and a filter that reads ``current_user`` or another table can
  admit different rows there.
* **leak** only when the role's *own* session reads the row. A door is
  credited with its owner's whole reach of the table — a view's own ``WHERE``
  and what a function returns are not traced — so a leak that exists only
  through a door is ``possible``: it may be filtered on the way out.
* everything the prover cannot decide is ``unknown``, with the reason.
* a superuser or ``BYPASSRLS`` column outside the anonymous set is
  ``exempt``: it skips RLS by design (SEC016 is the place to question that).
  An anonymous role that bypasses RLS is the worst leak there is, so the
  anonymous columns are never exempt.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pgrls.access import Cell, RoleReach, _dependence
from pgrls.ast_utils import parse_expr
from pgrls.model import Role, Schema, Table

ProofStatus = Literal["proven", "leak", "possible", "unknown", "exempt"]
ThreatModel = Literal["anon", "cross-tenant"]

PROOF_STATUSES: tuple[ProofStatus, ...] = ("proven", "leak", "possible", "unknown", "exempt")


@dataclass(frozen=True)
class CellProof:
    """The isolation verdict for one role x table SELECT cell.

    `witness` is the counterexample for ``leak`` / ``possible``: a row that
    characterizes the leak, ``{}`` for "every row", or ``None`` when no single
    row does (a conditional leak). `detail` says why: the reason a cell is
    ``unknown``, the door behind a ``possible``, the source of a ``leak``.
    """

    status: ProofStatus
    model: ThreatModel
    witness: dict[str, object] | None = None
    detail: str | None = None


class _Provers:
    """The two provers, configured once and cached by predicate: most cells
    share a handful of filters across roles."""

    def __init__(
        self,
        schema: Schema,
        *,
        anon_roles: set[str] | None,
        auth_functions: set[str] | None,
        identity_columns: frozenset[str] | None,
    ) -> None:
        from pgrls.verify import _anon_set_gucs  # noqa: PLC0415

        self.auth = auth_functions
        self.identity_columns = identity_columns
        self.set_gucs = _anon_set_gucs(schema, anon_roles)
        self.cache: dict[tuple[ThreatModel, str], tuple[str, dict[str, object] | None]] = {}

    def prove(self, model: ThreatModel, predicate: str) -> tuple[str, dict[str, object] | None]:
        key = (model, predicate)
        if key not in self.cache:
            self.cache[key] = self._prove(model, predicate)
        return self.cache[key]

    def _prove(self, model: ThreatModel, predicate: str) -> tuple[str, dict[str, object] | None]:
        from pgrls.diff._z3_compare import (  # noqa: PLC0415
            prove_anon_isolation,
            prove_cross_tenant_isolation,
        )

        node = parse_expr(predicate)
        if node is None:
            return "unparseable", None
        try:
            if model == "anon":
                return prove_anon_isolation(node, self.auth, set_gucs=self.set_gucs)
            return prove_cross_tenant_isolation(
                node, self.auth, identity_columns=self.identity_columns
            )
        except RecursionError:
            return "unverified", None


def _identity_axis(identity_columns: frozenset[str] | None) -> frozenset[str]:
    if identity_columns is not None:
        return identity_columns
    from pgrls.rules.sec021 import AXIS_IDENTITY_COLUMNS  # noqa: PLC0415

    return AXIS_IDENTITY_COLUMNS


def prove_cell(
    *,
    model: ThreatModel,
    role: Role | None,
    table: Table,
    cell: Cell,
    direct: Cell,
    has_doors: bool,
    provers: _Provers,
    axis: frozenset[str],
) -> CellProof:
    """The proof for one SELECT cell. `cell` is the role's merged verdict,
    `direct` its own session's verdict before any door, `has_doors` whether
    any door reaches the table's rows for this role."""
    if cell.verdict == "denied":
        return CellProof("proven", model, detail="no row reachable")
    if model == "cross-tenant" and role is not None and (role.superuser or role.bypassrls):
        return CellProof("exempt", model, detail=(
            "superuser" if role.superuser else "BYPASSRLS"
        ) + " — skips RLS by design")
    if cell.verdict == "undecided":
        return CellProof("unknown", model, detail=cell.note or "rows cannot be bounded")
    if cell.verdict == "open":
        own = direct.verdict == "open"
        if model == "cross-tenant" and not (set(table.columns) & axis):
            # No tenant discriminator: shared data, or a column the project
            # has not named in [lint.rules.SEC021].identity_columns.
            return CellProof("unknown", model, detail=(
                "reads every row, but the table has no tenant column to "
                "isolate on (see [lint.rules.SEC021].identity_columns)"
            ))
        return CellProof(
            "leak" if own else "possible", model, witness={},
            detail=cell.note if own else _door_detail(cell),
        )

    # conditional: one filter, shared by every path that reaches rows
    predicate = cell.predicate or ""
    own = direct.verdict == "conditional" and direct.predicate == cell.predicate
    if has_doors and _dependence(predicate) != (False, False):
        return CellProof("unknown", model, detail=(
            "the filter reads current_user, a privilege check or another "
            "table, and a door evaluates it as its owner — the rows can differ"
        ))
    verdict, witness = provers.prove(model, predicate)
    if verdict == "isolated":
        return CellProof("proven", model)
    if verdict == "leak":
        return CellProof(
            "leak" if own else "possible", model, witness=witness,
            detail=None if own else _door_detail(cell),
        )
    if verdict == "unparseable":
        return CellProof("unknown", model, detail="the filter does not parse")
    from pgrls.verify import _UNVERIFIED_PREDICATE_REASON  # noqa: PLC0415

    return CellProof("unknown", model, detail=_UNVERIFIED_PREDICATE_REASON[model])


def _door_detail(cell: Cell) -> str:
    """The door behind a POSSIBLE: a door is credited with its owner's whole
    reach of the table, and what it actually returns is not traced."""
    return cell.note or "through a door"


def prove_matrix(
    schema: Schema,
    tables: list[Table],
    roles: tuple[str, ...],
    reaches: dict[str, RoleReach],
    attrs: dict[str, Role],
    *,
    anon_roles: set[str] | None = None,
    auth_functions: set[str] | None = None,
    identity_columns: frozenset[str] | None = None,
) -> dict[tuple[str, str], CellProof]:
    """A proof for every (table, role) SELECT cell of the grid."""
    anon_set = (anon_roles if anon_roles else {"anon"}) | {"PUBLIC"}
    provers = _Provers(
        schema, anon_roles=anon_set, auth_functions=auth_functions,
        identity_columns=identity_columns,
    )
    axis = _identity_axis(identity_columns)
    out: dict[tuple[str, str], CellProof] = {}
    for name in roles:
        reach = reaches[name]
        model: ThreatModel = "anon" if name in anon_set else "cross-tenant"
        for table in tables:
            q = table.qualified_name
            direct, _ = reach.direct_select[q]
            out[(q, name)] = prove_cell(
                model=model,
                role=attrs.get(name),
                table=table,
                cell=reach.cells[(q, "SELECT")],
                direct=direct,
                has_doors=bool(reach.door_paths.get(q)),
                provers=provers,
                axis=axis,
            )
    return out


def proof_summary(proofs: Any) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(PROOF_STATUSES, 0)
    for p in proofs:
        if p is not None:
            counts[p.status] += 1
    return counts
