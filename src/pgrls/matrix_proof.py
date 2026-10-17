"""Isolation proofs for `pgrls matrix --prove`.

The matrix says which rows a role *reaches*; this module asks whether that
reach is *safe*, cell by cell, with the same Z3 provers `pgrls verify` uses —
SELECT only:

* an **anonymous** column (the anon roles and ``PUBLIC``) gets the anon
  threat model: can a session with no JWT read any row?
* every **other** column gets the cross-tenant model: can a session of that
  role, carrying its tenant identity, read a row of another tenant?

Each cell ends up ``proven``, ``leak`` (with the leaking row when one
characterizes it), ``possible``, ``unknown`` or ``exempt``. The rules that keep
the verdicts honest:

* **leak** only when the role's *own* session reads such a row: the role's
  direct read is proven to leak (or reads every row), or a partition /
  inheritance parent it queries itself returns every row. A parent whose
  filter leaks makes the child only a possible leak: the filter was written
  for every partition, so the leaking row may not be the child's. A role
  without USAGE on the
  table's schema cannot query the table by name, so its direct read is only
  a possible leak — a view or a pre-parsed function body skips that check.
* **possible** when the read exists only through a door: a door is credited
  with its owner's whole reach of the table — a view's own ``WHERE`` and what
  a function returns are not traced — so it may filter the row out.
* **proven** only when no such read is possible — the role reaches no row, or
  the prover shows the filter isolates — and nothing pgrls cannot see could
  change that: no door evaluates a filter that depends on who runs it
  (`pgrls.access._dependence`); no untraced door the role can open belongs to
  an owner that reaches the table, itself or through untraced doors of its
  own; the role owns neither the table (it can lift ``FORCE`` or rewrite a
  policy in one statement) nor a function the filter calls (it can redefine
  it); a filter scoped by a setting
  (``current_setting``) also isolates a session that leaves it unset, and —
  for a role that can log in — one that connects with no JWT; and every role
  the session can ``SET ROLE`` to is proven too.
* **unknown** for everything else, with the reason.
* **exempt** for a superuser or ``BYPASSRLS`` column outside the anonymous
  set: it skips RLS by design (SEC016 is the place to question that). An
  anonymous role that bypasses RLS is the worst leak there is, so anonymous
  columns are never exempt.

The cross-tenant model assumes a session carries its identity
(``auth.uid()`` is the session's user) — checked without one for a role that
can log in, assumed for a NOLOGIN role reached through a login role that sets
the JWT (Supabase's ``authenticated``). It also assumes the role can execute
the functions a policy calls, as `pgrls verify` does.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from pgrls.access import RoleReach, _dependence
from pgrls.ast_utils import parse_expr
from pgrls.model import Role, Schema, Table

ProofStatus = Literal["proven", "leak", "possible", "unknown", "exempt"]
ThreatModel = Literal["anon", "cross-tenant"]

PROOF_STATUSES: tuple[ProofStatus, ...] = ("proven", "leak", "possible", "unknown", "exempt")
_MODELS: tuple[ThreatModel, ...] = ("anon", "cross-tenant")

_ALL_DATA_ROLES = frozenset({"pg_read_all_data", "pg_write_all_data"})

_GucStates = tuple[dict[str, str | None], ...]
_StatesKey = tuple[tuple[tuple[str, str | None], ...], ...]


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


def _states_key(states: _GucStates) -> _StatesKey:
    return tuple(tuple(sorted(s.items())) for s in states)


def _has_node(predicate: str, match: Callable[[Any], bool]) -> bool:
    """Whether any node of `predicate`'s AST satisfies `match` — `True` when it
    does not parse or is too deep to walk."""
    from pglast.ast import Node  # noqa: PLC0415

    node = parse_expr(predicate)
    if node is None:
        return True
    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if match(n):
            found = True
            return
        if isinstance(n, Node):
            for fld in n:
                walk(getattr(n, fld, None))

    try:
        walk(node)
    except RecursionError:
        return True
    return found


def _calls_current_setting(predicate: str) -> bool:
    """Whether `predicate` reads a setting with the built-in
    ``current_setting`` (a tenant carried in a GUC, not a JWT)."""
    from pglast.ast import FuncCall  # noqa: PLC0415

    from pgrls.verify import _bare_builtin_name  # noqa: PLC0415

    return _has_node(predicate, lambda n: isinstance(n, FuncCall)
                     and _bare_builtin_name(n) == "current_setting")


def _called_functions(predicate: str) -> set[str]:
    """The names of the functions `predicate` calls, as written (qualified
    or bare)."""
    from pglast.ast import FuncCall  # noqa: PLC0415

    names: set[str] = set()

    def match(n: Any) -> bool:
        if isinstance(n, FuncCall):
            names.add(".".join(getattr(part, "sval", "") for part in n.funcname))
        return False

    _has_node(predicate, match)
    return names


def _has_subselect(predicate: str) -> bool:
    from pglast.ast import SubLink  # noqa: PLC0415

    return _has_node(predicate, lambda n: isinstance(n, SubLink))


class _Prover:
    """Everything one `prove_matrix` call shares: the provers (cached by
    predicate and session state), each role's reach, and the session states."""

    def __init__(
        self,
        schema: Schema,
        reach_of: Callable[[str], RoleReach],
        attrs: dict[str, Role],
        *,
        anon_set: frozenset[str],
        auth_functions: set[str] | None,
        identity_columns: frozenset[str] | None,
    ) -> None:
        from pgrls.rules.sec021 import AXIS_IDENTITY_COLUMNS  # noqa: PLC0415

        self.schema = schema
        self.tables = {t.qualified_name: t for t in schema.tables}
        self.reach_of = reach_of
        self.attrs = attrs
        self.anon_set = anon_set
        self.auth = auth_functions
        self.identity_columns = identity_columns
        self.axis = identity_columns if identity_columns is not None else AXIS_IDENTITY_COLUMNS
        self.cache: dict[Any, tuple[str, dict[str, object] | None]] = {}
        self.states_cache: dict[str, _GucStates] = {}
        self.base_cache: dict[Any, CellProof] = {}
        self.usage: dict[str, frozenset[str]] | None = None
        # function name — qualified and bare — -> its owners
        self.fn_owners: dict[str, set[str]] = {}
        for qname, owner in schema.function_owners or ():
            for key in (qname, qname.rsplit(".", 1)[-1]):
                self.fn_owners.setdefault(key, set()).add(owner)
        if schema.schema_usage is not None:
            usage: dict[str, set[str]] = {}
            for s, grantee in schema.schema_usage:
                usage.setdefault(s, set()).add(grantee)
            self.usage = {s: frozenset(g) for s, g in usage.items()}

    # --- inputs -------------------------------------------------------------

    def model(self, name: str) -> ThreatModel:
        return "anon" if name in self.anon_set else "cross-tenant"

    def states(self, name: str) -> _GucStates:
        """The setting states a session of column `name` can be in: one per
        login path. PUBLIC is every session, so every login role's."""
        if name not in self.states_cache:
            from pgrls.verify import _anon_set_gucs  # noqa: PLC0415

            if name == "PUBLIC":
                if self.schema.roles is not None:
                    logins = {r.name for r in self.schema.roles if r.can_login}
                else:
                    logins = {r for r, _, _ in self.schema.role_set_gucs}
                seed = logins or {"anon"}
            else:
                seed = {name}
            self.states_cache[name] = _anon_set_gucs(self.schema, seed)
        return self.states_cache[name]

    def has_usage(self, name: str, table: Table) -> bool:
        """Whether `name` holds USAGE on the table's schema — `True` when that
        was not captured."""
        if self.usage is None or table.schema not in self.usage:
            return True
        role = self.attrs.get(name)
        if role is not None and role.superuser:
            return True
        holders = self.usage[table.schema]
        if "PUBLIC" in holders:
            return True
        if name == "PUBLIC":
            return False
        from pgrls.verify import _inherit_closure  # noqa: PLC0415

        closure = _inherit_closure(self.schema, name)
        if closure is None:
            return True
        # pg_read_all_data / pg_write_all_data carry USAGE on every schema
        # without appearing in any schema's ACL.
        return bool((holders | _ALL_DATA_ROLES) & (closure | {name}))

    # --- provers ------------------------------------------------------------

    def prove(
        self, model: ThreatModel, predicate: str, states: _GucStates,
    ) -> tuple[str, dict[str, object] | None]:
        key = (model, predicate, _states_key(states) if model == "anon" else None)
        if key not in self.cache:
            self.cache[key] = self._prove(model, predicate, states)
        return self.cache[key]

    def _prove(
        self, model: ThreatModel, predicate: str, states: _GucStates,
    ) -> tuple[str, dict[str, object] | None]:
        from pgrls.diff._z3_compare import (  # noqa: PLC0415
            prove_anon_isolation,
            prove_cross_tenant_isolation,
        )

        node = parse_expr(predicate)
        if node is None:
            return "unparseable", None
        try:
            if model == "anon":
                return prove_anon_isolation(node, self.auth, set_gucs=states)
            return prove_cross_tenant_isolation(
                node, self.auth, identity_columns=self.identity_columns
            )
        except RecursionError:
            return "unverified", None

    # --- one cell -------------------------------------------------------------

    def cell(self, name: str, table: Table) -> CellProof:
        """The proof for column `name`'s SELECT on `table`, including the
        roles its session can SET ROLE to."""
        model = self.model(name)
        states = self.states(name)
        # A login role's session can arrive with no JWT at all; a NOLOGIN one
        # (authenticated) only through whoever logs in and switches to it.
        role = self.attrs.get(name)
        login = name != "PUBLIC" and (role is None or role.can_login)
        base = self.base(name, table, model, states, login)
        if base.status != "proven" or name == "PUBLIC":
            return base
        targets = self.set_role_targets(name)
        if targets is None:
            return CellProof("unknown", model, detail=(
                "role-membership graph not captured — cannot rule out a SET ROLE "
                "to a role that reads it"
            ))
        for target in sorted(targets):
            other = self.base(target, table, model, states, login)
            if other.status != "proven":
                return CellProof("unknown", model, detail=(
                    f"the session can SET ROLE {target}, whose read is "
                    f"{other.status.upper()}"
                ))
        return base

    def set_role_targets(self, name: str) -> set[str] | None:
        """Every role `name` can switch to with SET ROLE: the roles it is a
        member of, directly or through other memberships. Whether a grant
        carries the SET option is not captured, so every edge counts."""
        edges = self.schema.role_memberships
        if edges is None:
            return None
        out: set[str] = set()
        todo = [name]
        while todo:
            current = todo.pop()
            for e in edges:
                if e.member == current and e.role not in out and e.role != name:
                    out.add(e.role)
                    todo.append(e.role)
        return out

    def base(
        self, name: str, table: Table, model: ThreatModel, states: _GucStates,
        login: bool = False,
    ) -> CellProof:
        """`name`'s own read of `table`, in a session with `states` that
        logged in as itself (`login`) or as a role that switched to it."""
        key = (name, table.qualified_name, model, _states_key(states), login)
        if key not in self.base_cache:
            self.base_cache[key] = self._base(name, table, model, states, login)
        return self.base_cache[key]

    def _base(
        self, name: str, table: Table, model: ThreatModel, states: _GucStates,
        login: bool,
    ) -> CellProof:
        reach = self.reach_of(name)
        q = table.qualified_name
        cell = reach.cells[(q, "SELECT")]
        direct, _ = reach.direct_select[q]
        doors = reach.door_paths.get(q, ())
        # Without USAGE on the schema the role's own query fails ("permission
        # denied for schema"), but a stored query — a view, a function with a
        # pre-parsed body — does not look the name up again (measured: an
        # invoker view returned the rows). So missing USAGE turns the role's
        # own leak into a possible one; it never makes a cell PROVEN.
        usage = self.has_usage(name, table)
        role = self.attrs.get(name)

        if cell.verdict == "denied":
            return self.gates(name, table, model, states, login, None,
                              CellProof("proven", model, detail="no row reachable"))
        if model == "cross-tenant" and role is not None and (role.superuser or role.bypassrls):
            return CellProof("exempt", model, detail=(
                "superuser" if role.superuser else "BYPASSRLS"
            ) + " — skips RLS by design")
        if cell.verdict == "undecided":
            return CellProof("unknown", model, detail=cell.note or "rows cannot be bounded")
        shared = model == "cross-tenant" and not (set(table.columns) & self.axis)
        no_usage = (
            f"no USAGE on schema {table.schema}, so not by querying the table "
            "itself; a view or a function with a pre-parsed body that reads it "
            "still can"
        )

        # Every ancestor of a partition / inheritance child is a door of its
        # own, so each level is judged on the role's own query of it.
        parents_only = bool(doors) and all(
            p.kind == "parent" and self._parent_is_own(name, p.via) for p in doors
        )
        parent_leak = None if shared else self._parent_leak(name, reach, doors, model, states)

        # The role's own read first: a leak there is certain whatever a door adds.
        if direct.verdict == "open":
            if shared:
                return self._shared(model)
            if usage:
                return CellProof("leak", model, witness={}, detail=direct.note)
            return parent_leak or CellProof("possible", model, witness={}, detail=no_usage)
        if direct.verdict == "conditional":
            verdict, witness = self.prove(model, direct.predicate or "", states)
            if verdict == "leak":
                if usage:
                    return CellProof("leak", model, witness=witness)
                return parent_leak or CellProof(
                    "possible", model, witness=witness, detail=no_usage)
        if parent_leak is not None:
            return parent_leak
        if cell.verdict == "open":
            if shared:
                return self._shared(model)
            return CellProof("possible", model, witness={}, detail=cell.note)

        # conditional: one filter, shared by every path that reaches rows
        predicate = cell.predicate or ""
        if doors and not parents_only and _dependence(predicate) != (False, False):
            return CellProof("unknown", model, detail=(
                "the filter reads current_user, a privilege check or another "
                "table, and a door evaluates it as its owner — the rows can differ"
            ))
        verdict, witness = self.prove(model, predicate, states)
        if verdict == "isolated":
            return self.gates(name, table, model, states, login, predicate,
                              CellProof("proven", model))
        if verdict == "leak":
            # Through a door — or a parent, whose filter was written for every
            # partition: the leaking row may lie outside this one's bounds.
            return CellProof("possible", model, witness=witness, detail=cell.note)
        if verdict == "unparseable":
            return CellProof("unknown", model, detail="the filter does not parse")
        from pgrls.verify import _UNVERIFIED_PREDICATE_REASON  # noqa: PLC0415

        # Not a missing identity column: the filter is outside what the
        # prover decides.
        if _has_subselect(predicate):
            return CellProof("unknown", model, detail=(
                "the filter reads another table (a sub-select), which the prover "
                "cannot decide"
            ))
        if _dependence(predicate)[1]:
            return CellProof("unknown", model, detail=(
                "the filter calls a function the prover cannot see into — if it is "
                "your auth helper, name it with --auth-function"
            ))
        return CellProof("unknown", model, detail=_UNVERIFIED_PREDICATE_REASON[model])

    def _parent_leak(
        self, name: str, reach: RoleReach, doors: tuple[Any, ...], model: ThreatModel,
        states: _GucStates,
    ) -> CellProof | None:
        """A parent the role queries itself — USAGE on its schema, a direct read
        of it — that returns every row returns this child's rows too: RLS off,
        or a filter proven to admit every row. Any other leaking filter is left
        to the door logic: it was written for every partition, so the leaking
        row may not be this child's."""
        for door in doors:
            parent = self.tables.get(door.via or "") if door.kind == "parent" else None
            if parent is None or not self.has_usage(name, parent):
                continue
            own, _ = reach.direct_select[parent.qualified_name]
            every_row = own.verdict == "open" or (
                own.verdict == "conditional"
                and self.prove(model, own.predicate or "", states) == ("leak", {})
            )
            if every_row:
                return CellProof("leak", model, witness={},
                                 detail=f"through parent {parent.qualified_name}")
        return None

    def _shared(self, model: ThreatModel) -> CellProof:
        # No tenant discriminator: shared data, or a column the project has
        # not named in [lint.rules.SEC021].identity_columns.
        return CellProof("unknown", model, detail=(
            "reads every row, but the table has no tenant column to isolate on "
            "(see [lint.rules.SEC021].identity_columns)"
        ))

    def gates(
        self, name: str, table: Table, model: ThreatModel, states: _GucStates,
        login: bool, predicate: str | None, proven: CellProof,
    ) -> CellProof:
        """What must also hold before a cell is PROVEN."""
        if self._owns(name, table):
            return CellProof("unknown", model, detail=(
                f"the role owns the table ({table.owner}): one ALTER TABLE … NO "
                "FORCE ROW LEVEL SECURITY or ALTER POLICY lets it read every row"
            ))
        if predicate is not None:
            owned = sorted(f for f in _called_functions(predicate)
                           if name in self.fn_owners.get(f, ()))
            if owned:
                return CellProof("unknown", model, detail=(
                    f"the role owns {owned[0]}(), which the filter calls: a CREATE "
                    "OR REPLACE FUNCTION changes what it returns"
                ))
        for door in self.reach_of(name).untraced:
            if self._owner_reaches(door.owner, table):
                return CellProof("unknown", model, detail=(
                    f"{door.door} is an untraced door this role can open, and "
                    f"its owner {door.owner or '(unknown)'} reaches the table"
                ))
        setting = predicate is not None and _calls_current_setting(predicate)
        if (
            model == "cross-tenant" and predicate is not None and (login or setting)
            and self.prove("anon", predicate, states)[0] == "leak"
        ):
            ways = [w for w, on in (("logs in with no JWT", login),
                                    ("leaves the setting the filter reads unset", setting))
                    if on]
            return CellProof("unknown", model, detail=(
                "isolated for a session that carries its identity; one that "
                + " or ".join(ways) + " reads rows"
            ))
        return proven

    def _owns(self, name: str, table: Table) -> bool:
        """Whether `name` is the table's owner — and so can change its RLS. A
        member of the owner, inheriting or not, can SET ROLE to it: the SET
        ROLE gate in `cell` covers that."""
        return bool(table.owner) and name == table.owner

    def _parent_is_own(self, name: str, parent: str | None) -> bool:
        """Whether rows reached through `parent` come from the role querying
        it itself: it holds USAGE on the parent's schema, and the parent's
        rows reach it only directly or through the parent's own parents —
        never through a view or function, which may filter."""
        table = self.tables.get(parent or "")
        if table is None or not self.has_usage(name, table):
            return False
        return all(p.kind == "parent" for p in self.reach_of(name).door_paths.get(parent or "", ()))

    def _owner_reaches(self, owner: str, table: Table, seen: frozenset[str] = frozenset()) -> bool:
        """Whether `owner` reaches rows of `table` — itself, through its
        traced doors, or through an untraced door it can open in turn."""
        role = self.attrs.get(owner)
        if not owner or role is None:
            return True
        if role.superuser or role.bypassrls:
            return True
        reach = self.reach_of(owner)
        if reach.cells[(table.qualified_name, "SELECT")].verdict != "denied":
            return True
        seen = seen | {owner}
        return any(
            door.owner not in seen and self._owner_reaches(door.owner, table, seen)
            for door in reach.untraced
        )


def prove_matrix(
    schema: Schema,
    tables: list[Table],
    roles: Iterable[str],
    reach_of: Callable[[str], RoleReach],
    attrs: dict[str, Role],
    *,
    anon_roles: set[str] | None = None,
    auth_functions: set[str] | None = None,
    identity_columns: frozenset[str] | None = None,
) -> dict[tuple[str, str], CellProof]:
    """A proof for every (table, role) SELECT cell. `reach_of` gives any
    role's reach — the columns', and also door owners' and SET ROLE targets'."""
    anon_set = frozenset((anon_roles if anon_roles else {"anon"}) | {"PUBLIC"})
    prover = _Prover(schema, reach_of, attrs, anon_set=anon_set,
                     auth_functions=auth_functions, identity_columns=identity_columns)
    return {
        (table.qualified_name, name): prover.cell(name, table)
        for name in roles
        for table in tables
    }


def public_baseline(
    schema: Schema,
    tables: list[Table],
    reach_of: Callable[[str], RoleReach],
    attrs: dict[str, Role],
    *,
    anon_roles: set[str] | None = None,
    auth_functions: set[str] | None = None,
    identity_columns: frozenset[str] | None = None,
) -> dict[tuple[str, ThreatModel, bool], CellProof]:
    """PUBLIC's proof for every table under both threat models, for a session
    that logged in itself and one that switched in — so a role is compared
    with what everyone can do under the same question."""
    anon_set = frozenset((anon_roles if anon_roles else {"anon"}) | {"PUBLIC"})
    prover = _Prover(schema, reach_of, attrs, anon_set=anon_set,
                     auth_functions=auth_functions, identity_columns=identity_columns)
    states = prover.states("PUBLIC")
    return {
        (table.qualified_name, model, login):
            prover.base("PUBLIC", table, model, states, login)
        for table in tables
        for model in _MODELS
        for login in (False, True)
    }


def proof_summary(proofs: Any) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(PROOF_STATUSES, 0)
    for p in proofs:
        if p is not None:
            counts[p.status] += 1
    return counts
