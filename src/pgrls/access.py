"""The access engine behind `pgrls matrix`: who can reach which rows, and how.

For a role, a table and a command, Postgres decides in two steps that fail
independently:

* **privilege** — may the role run the command at all? Superuser; the owner,
  or an ``INHERIT`` member of the owner; a grant (table-level, or column-level
  for SELECT / INSERT / UPDATE) to the role, to a role it inherits, or to
  ``PUBLIC``; ``pg_read_all_data`` for SELECT and ``pg_write_all_data`` for
  INSERT / UPDATE / DELETE. TRUNCATE has neither a data role nor a column form.
* **rows** — given the privilege, which rows does RLS let through? Every row
  when RLS is off, for a superuser or a BYPASSRLS role, for the owner's
  privileges on a table that is not ``FORCE``d, and always for TRUNCATE, which
  RLS never applies to. Otherwise the OR of the applicable permissive policies,
  AND-ed with the restrictive ones — or none, when no permissive policy applies.

`cell_for` answers that for a session running as the role. **Doors** widen it,
each for the commands it runs:

* a ``security_invoker = false`` view runs as its OWNER — reads, and writes
  when the view is auto-updatable;
* a SECURITY DEFINER function runs each statement of its body as its owner;
* a SECURITY DEFINER trigger runs as its owner for anyone who can fire it —
  by writing its table, directly or through another door, not by EXECUTE (a
  trigger function cannot be called);
* a rewrite rule runs its actions with the relation owner's privileges and
  policies for anyone who writes the relation, directly or through another
  door; inside the action ``current_user`` is still the writer;
* a partitioned or inheritance parent applies its own policies to its
  children's rows;
* a foreign key's CASCADE / SET NULL / SET DEFAULT action rewrites the
  referencing rows as their table's owner with RLS off, for anyone who can
  delete or update the referenced rows — which rows is unknown, so UNDECIDED.

A door whose body sets a parameter (``SET``, ``set_config``, a ``SET`` clause
on the function) runs its filters on values it chose, so a filtered door is
UNDECIDED.

A policy ``TO R`` binds exactly the roles that inherit ``R``'s privileges, like
a grant: a ``NOINHERIT`` member is bound by neither a permissive nor a
restrictive policy on ``R``. Every rule here was measured live, on PG15, PG16
and PG17 where it matters.

Not modelled: ``SET ROLE`` and DDL (each principal is a session running as
that role, changing no schema); schema ``USAGE`` (an over-report); a view's
own ``WHERE`` / ``WITH CHECK OPTION`` and what a function actually returns or
writes (a door is credited with its owner's reach of the table — an
over-report); a view writable through an INSTEAD OF trigger, and event
triggers; an ordinary (invoker) trigger fired by a door's write — it runs as
a SECURITY DEFINER function's or trigger's owner, or as the referencing
table's owner for a foreign-key action (through a definer view or a rule it
runs as the writer and adds nothing); access outside SQL privileges
(``REPLICATION``, the server-file roles, a user mapping that logs in as
another role); a cast, or an operator reusing a built-in symbol, backed by a
user function; the write-side ``WITH CHECK`` of an UPDATE (the cell shows the
rows ``USING`` lets it touch). A function, trigger or rule whose SQL cannot
be traced — dynamic SQL, another language, a call into a function or
operator pgrls cannot see, a built-in that runs SQL named by an argument, a
utility statement — is listed as untraced instead of attributed to a table.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

from pgrls.ast_utils import flatten_or_disjuncts, is_literal_true, parse_expr
from pgrls.model import Policy, RewriteRule, Role, Schema, SecdefFunction, Table, View
from pgrls.rules.sec045 import _DEFAULT_PATTERNS, _is_pii
from pgrls.verify import _anon_reachable_roles, _inherit_closure

Verdict = Literal["open", "denied", "conditional", "undecided"]

COMMANDS: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")

# Widest first. `undecided` outranks `conditional`: a path that cannot be
# bounded might admit every row, so a known partial read must not mask it.
RANK: dict[str, int] = {"open": 3, "undecided": 2, "conditional": 1, "denied": 0}

PathKind = Literal[
    "superuser",
    "data_role",
    "owner",
    "owner_member",
    "grant",
    "public_grant",
    "column_grant",
    "view",
    "function",
    "trigger",
    "rule",
    "parent",
    "foreign_key",
]


@dataclass(frozen=True)
class Cell:
    """One role x table x command verdict."""

    verdict: Verdict
    predicate: str | None = None  # the row filter, for "conditional"
    note: str | None = None  # why: "RLS off", "through definer view …", …
    # Whose session evaluates `predicate`: None for the caller's own (a view
    # does not change `current_user`); the owner for a SECURITY DEFINER
    # function or trigger, where `current_user` is the owner; the rule itself
    # for a rule's action, where `current_user` stays whoever wrote the
    # relation — the role, or a door's owner — so its filters are never taken
    # for another path's. Two filters are the same row set only when predicate
    # and session match, or the predicate cannot depend on the session
    # (`_session_dependent`). Not rendered.
    session: str | None = None


@dataclass(frozen=True)
class AccessPath:
    """One reason a principal reaches a relation.

    ``via`` names what the path runs through — the grantee for a grant, the
    owner for owner-equivalence, the view / function / trigger / rule /
    parent / foreign key for a door. ``columns`` is ``None`` for a path that
    reaches every column, or the columns a column grant covers.
    """

    kind: PathKind
    via: str | None = None
    columns: tuple[str, ...] | None = None
    # For a `view` path: every relation walked from the view the principal
    # opened down to the base table, in order.
    hops: tuple[str, ...] = ()


@dataclass(frozen=True)
class UntracedDoor:
    """A door whose SQL cannot be fully traced — a SECURITY DEFINER function,
    trigger or rule whose body runs dynamic SQL, is in another language, calls
    into a function pgrls cannot see, or runs a statement it does not trace.

    It may reach tables it is not credited with, and which ones is unknown, so
    it is listed on its own rather than attributed: attributing it to every
    table would bury the matrix, and dropping it would hide a door.
    """

    principal: str
    door: str  # "public.f()", "trigger t on public.x", "rule r on public.x"
    owner: str
    reason: str
    # Who can open it, independent of which roles are shown: the EXECUTE
    # holders of a function, or the write that fires a trigger or rule.
    reached_by: str


@dataclass(frozen=True)
class RoleReach:
    """Everything one role reaches: the merged verdict per (table, command),
    the paths behind each SELECT, and the doors it could not trace."""

    cells: dict[tuple[str, str], Cell]
    # table -> the role's own SELECT verdict and privilege paths, before any
    # door (the paths are kept even when RLS then admits no row).
    direct_select: dict[str, tuple[Cell, tuple[AccessPath, ...]]]
    # table -> every door that reaches rows for SELECT.
    door_paths: dict[str, tuple[AccessPath, ...]]
    # table -> the permissive SELECT policies that apply to a direct read.
    select_policies: dict[str, tuple[str, ...]]
    untraced: tuple[UntracedDoor, ...]


def _derived_roles(schema: Schema) -> tuple[Role, ...]:
    """Every role name the schema mentions, when no catalogue was captured.

    Owners, grantees, policy targets, EXECUTE holders and membership
    endpoints. The attributes are what is lost: ``can_login`` is unknown
    (reported as True — excluding a real entry point would hide reach), and
    superuser / BYPASSRLS come only from ``bypassrls_roles``.
    """
    names: set[str] = set()
    for t in schema.tables:
        names.add(t.owner)
        names.update(g.role for g in t.grants)
        names.update(cg.role for cg in t.column_grants)
        for p in t.policies:
            names.update(p.roles)
    for v in schema.views:
        names.add(v.owner)
        names.update(g.role for g in v.grants)
        names.update(cg.role for cg in v.column_grants)
    for f in schema.security_definer_functions:
        names.add(f.owner)
        names.update(f.execute_roles)
    for m in schema.role_memberships or ():
        names.update((m.member, m.role))
    attrs = {r.name: r for r in schema.bypassrls_roles}
    names.update(attrs)
    names -= {"PUBLIC", ""}
    return tuple(
        Role(
            name=n,
            can_login=attrs[n].can_login if n in attrs else True,
            superuser=attrs[n].superuser if n in attrs else False,
            bypassrls=n in attrs,
        )
        for n in sorted(names)
    )


# The predefined role that confers a command on every relation with no grant
# of its own. `pg_read_all_data` is SELECT only; `pg_write_all_data` is
# INSERT / UPDATE / DELETE — neither implies the other, and neither confers
# TRUNCATE.
_DATA_ROLE: dict[str, str | None] = {
    "SELECT": "pg_read_all_data",
    "INSERT": "pg_write_all_data",
    "UPDATE": "pg_write_all_data",
    "DELETE": "pg_write_all_data",
    "TRUNCATE": None,
}
# The commands a column-level grant can confer.
_COLUMN_COMMANDS = frozenset({"SELECT", "INSERT", "UPDATE"})


def _privilege_paths(
    schema: Schema,
    role: Role,
    rel: Any,
    closure: frozenset[str] | None,
    privilege: str = "SELECT",
) -> tuple[list[AccessPath], bool]:
    """The paths by which `role` holds `privilege` on `rel` (a table or a
    view), and whether that answer is complete — False only when the
    membership graph is missing AND no path that needs no graph decided it."""
    if role.superuser:
        return [AccessPath("superuser")], True
    held = closure if closure is not None else frozenset({role.name})
    paths: list[AccessPath] = []
    data_role = _DATA_ROLE[privilege]
    if data_role is not None and data_role in held:
        paths.append(AccessPath("data_role", via=data_role))
    owner = getattr(rel, "owner", "")
    if owner and owner == role.name:
        paths.append(AccessPath("owner", via=role.name))
    elif owner and owner in held:
        paths.append(AccessPath("owner_member", via=owner))
    for g in rel.grants:
        if privilege not in g.privileges:
            continue
        if g.role == "PUBLIC":
            paths.append(AccessPath("public_grant", via="PUBLIC"))
        elif g.role in held:
            paths.append(AccessPath("grant", via=g.role))
    by_grantee: dict[str, list[str]] = {}
    if privilege in _COLUMN_COMMANDS:
        for cg in getattr(rel, "column_grants", ()):
            if privilege in cg.privileges and (cg.role == "PUBLIC" or cg.role in held):
                by_grantee.setdefault(cg.role, []).append(cg.column)
    for grantee in sorted(by_grantee):
        paths.append(AccessPath(
            "column_grant", via=grantee, columns=tuple(sorted(set(by_grantee[grantee])))
        ))
    return paths, closure is not None or bool(paths)


def _reachable_columns(paths: Iterable[AccessPath]) -> tuple[str, ...] | None:
    """None if any path reaches every column, else the union of column grants."""
    cols: set[str] = set()
    for p in paths:
        if p.columns is None:
            return None
        cols.update(p.columns)
    return tuple(sorted(cols))


def _applicability(schema: Schema, name: str) -> tuple[frozenset[str], bool]:
    """The roles whose ``TO`` list a session running as `name` satisfies —
    `name`, the roles it inherits (INHERIT edges only) and ``PUBLIC`` — and
    whether that set is complete. ``PUBLIC`` is a member of nothing, so its set
    is ``{PUBLIC}`` and always complete — even with no captured graph."""
    if name == "PUBLIC":
        return frozenset({"PUBLIC"}), True
    return _anon_reachable_roles(schema, {name})


def _effective_clause(policy: Policy, command: str) -> str | None:
    """The clause Postgres applies for `command` on this policy.

    SELECT / UPDATE / DELETE are gated by USING; INSERT by WITH CHECK. A
    ``FOR ALL`` policy with no WITH CHECK reuses its USING for INSERT. None
    means the policy imposes no clause for the command — for an applicable
    permissive policy that is a missing required clause, so default-deny,
    never openness.
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
    (``has_privs_of_role``). A NOINHERIT member is bound by neither a
    permissive nor a restrictive ``TO R`` policy (measured on PG15-17).
    ``None`` = undecidable: the membership graph was not captured and the
    policy names a role outside what can be seen.
    """
    if policy.command not in ("ALL", command):
        return False
    roles = set(policy.roles) or {"PUBLIC"}  # no TO clause means PUBLIC
    if roles & applies_to:
        return True
    return None if not complete else False


@lru_cache(maxsize=4096)
def _clause_is_open(clause: str) -> bool:
    """Whether a present clause imposes no restriction: a literal ``true``
    among its top-level OR disjuncts. Lexical — ``1 = 1`` is not recognised
    and stays a predicate. Cached: the same clause is judged for every role,
    command and door owner, and parsing dominates a large matrix."""
    node = parse_expr(clause)
    if node is None:
        return False
    return any(is_literal_true(d) for d in flatten_or_disjuncts(node))


def _narrowing_restrictive(restrictive: list[Policy], command: str) -> list[str]:
    """Restrictive clauses that actually narrow rows. A floor that is
    unconditionally true (``USING (true)``, SEC031) imposes nothing, so it is
    dropped: an all-true floor collapses to OPEN, and a mixed one shows only
    the predicate that matters."""
    return [
        c
        for p in restrictive
        if (c := _effective_clause(p, command)) and not _clause_is_open(c)
    ]


def cell_for(
    schema: Schema,
    table: Table,
    role: Role,
    command: str,
    closure: frozenset[str] | None,
    applies_to: frozenset[str],
    complete: bool,
    ctx: _Context | None = None,
) -> tuple[Cell, list[AccessPath], tuple[str, ...]]:
    """What a session running as `role` reaches of `table` for `command`: the
    verdict, the privilege paths, and the permissive policies that apply."""
    paths, known = _privilege_paths(schema, role, table, closure, command)
    if not paths:
        if not known:
            return Cell(
                "undecided",
                note="role-membership graph not captured; a grant to a role "
                "this one inherits cannot be ruled out",
            ), [], ()
        return Cell("denied"), [], ()
    if command == "TRUNCATE" and ctx is not None:
        # A table other tables reference cannot be truncated without CASCADE,
        # which needs TRUNCATE on every one of them.
        for child in ctx.truncate_cascade(table):
            if not _privilege_paths(schema, role, child, closure, "TRUNCATE")[0]:
                return Cell("denied", note=(
                    f"referenced by a foreign key from {child.qualified_name}: "
                    "TRUNCATE needs CASCADE, and the TRUNCATE privilege there"
                )), paths, ()
    if role.superuser:
        return Cell("open", note="superuser"), paths, ()
    if command == "TRUNCATE":
        # Row security never applies to TRUNCATE (measured: it emptied a
        # FORCE'd table whose DELETE policies admitted no row).
        return Cell("open", note="TRUNCATE is not subject to RLS"), paths, ()
    if role.bypassrls:
        return Cell("open", note="bypasses RLS"), paths, ()
    if not table.rls_enabled:
        return Cell("open", note="RLS off"), paths, ()
    if (
        any(p.kind in ("owner", "owner_member") for p in paths)
        and not table.force_rls
    ):
        return Cell("open", note="owner; RLS not FORCE'd"), paths, ()

    verdicts = {p.name: _policy_applies(p, command, applies_to, complete)
                for p in table.policies}
    applicable = [p for p in table.policies if verdicts[p.name] is True]
    # An undecidable PERMISSIVE policy might grant rows, so it can only widen;
    # an undecidable RESTRICTIVE one might narrow, so it is left out rather
    # than turn a true OPEN into COND. Both lean toward over-reporting access.
    unknown_permissive = [
        p for p in table.policies if verdicts[p.name] is None and p.permissive
    ]
    permissive = [p for p in applicable if p.permissive]
    restrictive = [p for p in applicable if not p.permissive]
    names = tuple(sorted(p.name for p in permissive))
    if not permissive:
        if unknown_permissive:
            return Cell(
                "undecided",
                note="role-membership graph not captured; cannot tell whether "
                + ", ".join(sorted(p.name for p in unknown_permissive))
                + " apply",
            ), paths, ()
        return Cell("denied", note="no permissive policy"), paths, ()

    # A permissive policy admits rows only through the clause Postgres applies
    # for this command; a missing required clause is default-deny.
    perm = [c for p in permissive if (c := _effective_clause(p, command))]
    if not perm:
        return Cell("denied", note="no applicable permissive clause"), paths, names

    restr = _narrowing_restrictive(restrictive, command)
    if any(_clause_is_open(c) for c in perm):
        cell = Cell("conditional", predicate=" AND ".join(restr)) if restr else Cell("open")
        return cell, paths, names
    if unknown_permissive:
        return Cell(
            "undecided",
            note="role-membership graph not captured; "
            + ", ".join(sorted(p.name for p in unknown_permissive))
            + " may also apply",
        ), paths, names
    parts = [f"({' OR '.join(perm)})" if len(perm) > 1 else perm[0]]
    parts.extend(restr)
    return Cell("conditional", predicate=" AND ".join(parts)), paths, names


# --- doors -------------------------------------------------------------------

# A door's verdict, and the path that names it.
_Door = tuple[Cell, AccessPath]


def _via(prefix: str, cell: Cell, session: str | None = None) -> Cell:
    """`cell` as reached through a door: same rows, the door named first, and
    — for a door that runs as its owner — that owner's session."""
    return Cell(
        cell.verdict,
        cell.predicate,
        prefix + (f" — {cell.note}" if cell.note else ""),
        session if session is not None else cell.session,
    )


def _owner_as_role(view: View, attrs: dict[str, Role]) -> Role:
    """The view's owner as a principal. The catalogue is authoritative; without
    it, fall back to the view's own flags (`owner_bypasses_rls` is superuser OR
    BYPASSRLS, so split it on `owner_is_superuser`)."""
    if view.owner in attrs:
        return attrs[view.owner]
    return Role(
        name=view.owner,
        can_login=False,
        superuser=view.owner_is_superuser,
        bypassrls=view.owner_bypasses_rls and not view.owner_is_superuser,
    )


def _function_owner(fn: SecdefFunction, attrs: dict[str, Role]) -> Role:
    if fn.owner in attrs:
        return attrs[fn.owner]
    # `owner_bypasses_rls` is superuser OR BYPASSRLS and cannot be split
    # without the catalogue — so treat it as BYPASSRLS, not superuser: that
    # still exempts the owner from the policies, but does NOT grant it the
    # privilege to read everything (which only a superuser has). Claiming
    # superuser here would invent doors.
    return Role(name=fn.owner, can_login=False, superuser=False,
                bypassrls=fn.owner_bypasses_rls)


@dataclass(frozen=True)
class _Session:
    """Who a command runs as at some point on a path, with what it holds."""

    role: Role
    closure: frozenset[str] | None
    applies_to: frozenset[str]
    complete: bool


@dataclass
class _Context:
    """Schema-wide lookups and memos for one matrix build: every role's
    analysis reads the same relations, bodies and door owners."""

    schema: Schema
    attrs: dict[str, Role]
    tables: dict[tuple[str, str], Table] = field(default_factory=dict)
    views: dict[tuple[str, str], View] = field(default_factory=dict)
    relations: dict[tuple[str, str], str] = field(default_factory=dict)
    functions: dict[str, list[SecdefFunction]] = field(default_factory=dict)
    rules: dict[tuple[str, str], list[RewriteRule]] = field(default_factory=dict)
    # parent table qname -> the OTHER tables whose foreign keys reference it
    referencing: dict[str, list[Table]] = field(default_factory=dict)
    sessions: dict[str, _Session] = field(default_factory=dict)
    analysed: dict[Any, _Trace] = field(default_factory=dict)

    def __post_init__(self) -> None:
        s = self.schema
        self.tables = {(t.schema, t.name): t for t in s.tables}
        self.views = {(v.schema, v.name): v for v in s.views}
        self.relations = {**{k: "view" for k in self.views}, **{k: "table" for k in self.tables}}
        for f in s.security_definer_functions:
            self.functions.setdefault(f.qualified_name, []).append(f)
        for r in s.rules or ():
            self.rules.setdefault((r.schema, r.relation), []).append(r)
        for t in s.tables:
            for fk in t.foreign_keys:
                if (fk.ref_schema, fk.ref_table) != (t.schema, t.name):
                    self.referencing.setdefault(f"{fk.ref_schema}.{fk.ref_table}", []).append(t)

    def session(self, role: Role) -> _Session:
        """`role`'s privilege closure and policy applicability — memoized, as
        every door owner is asked about again for every role and command."""
        if role.name not in self.sessions:
            closure = (frozenset({"PUBLIC"}) if role.name == "PUBLIC"
                       else _inherit_closure(self.schema, role.name))
            self.sessions[role.name] = _Session(
                role, closure, *_applicability(self.schema, role.name)
            )
        return self.sessions[role.name]

    def owner(self, name: str) -> Role:
        return self.attrs.get(name, Role(name, False, False, False))

    def truncate_cascade(self, table: Table) -> list[Table]:
        """Every other table a `TRUNCATE … CASCADE` of `table` also empties."""
        out: dict[str, Table] = {}
        todo = list(self.referencing.get(table.qualified_name, ()))
        while todo:
            child = todo.pop()
            if child.qualified_name not in out and child.qualified_name != table.qualified_name:
                out[child.qualified_name] = child
                todo.extend(self.referencing.get(child.qualified_name, ()))
        return list(out.values())

    def cell(self, s: _Session, table: Table, command: str) -> Cell:
        return cell_for(self.schema, table, s.role, command, s.closure,
                        s.applies_to, s.complete, self)[0]


def _context(schema: Schema, attrs: dict[str, Role], cache: dict[Any, Any] | None) -> _Context:
    if cache is not None and "ctx" in cache:
        ctx: _Context = cache["ctx"]
        return ctx
    ctx = _Context(schema, attrs)
    if cache is not None:
        cache["ctx"] = ctx
    return ctx


def _holds(ctx: _Context, s: _Session, rel: Any, command: str) -> bool | None:
    paths, complete = _privilege_paths(ctx.schema, s.role, rel, s.closure, command)
    if paths:
        return True
    return None if not complete else False


# (relation qname, command) pairs some session runs WITH the privilege to — the
# role itself or a door's owner — whether or not RLS then lets a row through.
# A statement trigger or a rule fires on that alone.
_Issued = set[tuple[str, str]]


def _view_doors(
    ctx: _Context,
    principal: _Session,
    command: str,
    *,
    starts: Iterable[View] | None = None,
    principal_direct: bool = False,
    session: str | None = None,
    issued: _Issued | None = None,
) -> dict[str, list[_Door]]:
    """Tables `principal` reaches for `command` THROUGH views, keyed by table.

    Each hop picks its own effective user, as `verify`'s reachability walk
    does (each rule measured on PG16, and for writes too):

    * a `security_invoker = false` view runs as its OWNER;
    * a `security_invoker = true` view RESETS the effective user to the
      principal rather than inheriting an enclosing definer;
    * every hop needs the command's privilege for its effective user, or the
      path is dead (`permission denied for view inner`);
    * a write reaches through only a view that accepts it on its own
      (`View.updatable`, which accounts for the views beneath it) and has no
      INSTEAD rule for it — a rule replaces the command (see `_rule_doors`);
    * a materialized-view hop is `undecided`: its rows were captured at
      REFRESH under the matview owner's RLS context.

    A chain of invoker views that reaches a table is the principal's own
    access — nothing new — unless `principal_direct`, used when the principal
    is a SECURITY DEFINER function's owner, whose own access IS the door.
    `starts` limits the walk to views a body names; `session` is whose
    `current_user` the predicates run under (the caller's unless the walk
    started inside a function). Every relation a write reaches with the
    privilege goes into `issued`, for the triggers and rules it fires.
    """
    found: dict[str, list[_Door]] = {}

    def record(table: Table, path: AccessPath, cell: Cell) -> None:
        if cell.verdict != "denied":
            found.setdefault(table.qualified_name, []).append((cell, path))

    def tables_beneath(v: View, seen: frozenset[tuple[str, str]]) -> list[Table]:
        out: list[Table] = []
        for ref in v.direct_references or v.references:
            if ref in seen:
                continue
            if ref in ctx.tables:
                out.append(ctx.tables[ref])
            elif ref in ctx.views:
                out.extend(tables_beneath(ctx.views[ref], seen | {ref}))
        return out

    def undecided(v: View, entry: View, hops: tuple[str, ...], why: str,
                  seen: frozenset[tuple[str, str]]) -> None:
        for t in tables_beneath(v, seen):
            record(t, AccessPath("view", via=entry.qualified_name,
                                 hops=hops + (t.qualified_name,)),
                   Cell("undecided", note=why, session=session))

    def label(entry: View, definer: View) -> str:
        if definer is entry:
            return (f"through definer view {entry.qualified_name}, as its owner "
                    f"{definer.owner}")
        return (f"through view {entry.qualified_name}, then definer view "
                f"{definer.qualified_name}, as its owner {definer.owner}")

    def reach(eff: _Session, table: Table) -> Cell:
        cell, paths, _ = cell_for(ctx.schema, table, eff.role, command, eff.closure,
                                  eff.applies_to, eff.complete, ctx)
        if paths and command != "SELECT" and issued is not None:
            issued.add((table.qualified_name, command))
        return cell

    def walk(view: View, hops: tuple[str, ...], entry: View,
             seen: frozenset[tuple[str, str]]) -> None:
        definer = None if view.security_invoker else view
        eff = principal if definer is None else ctx.session(_owner_as_role(definer, ctx.attrs))
        for ref in view.direct_references or view.references:
            child = ctx.views.get(ref)
            if child is not None:
                if ref in seen:
                    continue
                child_hops = hops + (child.qualified_name,)
                if child.is_materialized:
                    if command == "SELECT":
                        undecided(child, entry, child_hops, (
                            f"{child.qualified_name} is a materialized view: its "
                            "rows were captured at REFRESH under its owner's RLS"
                        ), seen | {ref})
                    continue
                readable = _holds(ctx, eff, child, command)
                if readable is False:
                    continue  # broken intermediate hop: dead path
                if readable is None:
                    undecided(child, entry, child_hops, (
                        "role-membership graph not captured; cannot decide "
                        f"whether the path can use {child.qualified_name}"
                    ), seen | {ref})
                    continue
                if command != "SELECT" and issued is not None:
                    issued.add((child.qualified_name, command))
                walk(child, child_hops, entry, seen | {ref})
                continue
            table = ctx.tables.get(ref)
            if table is None:
                continue  # not a relation the build knows
            path = AccessPath("view", via=entry.qualified_name,
                              hops=hops + (table.qualified_name,))
            if definer is None:
                if principal_direct:
                    own = reach(eff, table)
                    record(table, path, Cell(own.verdict, own.predicate, own.note, session))
                continue  # otherwise the principal's own direct access
            record(table, path, _via(label(entry, definer), reach(eff, table), session))

    chosen = starts if starts is not None else ctx.schema.views
    for v in sorted(chosen, key=lambda v: v.qualified_name):
        start = frozenset({(v.schema, v.name)})
        if command != "SELECT":
            if v.is_materialized:
                continue
            if any(r.instead and r.command == command
                   for r in ctx.rules.get((v.schema, v.name), ())):
                continue  # the rule replaces the command
            if v.updatable is not None and command not in v.updatable:
                continue
        opens = _holds(ctx, principal, v, command)
        if opens is False:
            continue
        if v.is_materialized:
            undecided(v, v, (v.qualified_name,), (
                f"{v.qualified_name} is a materialized view: its rows were "
                "captured at REFRESH under its owner's RLS"
            ), start)
            continue
        if opens is None:
            undecided(v, v, (v.qualified_name,), (
                "role-membership graph not captured; cannot decide whether "
                f"{principal.role.name} can use {v.qualified_name}"
            ), start)
            continue
        if command != "SELECT" and v.updatable is None:
            undecided(v, v, (v.qualified_name,), (
                f"whether {v.qualified_name} accepts {command} was not captured"
            ), start)
            continue
        walk(v, (v.qualified_name,), v, start)
    return found


# pglast parse modes a PL/pgSQL expression can carry: a whole statement, an
# expression, or an assignment (`target := expr`).
_PARSE_STATEMENT, _PARSE_EXPRESSION = 0, 2
_PARSE_ASSIGNMENTS = frozenset({3, 4, 5})


def _plpgsql_statements(definition: str) -> tuple[list[Any], str | None]:
    """The static SQL a PL/pgSQL function runs, parsed, and why the list is
    incomplete (None when it is not). Every expression in the function is
    included — IF conditions and assignments can hold subqueries too."""
    import pglast  # noqa: PLC0415 — heavy parser, only on this path

    try:
        tree = pglast.parse_plpgsql(definition)
    except pglast.parser.ParseError:
        return [], "the PL/pgSQL body does not parse"
    exprs: list[tuple[str, int]] = []
    dynamic = False

    def walk(node: Any) -> None:
        nonlocal dynamic
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key in ("PLpgSQL_stmt_dynexecute", "PLpgSQL_stmt_dynfors", "dynquery"):
                    dynamic = True
                if key == "PLpgSQL_expr" and isinstance(value, dict) and value.get("query"):
                    exprs.append((value["query"], value.get("parseMode", 0)))
                walk(value)

    walk(tree)
    stmts: list[Any] = []
    unparsed = False
    for query, mode in exprs:
        if mode in _PARSE_ASSIGNMENTS:
            head, sep, tail = query.partition(":=")
            query = tail if sep else query.partition("=")[2]
            mode = _PARSE_EXPRESSION
        text = query if mode == _PARSE_STATEMENT else f"SELECT {query}"
        try:
            stmts.extend(raw.stmt for raw in pglast.parse_sql(text))
        except pglast.parser.ParseError:
            unparsed = True
    reasons = []
    if dynamic:
        reasons.append("runs dynamic SQL (EXECUTE)")
    if unparsed:
        reasons.append("a statement in the body does not parse")
    return stmts, "; ".join(reasons) or None


def _body_statements(fn: SecdefFunction) -> tuple[list[Any], str | None]:
    """The statements `fn` runs, and why they may not be all of them."""
    import pglast  # noqa: PLC0415

    from pgrls.ast_utils import function_body_sql  # noqa: PLC0415

    if fn.language == "sql":
        try:
            return [raw.stmt for raw in pglast.parse_sql(function_body_sql(fn.body))], None
        except pglast.parser.ParseError:
            return [], "the SQL body does not parse"
    if fn.language == "plpgsql":
        if fn.definition is None:
            return [], "the PL/pgSQL definition was not captured"
        return _plpgsql_statements(fn.definition)
    return [], f"a {fn.language} body cannot be read"


def _search_schemas(fn: SecdefFunction) -> list[str] | None:
    """The schemas a bare name in `fn`'s body resolves against, in order —
    None when the function pins no search_path and so inherits the caller's
    (any schema could win)."""
    if fn.search_path is None:
        return None
    out = []
    for token in fn.search_path.split(","):
        name = token.strip().strip('"')
        if name == "$user":
            name = fn.owner
        if name and name not in ("pg_catalog", "pg_temp"):
            out.append(name)
    return out


# GUCs whose change alters which relation a later name resolves to, or who
# runs it. Setting any OTHER parameter changes what a later statement's
# policies admit (a tenant id, the JWT claims), so the door's rows are then
# no longer bounded by the filter it shows.
_RESOLUTION_GUCS = frozenset({"search_path", "role", "session_authorization"})


def _set_config_target(call: Any) -> str | None:
    """The parameter a `set_config(name, …)` call sets, if it is a literal."""
    from pglast.ast import A_Const, String  # noqa: PLC0415

    args = getattr(call, "args", None) or ()
    first = args[0] if args else None
    val = getattr(first, "val", None) if isinstance(first, A_Const) else None
    return str(val.sval).lower() if isinstance(val, String) else None


def _statement_touches(
    stmt: Any,
    search: list[str] | None,
    relations: dict[tuple[str, str], str],
) -> tuple[list[tuple[tuple[str, str], str]], list[str], bool]:
    """The (relation, command) pairs one statement runs, why it may run more,
    and whether it changes a run-time setting. `relations` maps every known
    table and view key to its kind; `search` resolves a bare name (None: the
    caller's path, so every schema).

    A DML target is written with its command (plus UPDATE for ``ON CONFLICT
    DO UPDATE``, plus a read when it has ``RETURNING``; a ``TRUNCATE …
    CASCADE`` also empties what references it); every other relation the
    statement names is read. A CTE name is a local alias, not a relation.
    Only SELECT and DML are traced: any other statement (``DO``, ``CALL``,
    DDL), a call into a function or operator pgrls cannot see, or a change to
    search_path or the role is a reason the trace is incomplete. Setting any
    other parameter (``SET``, ``set_config``) is traced but flagged: it
    changes what the policies of a later statement admit.
    """
    from pglast.ast import (  # noqa: PLC0415
        A_Expr,
        DeleteStmt,
        FuncCall,
        InsertStmt,
        MergeStmt,
        Node,
        NotifyStmt,
        RangeVar,
        SelectStmt,
        TruncateStmt,
        UpdateStmt,
        VariableSetStmt,
    )

    from pgrls.ast_utils import func_name_parts  # noqa: PLC0415
    from pgrls.rules.view004 import _cte_names  # noqa: PLC0415
    from pgrls.verify import (  # noqa: PLC0415
        DEFAULT_AUTH_FUNCTIONS,
        _has_range_function,
        _opaque_call,
        _opaque_operator,
    )

    reasons: list[str] = []
    context = False
    if isinstance(stmt, VariableSetStmt):
        if stmt.name is None or str(stmt.name).lower() in _RESOLUTION_GUCS:
            reasons.append("changes search_path or the role at run time")
        else:
            context = True
    elif not isinstance(stmt, (SelectStmt, InsertStmt, UpdateStmt, DeleteStmt, MergeStmt,
                               TruncateStmt, NotifyStmt)):
        reasons.append(f"runs a {type(stmt).__name__} statement it does not trace")
    ctes = _cte_names(stmt)
    targets: dict[int, list[str]] = {}  # id(RangeVar) -> commands
    names: list[Any] = []
    opaque = False

    def walk(n: Any) -> None:
        nonlocal context, opaque
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if not isinstance(n, Node):
            return
        if isinstance(n, FuncCall):
            if func_name_parts(n)[1] == "set_config":
                target = _set_config_target(n)
                if target is None or target in _RESOLUTION_GUCS:
                    reasons.append("changes search_path or the role at run time")
                else:
                    context = True
            elif _opaque_call(n, DEFAULT_AUTH_FUNCTIONS):
                opaque = True
        if isinstance(n, A_Expr) and _opaque_operator(n):
            opaque = True
        if isinstance(n, (InsertStmt, UpdateStmt, DeleteStmt, MergeStmt)):
            cmds = {InsertStmt: ["INSERT"], UpdateStmt: ["UPDATE"],
                    DeleteStmt: ["DELETE"],
                    MergeStmt: ["INSERT", "UPDATE", "DELETE", "SELECT"]}[type(n)]
            conflict = getattr(n, "onConflictClause", None)
            action = getattr(getattr(conflict, "action", None), "name", "")
            if action == "ONCONFLICT_UPDATE":
                cmds = cmds + ["UPDATE"]  # ON CONFLICT DO UPDATE, not DO NOTHING
            if getattr(n, "returningList", None):
                cmds = cmds + ["SELECT"]
            if n.relation is not None:
                targets[id(n.relation)] = cmds
        if isinstance(n, TruncateStmt):
            cascade = getattr(getattr(n, "behavior", None), "name", "") == "DROP_CASCADE"
            for rv in n.relations or ():
                targets[id(rv)] = ["TRUNCATE CASCADE" if cascade else "TRUNCATE"]
        if isinstance(n, RangeVar):
            names.append(n)
        for fld in n:
            walk(getattr(n, fld, None))

    walk(stmt)
    if ctes & {name for _, name in relations}:
        reasons.append("a CTE shadows a table name")
    if opaque or _has_range_function(stmt):
        reasons.append("calls a function it does not see into")
    touches: list[tuple[tuple[str, str], str]] = []
    for rv in names:
        relname, schemaname = rv.relname, rv.schemaname
        if schemaname is None and relname in ctes:
            continue
        if schemaname is not None:
            keys = [(schemaname, relname)] if (schemaname, relname) in relations else []
        elif search is None:
            keys = sorted(k for k in relations if k[1] == relname)
        else:
            # Every schema on the path that has the name: a schema the owner
            # lacks USAGE on is skipped by Postgres, so the first match is not
            # necessarily the one that wins.
            keys = [(s, relname) for s in search if (s, relname) in relations]
        for key in keys:
            for command in targets.get(id(rv), ["SELECT"]):
                touches.append((key, command))
    return touches, list(dict.fromkeys(reasons)), context


_Trace = tuple[list[tuple[tuple[str, str], str]], list[str], bool]


def _trace(ctx: _Context, key: Any, statements: Any, search: list[str] | None) -> _Trace:
    """What a body touches, why that may not be everything, and whether it
    changes a run-time setting — memoized: the same for every caller."""
    if key in ctx.analysed:
        return ctx.analysed[key]
    context = False
    try:
        stmts, why = statements()
        reasons = [why] if why else []
        touches: list[tuple[tuple[str, str], str]] = []
        for stmt in stmts:
            t, r, c = _statement_touches(stmt, search, ctx.relations)
            touches.extend(t)
            reasons.extend(r)
            context = context or c
    except RecursionError:
        # Measured: a 1200-term expression made the walk overflow the stack.
        touches, reasons = [], ["the body is nested too deeply to trace"]
    result = (list(dict.fromkeys(touches)), list(dict.fromkeys(reasons)), context)
    ctx.analysed[key] = result
    return result


def _display(fn: SecdefFunction) -> str:
    return fn.qualified_name + (f"({fn.signature})" if fn.signature is not None else "")


def _executors(fn: SecdefFunction) -> str:
    holders = sorted(fn.execute_roles)
    return "EXECUTE: " + ", ".join(holders + [f"owner {fn.owner}"] if fn.owner else holders)


def _run_as_owner(
    ctx: _Context,
    owner: _Session,
    touches: list[tuple[tuple[str, str], str]],
    label: str,
    kind: PathKind,
    via: str,
    *,
    session: str | None,
    context: bool = False,
) -> tuple[dict[tuple[str, str], list[_Door]], _Issued]:
    """Doors for statements that run with `owner`'s privileges and policies:
    each touched table is reached as the owner; a view is walked as the owner.
    `session` is whose `current_user` the filters see. When the body chose
    its own settings (`context`), a filter no longer bounds the rows, so a COND
    door is UNDECIDED. Also returns every relation written with the privilege,
    for the triggers and rules that fires."""
    found: dict[tuple[str, str], list[_Door]] = {}
    issued: _Issued = set()
    path = AccessPath(kind, via=via)

    def add(qname: str, command: str, door: Cell, p: AccessPath) -> None:
        if context and door.verdict == "conditional":
            door = Cell("undecided", note=(
                f"{door.note} — its body sets configuration parameters, so the "
                "filter runs on values it chooses"
            ), session=session)
        found.setdefault((qname, command), []).append((door, p))

    expanded: list[tuple[tuple[str, str], str]] = []
    for key, command in touches:
        if command == "TRUNCATE CASCADE":
            expanded.append((key, "TRUNCATE"))
            if key in ctx.tables:
                expanded.extend(((c.schema, c.name), "TRUNCATE")
                                for c in ctx.truncate_cascade(ctx.tables[key]))
        else:
            expanded.append((key, command))
    for key, command in dict.fromkeys(expanded):
        if key in ctx.tables:
            table = ctx.tables[key]
            cell, paths, _ = cell_for(ctx.schema, table, owner.role, command, owner.closure,
                                      owner.applies_to, owner.complete, ctx)
            if paths and command != "SELECT":
                issued.add((table.qualified_name, command))
            if cell.verdict != "denied":
                add(table.qualified_name, command, _via(label, cell, session), path)
            continue
        view = ctx.views.get(key)
        if view is None:
            continue
        if command != "SELECT" and _holds(ctx, owner, view, command):
            issued.add((view.qualified_name, command))
        for qname, doors in _view_doors(
            ctx, owner, command, starts=[view], principal_direct=True, session=session,
            issued=issued,
        ).items():
            for cell, vpath in doors:
                add(qname, command, _via(f"{label}, then {vpath.via}", cell, session),
                    AccessPath(kind, via=via, hops=vpath.hops))
    return found, issued


def _function_doors(
    ctx: _Context, role: Role, closure: frozenset[str] | None,
) -> tuple[dict[tuple[str, str], list[_Door]], list[UntracedDoor], _Issued]:
    """What `role` reaches by EXECUTEing a SECURITY DEFINER function, keyed by
    (table, command). The body runs as the function's OWNER, so each statement
    reaches its table with the owner's privileges and RLS. EXECUTE is a
    privilege — the INHERIT closure, ``PUBLIC`` by default (introspection
    expands ``acldefault``), and implicitly the owner and anyone who inherits
    it. A trigger function cannot be called, so it is never a door here
    (`_trigger_doors`)."""
    found: dict[tuple[str, str], list[_Door]] = {}
    untraced: list[UntracedDoor] = []
    issued: _Issued = set()
    held = (closure if closure is not None else frozenset({role.name})) | {"PUBLIC"}
    for fn in sorted(ctx.schema.security_definer_functions,
                     key=lambda f: (f.qualified_name, f.signature or "")):
        if fn.trigger:
            continue
        executors = set(fn.execute_roles)
        can = (
            role.superuser
            or (bool(fn.owner) and (fn.owner == role.name or fn.owner in held))
            or bool(executors & held)
        )
        if not can:
            if closure is None and role.name != "PUBLIC" and (executors - {"PUBLIC"} or fn.owner):
                untraced.append(UntracedDoor(
                    role.name, _display(fn), fn.owner,
                    "role-membership graph not captured; cannot decide whether "
                    f"{role.name} can EXECUTE it", _executors(fn),
                ))
            continue
        touches, reasons, context = _trace(ctx, ("fn", fn), lambda f=fn: _body_statements(f),
                                           _search_schemas(fn))
        if reasons:
            untraced.append(UntracedDoor(
                role.name, _display(fn), fn.owner, "; ".join(reasons), _executors(fn),
            ))
        owner = ctx.session(_function_owner(fn, ctx.attrs))
        doors, out = _run_as_owner(
            ctx, owner, touches,
            f"through SECURITY DEFINER {_display(fn)}, as its owner {fn.owner}",
            "function", _display(fn), session=owner.role.name,
            context=context or bool(fn.config_gucs),
        )
        issued |= out
        for key, ds in doors.items():
            found.setdefault(key, []).extend(ds)
    return found, untraced, issued


def _fires(ctx: _Context, table: Table, command: str, trigger: Any,
           cells: dict[tuple[str, str], Cell], issuable: _Issued) -> bool:
    """Whether the role can make `trigger` fire for `command` on `table`.

    A statement trigger (and one of unknown level, conservatively) fires on
    any statement the privilege allows, even one that touches no row — also
    when a door's owner issues it. A BEFORE row trigger on INSERT fires before
    the INSERT's WITH CHECK, and one returning NULL skips the check (measured:
    its writes stood while the INSERT itself was refused). Other row triggers
    fire only for rows that get through; an UPDATE that moves a row between
    partitions fires DELETE on the source and INSERT on the destination."""
    key = (table.qualified_name, command)
    if command == "TRUNCATE" or trigger.row is not True:
        return key in issuable
    if trigger.timing == "BEFORE" and command == "INSERT" and key in issuable:
        return True
    if cells[key].verdict != "denied":
        return True
    if command in ("INSERT", "DELETE"):
        return any(
            declarative and cells[(a.qualified_name, "UPDATE")].verdict != "denied"
            for a, declarative in _ancestors(ctx.schema, table)
        )
    return False


def _trigger_doors(
    ctx: _Context, me: _Session, cells: dict[tuple[str, str], Cell], issuable: _Issued,
) -> tuple[dict[tuple[str, str], list[_Door]], list[UntracedDoor], _Issued]:
    """What the role reaches by firing a SECURITY DEFINER trigger: writing the
    trigger's table — directly or through any door — runs the trigger function
    as its OWNER, with no EXECUTE check (measured: a role with only INSERT on
    `inbox` emptied a FORCE'd `secrets` through an AFTER INSERT trigger). A
    partition fires its declarative ancestors' row triggers (they are cloned
    to it). An ordinary trigger function runs as the writer and adds nothing."""
    found: dict[tuple[str, str], list[_Door]] = {}
    untraced: list[UntracedDoor] = []
    issued: _Issued = set()
    for table in ctx.tables.values():
        holders = [(table, True)] + [
            (a, False) for a, declarative in _ancestors(ctx.schema, table) if declarative
        ]
        for holder, own in holders:
            for tr in holder.triggers:
                fns = [f for f in ctx.functions.get(tr.function_qualified_name, ()) if f.trigger]
                if not tr.enabled or not fns or (not own and tr.row is False):
                    continue  # only row triggers are cloned to partitions
                for command in tr.event.split(" OR "):
                    if not _fires(ctx, table, command, tr, cells, issuable):
                        continue
                    for fn in fns:
                        door = f"trigger {tr.name} on {holder.qualified_name}"
                        touches, reasons, context = _trace(
                            ctx, ("fn", fn), lambda f=fn: _body_statements(f), _search_schemas(fn),
                        )
                        if reasons:
                            untraced.append(UntracedDoor(
                                me.role.name, door, fn.owner, "; ".join(reasons),
                                f"{command} on {table.qualified_name}",
                            ))
                        owner = ctx.session(_function_owner(fn, ctx.attrs))
                        doors, out = _run_as_owner(
                            ctx, owner, touches,
                            f"through {door} (SECURITY DEFINER {_display(fn)}, as its "
                            f"owner {fn.owner})",
                            "trigger", door, session=owner.role.name,
                            context=context or bool(fn.config_gucs),
                        )
                        issued |= out
                        for key, ds in doors.items():
                            found.setdefault(key, []).extend(ds)
    return found, untraced, issued


def _rule_statements(rule: RewriteRule) -> tuple[list[Any], str | None]:
    import pglast  # noqa: PLC0415

    try:
        [raw] = pglast.parse_sql(rule.definition)
    except (pglast.parser.ParseError, ValueError):
        return [], "the rule does not parse"
    return list(getattr(raw.stmt, "actions", None) or ()), None


def _rule_doors(
    ctx: _Context, me: _Session, issuable: _Issued,
) -> tuple[dict[tuple[str, str], list[_Door]], list[UntracedDoor], _Issued]:
    """What the role reaches through a rewrite rule: a write to the relation —
    by the role, or by a door's owner — runs the rule's actions with the
    relation OWNER's privileges and policies (measured: `ON INSERT TO requests
    DO ALSO DELETE FROM archive` emptied a FORCE'd table the inserting role
    could not touch, directly or through a SECURITY DEFINER function). Inside
    the action `current_user` stays the writer, so the door's filters are
    tagged with a session of their own and never merged as the same rows. The
    definition is deparsed schema-qualified, so no name needs resolving."""
    found: dict[tuple[str, str], list[_Door]] = {}
    untraced: list[UntracedDoor] = []
    issued: _Issued = set()
    for key, rules in ctx.rules.items():
        rel = ctx.tables.get(key) or ctx.views.get(key)
        if rel is None:
            continue
        for rule in rules:
            if (rule.qualified_relation, rule.command) not in issuable:
                continue
            door = f"rule {rule.name} on {rule.qualified_relation}"
            touches, reasons, context = _trace(
                ctx, ("rule", rule), lambda r=rule: _rule_statements(r), [],
            )
            if reasons:
                untraced.append(UntracedDoor(
                    me.role.name, door, rel.owner, "; ".join(reasons),
                    f"{rule.command} on {rule.qualified_relation}",
                ))
            doors, out = _run_as_owner(
                ctx, ctx.session(ctx.owner(rel.owner)), touches,
                f"through {door}, as its owner {rel.owner}", "rule", door,
                session=door, context=context,
            )
            issued |= out
            for k, ds in doors.items():
                found.setdefault(k, []).extend(ds)
    return found, untraced, issued


# Referential actions that rewrite the referencing rows, and the command they
# amount to there.
_FK_ACTIONS = {"CASCADE": "DELETE", "SET NULL": "UPDATE", "SET DEFAULT": "UPDATE"}


def _fk_doors(
    ctx: _Context, cells: dict[tuple[str, str], Cell],
) -> tuple[dict[tuple[str, str], list[_Door]], _Issued]:
    """What the role reaches through a foreign key's referential action: a
    CASCADE / SET NULL / SET DEFAULT rewrites the referencing rows as their
    table's owner with RLS off, for anyone who can delete or update the
    referenced rows (measured: a DELETE on `accounts` emptied a FORCE'd
    `ledger` the role could not touch). Which rows depends on the data, so the
    door is UNDECIDED. The action is a statement on the referencing table, so
    it fires that table's triggers."""
    found: dict[tuple[str, str], list[_Door]] = {}
    issued: _Issued = set()
    for child in ctx.tables.values():
        for fk in child.foreign_keys:
            parent = f"{fk.ref_schema}.{fk.ref_table}"
            for trigger, action in (("DELETE", fk.on_delete), ("UPDATE", fk.on_update)):
                if action not in _FK_ACTIONS:
                    continue
                if cells.get((parent, trigger), Cell("denied")).verdict == "denied":
                    continue
                command = "UPDATE" if trigger == "UPDATE" else _FK_ACTIONS[action]
                issued.add((child.qualified_name, command))
                found.setdefault((child.qualified_name, command), []).append((
                    Cell("undecided", note=(
                        f"rows referencing {parent} rows the role can "
                        f"{trigger.lower()} (foreign key {fk.name}: ON {trigger} "
                        f"{action}, run as the table's owner with RLS off)"
                    )),
                    AccessPath("foreign_key", via=fk.name),
                ))
    return found, issued


def _ancestors(schema: Schema, table: Table) -> list[tuple[Table, bool]]:
    """`table`'s partition ancestors (True) and classic-inheritance ancestors
    (False). A query on an ancestor reaches this table's rows under the
    ANCESTOR's policies and privileges (measured: a child with RLS FORCE'd and
    no grant was read, updated and deleted through its parent)."""
    try:
        return [(a, True) for a in schema.ancestors_of(table)] + [
            (a, False) for a in schema.inheritance_ancestors_of(table)
        ]
    except ValueError:  # a cycle: corrupted state Postgres never produces
        return []


def _parent_doors(
    ctx: _Context, cells: dict[tuple[str, str], Cell],
) -> dict[tuple[str, str], list[_Door]]:
    found: dict[tuple[str, str], list[_Door]] = {}
    for table in ctx.tables.values():
        for ancestor, declarative in _ancestors(ctx.schema, table):
            for command in COMMANDS:
                # An INSERT into a partitioned parent is routed to a partition;
                # one into a classic-inheritance parent stays in the parent.
                if command == "INSERT" and not declarative:
                    continue
                door = cells[(ancestor.qualified_name, command)]
                if door.verdict != "denied":
                    found.setdefault((table.qualified_name, command), []).append((
                        _via(f"through parent {ancestor.qualified_name}", door),
                        AccessPath("parent", via=ancestor.qualified_name),
                    ))
    return found


# Functions whose value depends on who runs them: a filter that calls one is
# not the same row set for two sessions, even word for word.
_SESSION_FUNCTIONS = frozenset({"pg_has_role", "row_security_active"})


@lru_cache(maxsize=4096)
def _session_dependent(predicate: str) -> bool:
    """Whether `predicate` can admit different rows for different current
    users: it reads `current_user` / `session_user` / `current_role` / `user`,
    checks a privilege, or calls a function pgrls cannot see into (which may
    do either). Unparseable counts as dependent."""
    from pglast.ast import FuncCall, Node, SQLValueFunction  # noqa: PLC0415

    from pgrls.ast_utils import func_name_parts  # noqa: PLC0415
    from pgrls.verify import DEFAULT_AUTH_FUNCTIONS, _opaque_call  # noqa: PLC0415

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
        if isinstance(n, SQLValueFunction):
            op = getattr(getattr(n, "op", None), "name", "")
            if "USER" in op or "ROLE" in op:
                found = True
                return
        if isinstance(n, FuncCall):
            bare = func_name_parts(n)[1] or ""
            if (bare in _SESSION_FUNCTIONS
                    or (bare.startswith("has_") and bare.endswith("_privilege"))
                    or _opaque_call(n, DEFAULT_AUTH_FUNCTIONS)):
                found = True
                return
        if isinstance(n, Node):
            for fld in n:
                walk(getattr(n, fld, None))

    walk(node)
    return found


def _merge(cell: Cell, door: Cell, path: AccessPath) -> Cell:
    """Fold one door into a cell: the wider verdict wins. Two filtered row
    sets are a problem — their union could be every row — so unless both are
    the same predicate, evaluated in the same session or not depending on it,
    the answer becomes UNDECIDED rather than the narrower-looking COND."""
    if door.verdict == "denied":
        return cell
    if RANK[door.verdict] > RANK[cell.verdict]:
        return door
    if cell.verdict == door.verdict == "conditional":
        if door.predicate is not None and door.predicate == cell.predicate and (
            door.session == cell.session or not _session_dependent(door.predicate)
        ):
            also = f"also {door.note}" if door.note else None
            note = "; ".join(n for n in (cell.note, also) if n) or None
            return Cell(cell.verdict, cell.predicate, note, cell.session)
        first = f"directly where {cell.predicate}" if cell.predicate and not cell.note \
            else (cell.note or cell.predicate)
        return Cell("undecided", note=(
            f"two filtered paths — {first}; and {door.note or door.predicate} — "
            "whose union cannot be bounded"
        ))
    return cell


def _fold(cell: Cell, doors: list[_Door]) -> Cell:
    for door, path in sorted(
        doors, key=lambda d: (-RANK[d[0].verdict], d[0].note or "", d[1].via or "")
    ):
        cell = _merge(cell, door, path)
    return cell


def role_reach(
    schema: Schema,
    role: Role,
    closure: frozenset[str] | None,
    attrs: dict[str, Role],
    cache: dict[Any, Any] | None = None,
) -> RoleReach:
    """Everything `role` reaches, per (table, command): its own session first,
    then every door. Views and SECURITY DEFINER functions are the role's own
    choice to open; parents, triggers, rules and foreign-key actions follow
    from what it — or a door's owner — can already do, so they are iterated to
    a fixed point: a trigger's write can fire another trigger, a cascade
    another cascade. Both the cells and the set of commands issued only ever
    grow, so the loop ends."""
    ctx = _context(schema, attrs, cache)
    me = _Session(role, closure, *_applicability(schema, role.name))
    direct: dict[tuple[str, str], Cell] = {}
    direct_select: dict[str, tuple[Cell, tuple[AccessPath, ...]]] = {}
    select_policies: dict[str, tuple[str, ...]] = {}
    issuable: _Issued = set()
    for q, t in ((t.qualified_name, t) for t in schema.tables):
        for command in COMMANDS:
            cell, paths, pols = cell_for(schema, t, role, command, closure,
                                         me.applies_to, me.complete, ctx)
            direct[(q, command)] = cell
            if paths and command != "SELECT":
                issuable.add((q, command))
            if command == "SELECT":
                direct_select[q] = (cell, tuple(paths))
                select_policies[q] = pols
    for v in schema.views:
        for command in ("INSERT", "UPDATE", "DELETE"):
            if _holds(ctx, me, v, command):
                issuable.add((v.qualified_name, command))

    chosen: dict[tuple[str, str], list[_Door]] = {}
    for command in COMMANDS:
        if command == "TRUNCATE":
            continue  # a view cannot be truncated
        for q, ds in _view_doors(ctx, me, command, issued=issuable).items():
            chosen.setdefault((q, command), []).extend(ds)
    fn_doors, untraced, fn_issued = _function_doors(ctx, role, closure)
    issuable |= fn_issued
    for key, ds in fn_doors.items():
        chosen.setdefault(key, []).extend(ds)
    base = {k: _fold(direct[k], chosen.get(k, [])) for k in direct}

    cells, reach = dict(base), set(issuable)
    followed: dict[tuple[str, str], list[_Door]] = {}
    later: list[UntracedDoor] = []
    while True:
        followed, more = {}, set()
        parent = _parent_doors(ctx, cells)
        fk, fk_issued = _fk_doors(ctx, cells)
        trig, trig_untraced, trig_issued = _trigger_doors(ctx, me, cells, reach)
        rule, rule_untraced, rule_issued = _rule_doors(ctx, me, reach)
        for found in (parent, fk, trig, rule):
            for key, ds in found.items():
                followed.setdefault(key, []).extend(ds)
        more = issuable | fk_issued | trig_issued | rule_issued
        later = trig_untraced + rule_untraced
        new = {k: _fold(base[k], followed.get(k, [])) for k in base}
        if new == cells and more == reach:
            break
        cells, reach = new, more

    door_paths: dict[str, list[AccessPath]] = {q: [] for q in direct_select}
    for doors in (chosen, followed):
        for (q, command), ds in doors.items():
            if command == "SELECT" and q in door_paths:
                door_paths[q].extend(p for d, p in ds if d.verdict != "denied")
    return RoleReach(
        cells=cells,
        direct_select=direct_select,
        door_paths={q: tuple(dict.fromkeys(p)) for q, p in door_paths.items()},
        select_policies=select_policies,
        untraced=tuple(dict.fromkeys(untraced + later)),
    )


def _sensitive(
    table: Table, columns: tuple[str, ...] | None, patterns: frozenset[str] = _DEFAULT_PATTERNS
) -> tuple[str, ...]:
    """The reachable columns whose name matches SEC045's PII patterns."""
    reachable = table.columns if columns is None else columns
    return tuple(sorted(c for c in reachable if _is_pii(c, patterns)))


def principal_of(
    schema: Schema, name: str, attrs: dict[str, Role]
) -> tuple[Role, frozenset[str] | None]:
    """A role name as `(Role, privilege closure)`. ``PUBLIC`` is the pseudo-role
    every session is in: it holds only what is granted to ``PUBLIC``."""
    if name == "PUBLIC":
        return Role("PUBLIC", False, False, False), frozenset({"PUBLIC"})
    return attrs.get(name, Role(name, False, False, False)), _inherit_closure(schema, name)
