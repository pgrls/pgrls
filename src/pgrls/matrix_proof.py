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
  own; the role does not own the table (it could lift ``FORCE`` or rewrite a
  policy in one statement); the filter reads nothing an HTTP client chooses
  through PostgREST (a request header, cookie, method or path setting, or the
  search_path behind ``current_schema()``); no auth function the
  filter calls reads — in
  its body or a callee's, a view standing for its tables — a table the
  session can write (it could change who it is taken to be; a relation pgrls
  cannot resolve counts, and a body it cannot read counts as any table); for a role that can log in — a raw SQL
  session — it has no CREATEROLE before Postgres 16 (which grants itself any
  non-superuser role), the filter reads no setting the session could set for
  itself (directly or in a function body, the catalog's view of session
  state included), the session owns no user-defined function (one may
  sit behind a call, an operator or a cast), it cannot create objects in a
  schema, nor a schema in the database, while the filter calls a
  user-defined function, and no
  user-defined function the filter reaches reads a relation by bare name
  under a search_path that does not end in ``pg_temp`` (the session's own
  temp table would take its place); a filter scoped by a setting
  (``current_setting``) also isolates a session that leaves it unset, and —
  for a role that can log in — one that connects with no JWT; and every role
  the session can ``SET ROLE`` to is proven too.
* **unknown** for everything else, with the reason.
* **exempt** for a superuser or ``BYPASSRLS`` column outside the anonymous
  set: it skips RLS by design (SEC016 is the place to question that). An
  anonymous role that bypasses RLS is the worst leak there is, so anonymous
  columns are never exempt.

Who the session is: a NOLOGIN role (Supabase's ``anon`` and
``authenticated``) is reached through a gateway that sets its identity and
runs only the API's queries, so the cross-tenant model takes the identity as
given and the session changes no schema object; whatever the gateway's own
login role can do is that role's column. A role that can log in is a raw SQL
session: it can set any setting, create temp tables and use any schema it can
create in, which the gates above account for. A door pgrls cannot trace
runs whatever its owner can, DDL included, so for every column the owners of
untraced doors the session can open count toward the ownership and CREATE
checks. The proof also assumes the role
can execute the functions a policy calls, as `pgrls verify` does.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from pgrls.access import RoleReach, _dependence
from pgrls.ast_utils import parse_expr
from pgrls.model import Role, Schema, Table, UserFunction, View

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
    node = parse_expr(predicate)
    if node is None:
        return True
    return _has_node_in(node, match)


def _has_node_in(node: Any, match: Callable[[Any], bool]) -> bool:
    """Whether any node under `node` satisfies `match` — `True` when it is too
    deep to walk."""
    from pglast.ast import Node  # noqa: PLC0415

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


def _is_current_setting(n: Any) -> bool:
    from pglast.ast import FuncCall  # noqa: PLC0415

    from pgrls.verify import _bare_builtin_name  # noqa: PLC0415

    return isinstance(n, FuncCall) and _bare_builtin_name(n) == "current_setting"


_CLIENT_SETTINGS = ("request.header.", "request.cookie.")
# Follow the search_path, which a session sets — and PostgREST sets from the
# client's Accept-Profile / Content-Profile header.
_SEARCH_PATH_FUNCTIONS = frozenset({"current_schema", "current_schemas"})
_CLIENT_SETTING_NAMES = frozenset({
    "request.headers", "request.cookies", "request.method", "request.path",
})


def _client_setting(node: Any) -> str | None:
    """The setting name when `node` is a ``current_setting`` call reading one
    an HTTP client controls through PostgREST (a request header or cookie)."""
    from pglast.ast import A_Const, FuncCall, String, TypeCast  # noqa: PLC0415

    if isinstance(node, FuncCall) and getattr(
        node.funcname[-1], "sval", "").lower() in _SEARCH_PATH_FUNCTIONS:
        return "search_path"
    if not _is_current_setting(node) or not node.args:
        return None
    arg = node.args[0]
    while isinstance(arg, TypeCast):  # stored policies carry 'name'::text
        arg = arg.arg
    val = getattr(arg, "val", None) if isinstance(arg, A_Const) else None
    if not isinstance(val, String):
        return "?"
    name = str(val.sval).lower()
    if name in _CLIENT_SETTING_NAMES or name.startswith(_CLIENT_SETTINGS):
        return name
    return None


def _client_reason(found: str, where: str | None) -> str:
    """The reason for a client-controlled setting `found` ("?" for a computed
    name) read in `where` (None: the filter itself)."""
    loc = f" (in {where}())" if where else ""
    if found == "search_path":
        return (f"the filter reads current_schema(){loc}, which follows the "
                "search_path — PostgREST sets it from the client's Accept-Profile "
                "header, so the client may choose among the exposed schemas")
    if found == "?":
        return (f"the filter reads a setting whose name is computed{loc}; it may be a "
                "request header or cookie the HTTP client chooses through PostgREST")
    return (f"the filter reads {found}{loc}, a request header or cookie the HTTP "
            "client sets through PostgREST — the client chooses its value")


def _reads_session_state(n: Any) -> bool:
    """A setting read, or a system catalog relation — pg_settings and
    pg_stat_activity show state the session sets for itself (application_name,
    any SET) — or a catalog function that does."""
    from pglast.ast import FuncCall, RangeVar  # noqa: PLC0415

    if _is_current_setting(n):
        return True
    if isinstance(n, RangeVar):
        schema = (n.schemaname or "").lower()
        return schema == "pg_catalog" or (not schema and n.relname.lower().startswith("pg_"))
    if isinstance(n, FuncCall):
        name = getattr(n.funcname[-1], "sval", "").lower()
        return (name.startswith("pg_show_all_settings") or name == "pg_stat_get_activity"
                or name in _SEARCH_PATH_FUNCTIONS)
    return False


def _calls_current_setting(predicate: str) -> bool:
    """Whether `predicate` reads a setting with the built-in
    ``current_setting`` (a tenant carried in a GUC, not a JWT)."""
    return _has_node(predicate, _is_current_setting)


def _has_node_in_sql(body: str, match: Callable[[Any], bool]) -> bool:
    """`_has_node` for a function body — `True` when it does not parse."""
    from pglast import parse_sql  # noqa: PLC0415

    try:
        stmts = parse_sql(body)
    except Exception:  # noqa: BLE001
        return True
    return _has_node_in(stmts, match)


def _called_functions(sql: str, *, statement: bool = False) -> set[str]:
    """The names of the functions `sql` — an expression, or with `statement`
    a function body — calls, as written (qualified or bare)."""
    from pglast import parse_sql  # noqa: PLC0415
    from pglast.ast import FuncCall  # noqa: PLC0415

    names: set[str] = set()

    def match(n: Any) -> bool:
        if isinstance(n, FuncCall):
            names.add(".".join(getattr(part, "sval", "") for part in n.funcname))
        return False

    if statement:
        try:
            stmts = parse_sql(sql)
        except Exception:  # noqa: BLE001
            return names
        _has_node_in(stmts, match)
    else:
        _has_node(predicate=sql, match=match)
    return names


def _pg_temp_last(search_path: str) -> bool:
    """Whether a pinned ``search_path`` value names pg_temp as its last entry."""
    entries = [e.strip().strip('"').lower() for e in search_path.split(",") if e.strip()]
    return bool(entries) and entries[-1] == "pg_temp"


def _unqualified_relations(body: str) -> set[str] | None:
    """The relation names a SQL body reads without a schema — a CTE's name
    too, since its scope is not modelled — or None when it does not parse."""
    from pglast import parse_sql  # noqa: PLC0415
    from pglast.ast import Node, RangeVar  # noqa: PLC0415

    try:
        stmts = parse_sql(body)
    except Exception:  # noqa: BLE001 — any parse failure means "unreadable"
        return None
    names: set[str] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, RangeVar) and not n.schemaname:
            names.add(n.relname)
        if isinstance(n, Node):
            for fld in n:
                walk(getattr(n, fld, None))

    try:
        walk(stmts)
    except RecursionError:
        return None
    return names


def _body_statements_of(fn: UserFunction) -> list[Any] | None:
    """The statements a user-defined function's body runs, parsed — None
    when they cannot all be known (another language, dynamic SQL, a parse
    error). An atomic body's ``CREATE FUNCTION`` is parsed whole."""
    from pglast import parse_sql  # noqa: PLC0415

    from pgrls.access import _plpgsql_statements  # noqa: PLC0415

    if fn.body is None:
        return None
    if fn.language == "sql" or fn.atomic:
        try:
            return [raw.stmt for raw in parse_sql(fn.body)]
        except Exception:  # noqa: BLE001
            return None
    if fn.language == "plpgsql":
        stmts, incomplete = _plpgsql_statements(
            "CREATE FUNCTION pgrls_body() RETURNS void LANGUAGE plpgsql AS "
            f"$pgrls_body${fn.body}$pgrls_body$"
        )
        return None if incomplete else stmts
    return None


def _names_called(stmts: Any) -> set[str]:
    """The function names (as written) called anywhere in `stmts`."""
    from pglast.ast import FuncCall  # noqa: PLC0415

    names: set[str] = set()

    def match(n: Any) -> bool:
        if isinstance(n, FuncCall):
            names.add(".".join(getattr(part, "sval", "") for part in n.funcname))
        return False

    _has_node_in(stmts, match)
    return names


def _or_branches(node: Any) -> list[Any]:
    """The top-level OR disjuncts of an expression (itself when not an OR)."""
    from pglast.ast import BoolExpr  # noqa: PLC0415
    from pglast.enums import BoolExprType  # noqa: PLC0415

    if isinstance(node, BoolExpr) and node.boolop == BoolExprType.OR_EXPR:
        return [b for arg in node.args for b in _or_branches(arg)]
    return [node]


def _has_subselect(predicate: str) -> bool:
    """Whether `predicate` has a sub-select that reads a relation anywhere in
    it (a UNION's halves included) — a FROM-less ``( SELECT auth.uid() AS
    uid)`` (Supabase's InitPlan wrapper) does not."""
    from pglast.ast import RangeVar, SubLink  # noqa: PLC0415

    def reads_relation(n: Any) -> bool:
        return isinstance(n, SubLink) and _has_node_in(
            n.subselect, lambda m: isinstance(m, RangeVar))

    return _has_node(predicate, reads_relation)


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
        # function name — qualified and bare — -> its owners; and by
        # qualified name alone, for naming the owned function
        self.fn_owners: dict[str, set[str]] = {}
        self.fn_owners_by_name: dict[str, set[str]] = {}
        # name — qualified and bare — -> the user-defined functions it may be
        self.functions: dict[str, list[UserFunction]] = {}
        for fn in schema.user_functions or ():
            for key in (fn.qualified_name, fn.qualified_name.rsplit(".", 1)[-1]):
                self.functions.setdefault(key, []).append(fn)
        # schema -> who can create objects in it (none known when not captured)
        self.creators: dict[str, set[str]] = {}
        for sch, grantee in schema.schema_create or ():
            self.creators.setdefault(sch, set()).add(grantee)
        owner_pairs = schema.function_owners
        if owner_pairs is None and schema.user_functions is not None:
            owner_pairs = tuple((f.qualified_name, f.owner) for f in schema.user_functions)
        for qname, owner in owner_pairs or ():
            self.fn_owners_by_name.setdefault(qname, set()).add(owner)
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
        if base.status != "proven":
            return base
        if name == "PUBLIC":
            written = self._identity_reads_writable({"PUBLIC"}, table)
            if written:
                return CellProof("unknown", model, detail=(
                    f"the filter's identity comes from {written[0]}(), which {written[1]} "
                    "— the session may be able to change who it is taken to be"
                ))
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
                what = ("which bypasses RLS and reads every row (see SEC029)"
                        if other.status == "exempt"
                        else f"whose read is {other.status.upper()}")
                return CellProof("unknown", model, detail=(
                    f"the session can SET ROLE {target}, {what}"
                ))
        readers = {name} | targets
        # A door pgrls cannot trace runs whatever its owner can, DDL included
        # (measured: ALTER TABLE … NO FORCE, CREATE OR REPLACE FUNCTION through
        # a SECURITY DEFINER function's dynamic SQL) — for any session.
        door_owners = self._door_owners(readers)
        written = self._identity_reads_writable(readers, table, login, door_owners)
        if written:
            return CellProof("unknown", model, detail=(
                f"the filter's identity comes from {written[0]}(), which {written[1]} "
                "— the session may be able to change who it is taken to be"
            ))
        if not login:
            # Reached through a gateway that runs only the API's queries: it
            # changes no schema object itself (a login member's own column
            # does); a door it can open still acts as that door's owner.
            return self._redefinable(name, readers, door_owners, table, model) or base
        granting = sorted(({name} | targets) & set(self.schema.self_granting_roles or ()))
        if granting:
            who = (f"{granting[0]} has" if granting[0] == name
                   else f"the session can SET ROLE {granting[0]}, which has")
            return CellProof("unknown", model, detail=(
                f"{who} CREATEROLE on a server before Postgres 16: it can grant "
                "itself any non-superuser role, a BYPASSRLS one included"
            ))
        return self._redefinable(name, readers, readers | door_owners, table, model) or base

    def _door_owners(self, roles: set[str]) -> set[str]:
        """The owners of every untraced door `roles` can open, and of the
        untraced doors those owners can open in turn."""
        out: set[str] = set()
        todo = sorted(roles)
        seen = set(todo)
        while todo:
            for door in self.reach_of(todo.pop()).untraced:
                if door.owner and door.owner not in out:
                    out.add(door.owner)
                    if door.owner not in seen:
                        seen.add(door.owner)
                        todo.append(door.owner)
        return out

    def _redefinable(
        self, name: str, readers: set[str], actors: set[str], table: Table,
        model: ThreatModel,
    ) -> CellProof | None:
        """Whether `actors` — the session's roles, and the owners of untraced
        doors it can open — can change what a filter `readers` read the table
        through computes:

        * it owns a user-defined function: CREATE OR REPLACE changes it, and
          it may sit behind a call, an operator or a cast the filter uses
          (measured: a redefined auth.uid(), and an operator's function);
        * it can create objects in a schema while the filter calls a
          user-defined function, whose body resolves names at run time
          through a search_path the session can put that schema on
          (measured).
        """
        if not actors:
            return None
        owned = sorted(f for f, owners in self.fn_owners_by_name.items() if owners & actors)
        holders = self._privilege_holders(actors)
        creates = sorted(s for s, who in self.creators.items() if who & holders)
        on_database = bool(set(self.schema.database_create or ()) & holders)
        if on_database:
            creates.insert(0, "")
        if not owned and not creates:
            return None
        for role in sorted(readers):
            predicate = self.reach_of(role).cells[(table.qualified_name, "SELECT")].predicate
            if not predicate:
                continue
            if owned:
                return CellProof("unknown", model, detail=(
                    f"the session owns the user-defined function {owned[0]}(): "
                    "redefining it changes any filter that reaches it — through "
                    "a call, an operator or a cast"
                ))
            called = sorted(f for f in _called_functions(predicate) if f in self.functions)
            if called:
                where = ("a schema of its own (it holds CREATE on the database)"
                         if not creates[0] else f"schema {creates[0]}")
                return CellProof("unknown", model, detail=(
                    f"the session can create objects in {where}, and the filter "
                    f"calls {called[0]}(), whose body can resolve names through the "
                    "session's search_path"
                    + ("; REVOKE CREATE ON SCHEMA public FROM PUBLIC lifts this"
                       if creates[0] == "public" else "")
                ))
        return None

    def _privilege_holders(self, session: set[str]) -> set[str]:
        """The grantees whose privileges some role of `session` holds — itself,
        its INHERIT closure, and PUBLIC."""
        from pgrls.verify import _inherit_closure  # noqa: PLC0415

        out = {"PUBLIC"}
        for role in session:
            out |= _inherit_closure(self.schema, role) or {role}
        return out

    def _shadowable(
        self, fname: str, path: str | None = None, seen: frozenset[str] = frozenset(),
    ) -> str | None:
        """Why a call to `fname` can be made to read a session's own temp table
        instead of the one meant, or None. `path` is the search_path the call
        runs under — None for the session's own, which puts pg_temp first.

        A body resolves a bare relation name through its pinned search_path,
        or else its caller's; pg_temp comes first unless the path names it. So
        a body's own references are safe only when they are pre-parsed (BEGIN
        ATOMIC) or the path ends in pg_temp — and every function it calls is
        judged the same way, under the path it inherits. Any bare relation name
        counts, a CTE's included (scoping is not modelled). A body that cannot
        be read is assumed unsafe. Types resolve through pg_temp too, but only
        a superuser can create the base type that would compute differently."""
        for fn in self.functions.get(fname, ()):
            key = f"{fn.qualified_name}@{path}"
            if key in seen or fn.language in ("c", "internal"):
                continue
            effective = fn.search_path if fn.search_path is not None else path
            safe_path = effective is not None and _pg_temp_last(effective)
            if fn.body is None or (fn.language != "sql" and not fn.atomic):
                if not safe_path:
                    return f"{fn.qualified_name}() has a {fn.language} body pgrls cannot read"
                # A body pgrls cannot read may still call a function whose
                # own pinned path is unsafe; it cannot tell which.
                return (f"{fn.qualified_name}() has a {fn.language} body pgrls cannot "
                        "follow into the functions it calls")
            if not fn.atomic and not safe_path:
                refs = _unqualified_relations(fn.body)
                if refs is None:
                    return f"the body of {fn.qualified_name}() does not parse"
                if refs:
                    return (f"{fn.qualified_name}() reads {sorted(refs)[0]} without a schema "
                        "(a CTE's name counts: its scope is not modelled)")
            for inner in sorted(_called_functions(fn.body, statement=True)):
                why = self._shadowable(inner, effective, seen | {key})
                if why:
                    return why
        return None

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
            opaque = self._opaque_helpers(direct.predicate or "")
            if verdict == "leak" and witness is None and opaque:
                # No row characterizes it and it rests on a helper the prover
                # cannot see into, so it is not certain.
                return parent_leak or CellProof("unknown", model, detail=(
                    f"the filter may admit rows, depending on what {opaque[0]}() "
                    "returns — if it is your auth helper, name it with "
                    "--auth-function"
                ))
            other = (self._other_session_value(direct.predicate or "")
                     if model == "cross-tenant" and witness is None else None)
            if verdict == "leak" and other:
                return parent_leak or CellProof("unknown", model, detail=(
                    f"the filter may admit another tenant's rows depending on {other}, "
                    "a session value besides the tenant identity that the prover "
                    "leaves free — a real session may never hold it"
                ))
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
            opaque = self._opaque_helpers(predicate)
            what = f"{opaque[0]}()" if opaque else "a function"
            return CellProof("unknown", model, detail=(
                f"the filter calls {what}, which the prover cannot see into — if it "
                "is your auth helper, name it with --auth-function"
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
            header = self._client_controlled(predicate)
            if header:
                return CellProof("unknown", model, detail=header)
        if login and predicate is not None:
            # A raw SQL session: it can SET any setting, create temp tables,
            # and put any schema it can create in on its search_path.
            forged = self._settable_identity(predicate)
            if forged:
                return CellProof("unknown", model, detail=(
                    f"a session that logs in as this role runs its own SQL and can "
                    f"set what {forged} reads — another tenant's identity, or none"
                ))
            for fname in sorted(_called_functions(predicate)):
                why = self._shadowable(fname)
                if why:
                    return CellProof("unknown", model, detail=(
                        f"the filter calls {fname}(): {why} under a search_path "
                        "that does not end in pg_temp — a session's own temp table "
                        "could take its place"
                    ))
        for door in self.reach_of(name).untraced:
            if self._owner_reaches(door.owner, table):
                return CellProof("unknown", model, detail=(
                    f"{door.door} is an untraced door this role can open, and "
                    f"its owner {door.owner or '(unknown)'} reaches the table"
                ))
        if (
            model == "cross-tenant" and predicate is not None
            and _calls_current_setting(predicate)
            and self.prove("anon", predicate, states)[0] == "leak"
        ):
            return CellProof("unknown", model, detail=(
                "isolated for a session that carries its identity; one that "
                "leaves the setting the filter reads unset reads rows"
            ))
        return proven

    def _identity_reads_writable(
        self, session: set[str], table: Table, login: bool = False,
        door_owners: set[str] | None = None,
    ) -> tuple[str, str] | None:
        """(auth function, what it reads) when an auth function a filter of the
        session's read of `table` calls reads — in its body, or a function that
        body calls — a table some role of the session (it, or one it can SET
        ROLE to) can INSERT, UPDATE or DELETE: the prover takes the function's
        value as the session's identity, but the session can rewrite what it
        reads (measured, through an ordinary API write too). A view counts as
        the tables under it. A body pgrls cannot read, or a relation it
        cannot resolve, counts as any table — unsafe unless the role can write
        none. For a login session, a relation it owns counts too — the owner
        can lift FORCE, or replace a view's rule (measured)."""
        from pgrls.verify import DEFAULT_AUTH_FUNCTIONS  # noqa: PLC0415

        auth = self.auth if self.auth is not None else set(DEFAULT_AUTH_FUNCTIONS)
        bare = {a.rsplit(".", 1)[-1] for a in auth}
        reaches = [self.reach_of(r) for r in sorted(session)]
        owners = self._privilege_holders(session) - {"PUBLIC"} if login else set()
        if door_owners:
            owners |= self._privilege_holders(door_owners) - {"PUBLIC"}

        def writable(t: Table) -> bool:
            if any(reach.cells[(t.qualified_name, cmd)].verdict != "denied"
                   for reach in reaches for cmd in ("INSERT", "UPDATE", "DELETE")):
                return True
            # A door pgrls cannot trace may write it as its owner (measured:
            # a SECURITY DEFINER function's dynamic UPDATE).
            return any(self._owner_writes(door.owner, t)
                       for reach in reaches for door in reach.untraced)

        called = set()
        for reach in reaches:
            predicate = reach.cells[(table.qualified_name, "SELECT")].predicate
            if predicate:
                called |= _called_functions(predicate)
        for fname in sorted(called):
            if fname not in auth and fname.rsplit(".", 1)[-1] not in bare:
                continue
            read = self._relations_read(fname)
            if read is None:
                # Every non-system schema is introspected, so "any table it
                # could read" is one of these.
                anything = next((t for t in self.schema.tables if writable(t)), None)
                if anything is not None:
                    return fname, (f"has a body pgrls cannot read, and the session can "
                                   f"write {anything.qualified_name}")
                continue
            resolved = self._resolve(read)
            if isinstance(resolved, str):
                return fname, (f"reads {resolved}, which pgrls cannot resolve, so it "
                               "cannot rule out that the session writes it")
            tables, views = resolved
            owned = [r.qualified_name for r in tables if r.owner in owners] + [
                v.qualified_name for v in views if v.owner in owners]
            if owned:
                return fname, (f"reads {owned[0]}, which the session owns — it can "
                               "lift FORCE or replace what it returns")
            for t in tables:
                if writable(t):
                    return fname, f"reads {t.qualified_name}, which the session can write"
        return None

    def _relations_read(self, fname: str, seen: frozenset[str] = frozenset()) -> set[str] | None:
        """Every relation name (as written) the body of `fname` and the
        user-defined functions it calls read — a bare name a body defines as a
        CTE left out of that body's — or None when a body cannot be read
        (another language, dynamic SQL, a parse error)."""
        from pglast.ast import CommonTableExpr, RangeVar  # noqa: PLC0415

        out: set[str] = set()
        for fn in self.functions.get(fname, ()):
            if fn.qualified_name in seen or fn.language in ("c", "internal"):
                continue
            stmts = _body_statements_of(fn)
            if stmts is None:
                return None
            rels: set[str] = set()
            ctes: set[str] = set()

            def match(n: Any) -> bool:
                if isinstance(n, RangeVar):
                    rels.add(f"{n.schemaname}.{n.relname}" if n.schemaname else n.relname)
                if isinstance(n, CommonTableExpr):
                    ctes.add(n.ctename)
                return False

            _has_node_in(stmts, match)
            out |= rels - ctes
            for inner in sorted(_names_called(stmts)):
                more = self._relations_read(inner, seen | {fn.qualified_name})
                if more is None:
                    return None
                out |= more
        return out

    def _resolve(self, rels: set[str]) -> tuple[list[Table], list[View]] | str:
        """The tables relation names read — a view's base tables for a view,
        and the views themselves; a bare name as every table or view of that
        name. A name that resolves to nothing pgrls captured is returned
        instead (a system catalog excepted)."""
        tables: dict[str, Table] = {}
        views: dict[str, View] = {}
        for rel in rels:
            schema_name, _, relname = rel.rpartition(".")
            if schema_name in ("pg_catalog", "information_schema") or (
                not schema_name and relname.startswith("pg_")
            ):
                continue
            found = False
            for t in self.schema.tables:
                if t.name == relname and (not schema_name or t.schema == schema_name):
                    tables[t.qualified_name] = t
                    found = True
            for v in self.schema.views:
                if v.name == relname and (not schema_name or v.schema == schema_name):
                    found = True
                    views[v.qualified_name] = v
                    for vs, vn in v.references:
                        base = self.tables.get(f"{vs}.{vn}")
                        if base is None:
                            return f"{vs}.{vn}"
                        tables[base.qualified_name] = base
            if not found:
                return rel
        # A query on a parent returns its inheritance children's and
        # partitions' rows too (measured: an insert into a writable child
        # changed what the parent read). ONLY is not distinguished.
        todo = list(tables)
        while todo:
            parent = todo.pop()
            ps, _, pn = parent.partition(".")
            for t in self.schema.tables:
                if t.qualified_name in tables:
                    continue
                if t.partition_of == (ps, pn) or (ps, pn) in t.inherits:
                    tables[t.qualified_name] = t
                    todo.append(t.qualified_name)
        return list(tables.values()), list(views.values())

    def _client_controlled(self, predicate: str) -> str | None:
        """A request header or cookie setting the filter reads — directly, or
        in the body of a function it calls or one those call — whose value
        the HTTP client chooses; or a body pgrls cannot read, which may."""
        found: list[str] = []

        def match(n: Any) -> bool:
            name = _client_setting(n)
            if name:
                found.append(name)
            return False

        _has_node(predicate, match)
        if found:
            return _client_reason(found[0], None)
        for fname in sorted(_called_functions(predicate)):
            why = self._client_in_body(fname)
            if why:
                return why
        return None

    def _client_in_body(self, fname: str, seen: frozenset[str] = frozenset()) -> str | None:
        found: list[str] = []

        def match(n: Any) -> bool:
            name = _client_setting(n)
            if name:
                found.append(name)
            return False

        for fn in self.functions.get(fname, ()):
            if fn.qualified_name in seen or fn.language in ("c", "internal"):
                continue
            stmts = _body_statements_of(fn)
            if stmts is None:
                return (f"the filter reaches {fn.qualified_name}(), whose body pgrls "
                        "cannot read; it may read a request header or cookie the HTTP "
                        "client chooses through PostgREST")
            _has_node_in(stmts, match)
            if found:
                return _client_reason(found[0], fn.qualified_name)
            for inner in sorted(_names_called(stmts)):
                why = self._client_in_body(inner, seen | {fn.qualified_name})
                if why:
                    return why
        return None

    def _other_session_value(self, predicate: str) -> str | None:
        """A session value `predicate` reads outside its tenant binding — a
        setting or an auth function not compared with a tenant column — or
        None."""
        from pglast.ast import A_Expr, ColumnRef, FuncCall, Node  # noqa: PLC0415

        from pgrls.verify import DEFAULT_AUTH_FUNCTIONS  # noqa: PLC0415

        node = parse_expr(predicate)
        if node is None:
            return None
        auth = self.auth if self.auth is not None else set(DEFAULT_AUTH_FUNCTIONS)
        bare = {a.rsplit(".", 1)[-1] for a in auth}

        def is_axis_column(n: Any) -> bool:
            if not isinstance(n, ColumnRef):
                return False
            last = getattr(n.fields[-1], "sval", "") if n.fields else ""
            return str(last).lower() in self.axis

        def session_value(n: Any) -> str | None:
            if not isinstance(n, FuncCall):
                return None
            f = ".".join(getattr(part, "sval", "") for part in n.funcname)
            if _is_current_setting(n):
                return "current_setting()"
            return f"{f}()" if (f in auth if "." in f else f in bare) else None

        def has_session_value(n: Any) -> bool:
            return _has_node_in(n, lambda m: session_value(m) is not None)

        def binds_tenant(n: Any) -> bool:
            """`tenant_col = <session value>` — not a fixed tenant like 'demo'."""
            if not (isinstance(n, A_Expr) and n.name
                    and getattr(n.name[-1], "sval", "") == "="):
                return False
            return ((is_axis_column(n.lexpr) and has_session_value(n.rexpr))
                    or (is_axis_column(n.rexpr) and has_session_value(n.lexpr)))

        found: list[str] = []

        def walk(n: Any) -> None:
            if found or n is None:
                return
            if isinstance(n, (list, tuple)):
                for item in n:
                    walk(item)
                return
            name = session_value(n)
            if name:
                found.append(name)
                return
            if isinstance(n, Node):
                for fld in n:
                    walk(getattr(n, fld, None))

        # A top-level OR branch that carries the tenant binding cannot leak
        # another tenant's row on its own; a session value in any other
        # branch is what a no-witness leak may rest on.
        try:
            for branch in _or_branches(node):
                if not _has_node_in(branch, binds_tenant):
                    walk(branch)
        except RecursionError:
            return "a value pgrls could not walk"
        return found[0] if found else None

    def _opaque_helpers(self, predicate: str) -> list[str]:
        """The functions `predicate` calls that are user-defined (captured, or
        named with a schema other than pg_catalog) and not auth functions —
        values the prover cannot see into."""
        from pgrls.verify import DEFAULT_AUTH_FUNCTIONS  # noqa: PLC0415

        auth = self.auth if self.auth is not None else set(DEFAULT_AUTH_FUNCTIONS)
        bare = {a.rsplit(".", 1)[-1] for a in auth}
        def is_auth(f: str) -> bool:  # a qualified call must name it exactly
            return f in auth if "." in f else f in bare

        return sorted(
            f for f in _called_functions(predicate)
            if not is_auth(f)
            and (f in self.functions
                 or ("." in f and not f.lower().startswith("pg_catalog.")))
        )

    def _settable_identity(self, predicate: str) -> str | None:
        """What in `predicate` reads state a session can set for itself — a
        setting, directly or in the body of a function it calls — or None. A
        default auth function whose body was not captured is taken to read
        the request's JWT claims from settings; so is any body pgrls cannot
        read."""
        if _calls_current_setting(predicate):
            return "current_setting()"
        for fname in sorted(_called_functions(predicate)):
            if self._reads_settings(fname):
                return f"{fname}()"
        return None

    def _reads_settings(self, fname: str, seen: frozenset[str] = frozenset()) -> bool:
        from pgrls.verify import DEFAULT_AUTH_FUNCTIONS  # noqa: PLC0415

        fns = self.functions.get(fname)
        if not fns:
            auth = self.auth if self.auth is not None else set(DEFAULT_AUTH_FUNCTIONS)
            bare = {a.rsplit(".", 1)[-1] for a in auth}
            return fname in auth or fname.rsplit(".", 1)[-1] in bare
        for fn in fns:
            if fn.qualified_name in seen or fn.language in ("c", "internal"):
                continue
            if fn.body is None or (fn.language != "sql" and not fn.atomic):
                return True
            if _has_node_in_sql(fn.body, _reads_session_state):
                return True
            if any(self._reads_settings(inner, seen | {fn.qualified_name})
                   for inner in _called_functions(fn.body, statement=True)):
                return True
        return False

    def _owns(self, name: str, table: Table) -> bool:
        """Whether `name` is the table's owner — and so can change its RLS. A
        member of the owner, inheriting or not, can SET ROLE to it: the SET
        ROLE gate in `cell` covers that."""
        return bool(table.owner) and name == table.owner

    def _owner_writes(self, owner: str, table: Table, seen: frozenset[str] = frozenset()) -> bool:
        """Whether `owner` can write `table` — itself, through its traced
        doors, or through an untraced door it can open in turn."""
        role = self.attrs.get(owner)
        if not owner or role is None or role.superuser or role.bypassrls:
            return True
        reach = self.reach_of(owner)
        if any(reach.cells[(table.qualified_name, cmd)].verdict != "denied"
               for cmd in ("INSERT", "UPDATE", "DELETE")):
            return True
        seen = seen | {owner}
        return any(door.owner not in seen and self._owner_writes(door.owner, table, seen)
                   for door in reach.untraced)

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
