"""`pgrls access` — who can reach which data, and by what path.

`pgrls verify` asks one narrow question — can an *anonymous* session read a
table's rows? — and proves the answer. This module asks the general one, for
every principal: which relations can each role ``SELECT``, which columns of
them, how (the privilege path), and which rows (the RLS outcome for that role).

Two levels of reach are reported separately because they fail independently:

* **privilege** — can the role issue ``SELECT`` at all without ``permission
  denied``? Decided by ownership, owner-equivalence (an ``INHERIT`` member of
  the owner), a table- or column-level ``SELECT`` grant to the role, to a role
  whose privileges it inherits, or to ``PUBLIC``, ``pg_read_all_data``, or
  superuser.
* **rows** — given privilege, which rows does RLS let through? ``all`` (RLS
  off, or the role is exempt), ``filtered`` (named permissive policies apply),
  ``none`` (RLS on and no permissive policy applies — default-deny), or
  ``undecided`` (the role graph was not captured, so which policies apply
  cannot be known).

Row reach is classified *structurally* — it names the policies that apply, it
does not prove what they admit. Whether a filter is actually tight is
`pgrls verify`'s question, and keeping the two apart keeps this module's
soundness surface small.

Every privilege and exemption rule here is the one `verify` already uses and
was measured live on PG16 (see `verify._role_reads_relation` and
`verify._anon_session_exempt`): BYPASSRLS escapes the policies but NOT the
privilege check; a ``NOINHERIT`` member holds none of the group's privileges;
``FORCE`` strips owner-based exemption but not superuser/BYPASSRLS.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from pgrls._render_common import (
    make_dispatcher,
    markdown_table,
    pluralize,
    render_text_table,
)
from pgrls.ast_utils import is_literal_true
from pgrls.formatters._common import safe_location
from typing import Any

from pgrls.model import Role, Schema, Table, View
from pgrls.rules.sec045 import _DEFAULT_PATTERNS, _is_pii
from pgrls.verify import (
    _anon_reachable_roles,
    _inherit_closure,
    _role_reads_relation,
)

PathKind = Literal[
    "superuser",
    "pg_read_all_data",
    "owner",
    "owner_member",
    "grant",
    "public_grant",
    "column_grant",
    "view",
]

RowReach = Literal["all", "filtered", "none", "undecided"]

# Commands whose permissive policies govern a SELECT. `ALL` covers every
# command, reads included.
_READ_COMMANDS = frozenset({"SELECT", "ALL"})


@dataclass(frozen=True)
class AccessPath:
    """One reason a principal can ``SELECT`` a relation.

    ``via`` names what the path runs through — the grantee role for a grant,
    the owner for owner-equivalence. ``columns`` is ``None`` for a path that
    reaches every column, or the specific columns a column grant covers.
    """

    kind: PathKind
    via: str | None = None
    columns: tuple[str, ...] | None = None
    # For a `view` path: every relation walked from the view the principal
    # opened down to the base table, in order.
    hops: tuple[str, ...] = ()


@dataclass(frozen=True)
class Access:
    """What one principal can read of one relation."""

    principal: str
    relation: str
    # None = every column; otherwise the union of the column grants.
    columns: tuple[str, ...] | None
    paths: tuple[AccessPath, ...]
    rows: RowReach
    # The permissive policies that apply, for `rows == "filtered"` (and the
    # USING-(true) one that makes it `all`).
    policies: tuple[str, ...] = ()
    # Why `rows == "all"` on an RLS-enabled table, or why it is undecided.
    reason: str | None = None
    # The reachable columns whose NAME matches SEC045's PII patterns — the
    # same matcher, so `access` and the lint rule agree on what "sensitive"
    # means. A name heuristic: an opaquely-named sensitive column is missed.
    sensitive: tuple[str, ...] = ()


@dataclass(frozen=True)
class AccessMap:
    principals: tuple[str, ...]
    accesses: tuple[Access, ...]
    # True when `schema.roles` was not captured and the principal set was
    # derived from grantees / owners / policy targets / membership endpoints.
    roles_derived: bool
    # False when `schema.role_memberships` was not captured: inherited
    # privileges and policy applicability through membership are unknown.
    graph_complete: bool


def _derived_roles(schema: Schema) -> tuple[Role, ...]:
    """Every role name the schema mentions, when no catalogue was captured.

    Sound for *reach*: a role absent from all of these holds no grant, owns
    nothing, is no policy's target and is in no membership edge, so it reaches
    nothing except through ``PUBLIC`` — which every derived role's analysis
    already includes. What is lost is the attributes: ``can_login`` is unknown
    (reported as True, since excluding a real entry point would hide reach) and
    superuser / BYPASSRLS come only from ``bypassrls_roles``.
    """
    names: set[str] = set()
    for t in schema.tables:
        if t.owner:
            names.add(t.owner)
        names.update(g.role for g in t.grants)
        names.update(cg.role for cg in t.column_grants)
        for p in t.policies:
            names.update(p.roles)
    for m in schema.role_memberships or ():
        names.update((m.member, m.role))
    attrs = {r.name: r for r in schema.bypassrls_roles}
    names.update(attrs)
    names.discard("PUBLIC")
    return tuple(
        Role(
            name=n,
            can_login=attrs[n].can_login if n in attrs else True,
            superuser=attrs[n].superuser if n in attrs else False,
            bypassrls=n in attrs,
        )
        for n in sorted(names)
    )


def _privilege_paths(
    schema: Schema, role: Role, table: Table, closure: frozenset[str] | None
) -> tuple[list[AccessPath], bool]:
    """The privilege paths by which `role` can SELECT `table`, and whether the
    answer is complete (False only when the membership graph is missing AND no
    path that needs no graph decided it)."""
    if role.superuser:
        return [AccessPath("superuser")], True
    held = closure if closure is not None else frozenset({role.name})
    paths: list[AccessPath] = []
    if "pg_read_all_data" in held and role.name != "pg_read_all_data":
        paths.append(AccessPath("pg_read_all_data", via="pg_read_all_data"))
    if table.owner and table.owner == role.name:
        paths.append(AccessPath("owner", via=role.name))
    elif table.owner and table.owner in held:
        paths.append(AccessPath("owner_member", via=table.owner))
    for g in table.grants:
        if "SELECT" not in g.privileges:
            continue
        if g.role == "PUBLIC":
            paths.append(AccessPath("public_grant", via="PUBLIC"))
        elif g.role in held:
            paths.append(AccessPath("grant", via=g.role))
    by_grantee: dict[str, list[str]] = {}
    for cg in table.column_grants:
        if "SELECT" in cg.privileges and (cg.role == "PUBLIC" or cg.role in held):
            by_grantee.setdefault(cg.role, []).append(cg.column)
    for grantee in sorted(by_grantee):
        paths.append(
            AccessPath(
                "column_grant", via=grantee, columns=tuple(sorted(set(by_grantee[grantee])))
            )
        )
    # Without the graph, a grant to some OTHER role this one might inherit
    # cannot be ruled out — unless a path that needs no graph already decided.
    complete = closure is not None or bool(paths)
    return paths, complete


def _reachable_columns(paths: list[AccessPath]) -> tuple[str, ...] | None:
    """None if any path reaches every column, else the union of column grants."""
    if any(p.columns is None for p in paths):
        return None
    cols: set[str] = set()
    for p in paths:
        cols.update(p.columns or ())
    return tuple(sorted(cols))


def _row_reach(
    schema: Schema,
    role: Role,
    table: Table,
    paths: list[AccessPath],
) -> tuple[RowReach, tuple[str, ...], str | None]:
    """Which rows RLS lets `role` read, structurally."""
    if not table.rls_enabled:
        return "all", (), "RLS is off"
    if role.superuser:
        return "all", (), "superuser — RLS never applies"
    if role.bypassrls:
        return "all", (), "BYPASSRLS — the policies are skipped"
    owns = any(p.kind in ("owner", "owner_member") for p in paths)
    if owns and not table.force_rls:
        return "all", (), "holds the owner's privileges and RLS is not FORCE'd"
    # Policy applicability follows EVERY membership edge (is_member_of_role),
    # INHERIT or not — unlike privileges, which follow INHERIT only.
    applies_to, complete = _anon_reachable_roles(schema, {role.name})
    permissive = [
        p for p in table.policies
        if p.permissive and p.command in _READ_COMMANDS
    ]
    restrictive = [
        p for p in table.policies
        if not p.permissive and p.command in _READ_COMMANDS
    ]
    def _applies(p: object) -> bool | None:
        roles = set(getattr(p, "roles", ()) or ("PUBLIC",))
        if roles & applies_to:
            return True
        return None if not complete else False

    applicable = [p for p in permissive if _applies(p) is True]
    unknown = [p for p in permissive if _applies(p) is None]
    if not applicable and unknown:
        return (
            "undecided", (),
            "role-membership graph not captured; cannot tell whether "
            + ", ".join(sorted(p.name for p in unknown)) + " apply",
        )
    if not applicable:
        return "none", (), "RLS is on and no permissive SELECT policy applies"
    names = tuple(sorted(p.name for p in applicable))
    floors = [p for p in restrictive if _applies(p) is not False]
    open_ = [p for p in applicable if p.using_ast is not None and is_literal_true(p.using_ast)]
    if open_ and not floors:
        return (
            "all", names,
            f"permissive policy {sorted(p.name for p in open_)[0]!r} is USING (true)",
        )
    return "filtered", names, None


# One reach result for a (principal, table), before merging: the paths that
# produce it, the columns they reach (None = every column), and the row reach.
_Reach = tuple[list[AccessPath], "tuple[str, ...] | None", RowReach, tuple[str, ...], "str | None"]


def _owner_as_role(view: View, attrs: dict[str, Role]) -> Role:
    """The view's owner as a principal. The catalogue is authoritative; without
    it, fall back to the view's own flags (`owner_bypasses_rls` is set for a
    superuser OR a BYPASSRLS owner, so split it on `owner_is_superuser`)."""
    if view.owner in attrs:
        return attrs[view.owner]
    return Role(
        name=view.owner,
        can_login=False,
        superuser=view.owner_is_superuser,
        bypassrls=view.owner_bypasses_rls and not view.owner_is_superuser,
    )


def _view_doors(
    schema: Schema,
    role: Role,
    closure: frozenset[str] | None,
    attrs: dict[str, Role],
) -> dict[str, list[_Reach]]:
    """Base tables `role` reaches THROUGH a definer view, keyed by table.

    Each hop picks its own effective user, exactly as `verify`'s reachability
    walk (every rule below was measured on PG16 there):

    * a `security_invoker = false` view runs as its OWNER;
    * a `security_invoker = true` view RESETS the effective user to the session
      user — the principal — rather than inheriting an enclosing definer;
    * every hop must be readable by the effective user, or the path is dead
      (measured: `permission denied for view inner`, no leak);
    * a materialized-view hop is `undecided`: its rows were captured at REFRESH
      under the matview owner's RLS context, which is not modeled.

    An invoker chain that reaches a base table adds nothing — that read uses
    the principal's own privileges, already reported as direct reach. Only a
    definer hop opens a new door, and its rows are the OWNER's row reach.
    """
    views_by_key = {(v.schema, v.name): v for v in schema.views}
    tables_by_key = {(t.schema, t.name): t for t in schema.tables}
    found: dict[str, list[_Reach]] = {}

    def record(table: Table, path: AccessPath, rows: RowReach,
               pols: tuple[str, ...], reason: str | None) -> None:
        found.setdefault(table.qualified_name, []).append(
            ([path], None, rows, pols, reason)
        )

    def caller_reads(rel: Any) -> bool | None:
        paths, complete = _privilege_paths(schema, role, rel, closure)
        if paths:
            return True
        return None if not complete else False

    def tables_beneath(v: View, seen: frozenset[tuple[str, str]]) -> list[Table]:
        out: list[Table] = []
        for ref in v.direct_references or v.references:
            if ref in seen:
                continue
            if ref in tables_by_key:
                out.append(tables_by_key[ref])
            elif ref in views_by_key:
                out.extend(tables_beneath(views_by_key[ref], seen | {ref}))
        return out

    def undecided(v: View, entry: View, hops: tuple[str, ...], why: str,
                  seen: frozenset[tuple[str, str]]) -> None:
        for t in tables_beneath(v, seen):
            record(
                t,
                AccessPath("view", via=entry.qualified_name,
                           hops=hops + (t.qualified_name,)),
                "undecided", (), why,
            )

    def walk(view: View, hops: tuple[str, ...], entry: View,
             seen: frozenset[tuple[str, str]]) -> None:
        eff = None if view.security_invoker else view
        for ref in view.direct_references or view.references:
            child = views_by_key.get(ref)
            if child is not None:
                if ref in seen:
                    continue
                readable = (
                    _role_reads_relation(schema, eff, child)
                    if eff is not None
                    else caller_reads(child)
                )
                if readable is False:
                    continue  # broken intermediate hop: dead path
                child_hops = hops + (child.qualified_name,)
                if child.is_materialized:
                    undecided(child, entry, child_hops, (
                        f"{child.qualified_name} is a materialized view: its rows "
                        "were captured at REFRESH under its owner's RLS context"
                    ), seen | {ref})
                    continue
                if readable is None:
                    undecided(child, entry, child_hops, (
                        "role-membership graph not captured; cannot decide "
                        f"whether the path can read {child.qualified_name}"
                    ), seen | {ref})
                    continue
                walk(child, child_hops, entry, seen | {ref})
                continue
            table = tables_by_key.get(ref)
            if table is None or eff is None:
                continue  # unknown relation, or the principal's own direct read
            path = AccessPath("view", via=entry.qualified_name,
                              hops=hops + (table.qualified_name,))
            reads = _role_reads_relation(schema, eff, table)
            if reads is False:
                continue  # the owner cannot read it: permission denied
            if reads is None:
                record(table, path, "undecided", (), (
                    f"role-membership graph not captured; cannot decide whether "
                    f"{eff.owner} can read {table.qualified_name}"
                ))
                continue
            owner = _owner_as_role(eff, attrs)
            owner_paths, _ = _privilege_paths(
                schema, owner, table, _inherit_closure(schema, owner.name)
            )
            rows, pols, why = _row_reach(schema, owner, table, owner_paths)
            record(table, path, rows, pols, (
                f"through definer view {eff.qualified_name}, as its owner "
                f"{eff.owner}" + (f" — {why}" if why else "")
            ))

    for v in sorted(schema.views, key=lambda v: v.qualified_name):
        opens = caller_reads(v)
        if opens is False:
            continue
        start = frozenset({(v.schema, v.name)})
        if v.is_materialized:
            undecided(v, v, (v.qualified_name,), (
                f"{v.qualified_name} is a materialized view: its rows were "
                "captured at REFRESH under its owner's RLS context"
            ), start)
            continue
        if opens is None:
            undecided(v, v, (v.qualified_name,), (
                "role-membership graph not captured; cannot decide whether "
                f"{role.name} can open {v.qualified_name}"
            ), start)
            continue
        walk(v, (v.qualified_name,), v, start)
    return found


# Widest-first. `undecided` outranks `filtered`: a path we cannot bound might
# admit every row, and a security report must not let a known partial read
# mask an unbounded one.
_ROW_RANK: dict[str, int] = {"all": 3, "undecided": 2, "filtered": 1, "none": 0}


def _merge(reaches: list[_Reach]) -> _Reach:
    paths: list[AccessPath] = []
    for r in reaches:
        paths.extend(r[0])
    cols: tuple[str, ...] | None
    if any(r[1] is None for r in reaches):
        cols = None
    else:
        cols = tuple(sorted({c for r in reaches for c in (r[1] or ())}))
    widest = max(reaches, key=lambda r: _ROW_RANK[r[2]])
    pols = tuple(sorted({p for r in reaches for p in r[3]}))
    return paths, cols, widest[2], pols, widest[4]


def _sensitive(table: Table, columns: tuple[str, ...] | None) -> tuple[str, ...]:
    """The reachable columns whose name matches SEC045's PII patterns."""
    reachable = table.columns if columns is None else columns
    return tuple(sorted(c for c in reachable if _is_pii(c, _DEFAULT_PATTERNS)))


def build_access_map(
    schema: Schema,
    *,
    principals: set[str] | None = None,
    include_nologin: bool = False,
) -> AccessMap:
    """Map every principal's read access across the schema's tables.

    `principals` restricts the report to named roles. By default only roles
    that can log in are reported — the real entry points; a NOLOGIN group is
    reachable only through membership, which every login role's analysis
    already follows. `include_nologin` reports every role.
    """
    derived = schema.roles is None
    catalogue = _derived_roles(schema) if derived else schema.roles or ()
    graph_complete = schema.role_memberships is not None
    chosen = [
        r for r in catalogue
        if (principals is None or r.name in principals)
        and (include_nologin or r.can_login or (principals is not None))
    ]
    attrs = {r.name: r for r in catalogue}
    tables_by_q = {t.qualified_name: t for t in schema.tables}
    accesses: list[Access] = []
    for role in sorted(chosen, key=lambda r: r.name):
        closure = _inherit_closure(schema, role.name)
        per_table: dict[str, list[_Reach]] = {}
        for table in schema.tables:
            paths, complete = _privilege_paths(schema, role, table, closure)
            if paths:
                rows, policies, reason = _row_reach(schema, role, table, paths)
                per_table.setdefault(table.qualified_name, []).append(
                    (paths, _reachable_columns(paths), rows, policies, reason)
                )
            elif not complete:
                per_table.setdefault(table.qualified_name, []).append((
                    [], None, "undecided", (),
                    "role-membership graph not captured; a grant to a role "
                    "this one inherits cannot be ruled out",
                ))
        for qname, reaches in _view_doors(schema, role, closure, attrs).items():
            per_table.setdefault(qname, []).extend(reaches)
        for qname in sorted(per_table):
            paths, cols, rows, policies, reason = _merge(per_table[qname])
            accesses.append(
                Access(
                    role.name,
                    qname,
                    cols,
                    tuple(paths),
                    rows,
                    policies,
                    reason,
                    _sensitive(tables_by_q[qname], cols),
                )
            )
    return AccessMap(
        principals=tuple(sorted(r.name for r in chosen)),
        accesses=tuple(accesses),
        roles_derived=derived,
        graph_complete=graph_complete,
    )


# --- rendering ---------------------------------------------------------------


def _path_label(p: AccessPath, principal: str) -> str:
    if p.kind == "superuser":
        return "superuser"
    if p.kind == "pg_read_all_data":
        return "pg_read_all_data"
    if p.kind == "owner":
        return "owner"
    if p.kind == "owner_member":
        return f"member of owner {p.via}"
    if p.kind == "public_grant":
        return "PUBLIC grant"
    if p.kind == "column_grant":
        return "column grant" if p.via == principal else f"column grant via {p.via}"
    if p.kind == "view":
        return "view " + " → ".join(p.hops) if p.hops else f"view {p.via}"
    return "grant" if p.via == principal else f"grant via {p.via}"


def _rows_label(a: Access) -> str:
    if a.rows == "filtered":
        return f"filtered ({', '.join(a.policies)})"
    return a.rows


def _via(a: Access) -> str:
    return "; ".join(_path_label(p, a.principal) for p in a.paths) or "-"


def _cols(a: Access) -> str:
    return "all" if a.columns is None else ", ".join(a.columns)


def _caveats(amap: AccessMap) -> list[str]:
    out = []
    if amap.roles_derived:
        out.append(
            "No role catalogue was captured (pre-v27 snapshot or offline SQL), so "
            "principals were derived from grantees, owners and policy targets — "
            "a role that appears nowhere is not listed, and login/superuser "
            "attributes are approximate."
        )
    if not amap.graph_complete:
        out.append(
            "No role-membership graph was captured, so privileges inherited "
            "through membership are unknown — those relations are `undecided`, "
            "never reported as unreachable."
        )
    return out


def _exposures(amap: AccessMap) -> list[tuple[str, str, Access]]:
    """(relation, column, access) for every sensitive column a principal can
    reach with at least some rows."""
    return sorted(
        (
            (a.relation, col, a)
            for a in amap.accesses
            if a.rows != "none"
            for col in a.sensitive
        ),
        key=lambda x: (x[0], x[1], x[2].principal),
    )


def render_text(amap: AccessMap) -> str:
    n_p, n_rel = len(amap.principals), len({a.relation for a in amap.accesses})
    lines = [
        f"pgrls access — {n_p} {pluralize(n_p, 'principal')}, "
        f"{n_rel} reachable {pluralize(n_rel, 'relation')}",
        "",
    ]
    exposures = _exposures(amap)
    if exposures:
        lines.append("Sensitive columns reachable:")
        rows = [
            [
                safe_location(f"{rel}.{col}"),
                safe_location(a.principal),
                _rows_label(a),
                _via(a),
            ]
            for rel, col, a in exposures
        ]
        lines.extend("  " + ln for ln in render_text_table(
            ("COLUMN", "PRINCIPAL", "ROWS", "VIA"), rows
        ))
        lines.append("")
    if amap.accesses:
        rows = [
            [
                safe_location(a.principal),
                safe_location(a.relation),
                _cols(a),
                _rows_label(a),
                _via(a),
            ]
            for a in amap.accesses
        ]
        lines.extend(render_text_table(
            ("PRINCIPAL", "RELATION", "COLUMNS", "ROWS", "VIA"), rows
        ))
    else:
        lines.append("No principal can read any relation in the scanned schemas.")
    for c in _caveats(amap):
        lines.extend(["", f"note: {c}"])
    return "\n".join(lines) + "\n"


def _access_json(a: Access) -> dict[str, object]:
    return {
        "principal": a.principal,
        "relation": a.relation,
        "columns": list(a.columns) if a.columns is not None else None,
        "rows": a.rows,
        "policies": list(a.policies),
        "reason": a.reason,
        "sensitive_columns": list(a.sensitive),
        "paths": [
            {
                "kind": p.kind,
                "via": p.via,
                "columns": list(p.columns) if p.columns is not None else None,
            }
            for p in a.paths
        ],
    }


def render_json(amap: AccessMap) -> str:
    return json.dumps(
        {
            "principals": list(amap.principals),
            "roles_derived": amap.roles_derived,
            "graph_complete": amap.graph_complete,
            "accesses": [_access_json(a) for a in amap.accesses],
        },
        indent=2,
    ) + "\n"


def _md(text: str) -> str:
    return safe_location(text).replace("|", "\\|")


def render_markdown(amap: AccessMap) -> str:
    n_p = len(amap.principals)
    exposures = _exposures(amap)
    summary = (
        f"{n_p} {pluralize(n_p, 'principal')}, {len(amap.accesses)} "
        f"{pluralize(len(amap.accesses), 'access', 'accesses')}; {len(exposures)} sensitive "
        f"{pluralize(len(exposures), 'column exposure')}."
    )
    for c in _caveats(amap):
        summary += f"\n\n> **Note:** {c}"
    body = [
        f"| `{_md(a.principal)}` | `{_md(a.relation)}` | {_md(_cols(a))} "
        f"| {_md(_rows_label(a))} | {_md(_via(a))} |"
        for a in amap.accesses
    ] or ["| — | — | — | — | — |"]
    return markdown_table(
        heading="## pgrls access",
        summary=summary,
        header_row="| Principal | Relation | Columns | Rows | Via |",
        separator_row="|---|---|---|---|---|",
        body_rows=body,
    )


render, ACCESS_FORMATS = make_dispatcher({
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
})
