"""Effective tenant-isolation proof for `pgrls verify`.

Where `pgrls lint` *flags* a suspicious policy (SEC004 / SEC038) and `pgrls
matrix` *summarizes* who-can-read-what, `pgrls verify` **proves** — with Z3 —
a concrete safety property and hands back a counterexample when it fails. Five
complementary threat models (`--mode`):

* ``anon`` (default) — for every RLS-protected table, can an *anonymous*
  session read any row? Two anonymous sessions are modelled and a leak under
  either is a leak: the JWT-less connection (every auth function —
  auth.uid()/role()/jwt(), current_setting(...) — NULL) and the Supabase
  anon-key caller (``auth.role()`` = 'anon', ``auth.jwt()`` non-null,
  ``auth.uid()`` NULL).
* ``cross-tenant`` — can a session authenticated as *one* tenant read a
  *different* tenant's row? For the policy's own tenant-scoping equality
  ``<column> = <session identity>``, a row is exposed iff it can be visible
  while ``column`` differs from the session's tenant.
* ``write`` — can a session authenticated as *one* tenant **write** (INSERT,
  UPDATE or DELETE) a row of a *different* tenant? Same satisfiability question
  as ``cross-tenant``, but proven over BOTH gates of each write policy: the
  new-row gate (``WITH CHECK``, or the ``USING`` a ``FOR UPDATE`` / ``FOR ALL``
  policy reuses as the new-row check) and the old-row gate (``USING``, for
  ``UPDATE`` / ``DELETE`` / ``ALL``) — a leak through either is a leak. This is
  the most CVE-adjacent footgun (CVE-2025-48757): a policy that scopes reads but
  not writes lets a tenant stamp data for another tenant. The write-side lint
  rules SEC006 / SEC020 / SEC028 / SEC040 are its heuristic fallback.
* ``escalation`` — can a low-trust role that reaches a table's *owner* (via the
  `pg_auth_members` closure) ``SET ROLE`` to it and read past RLS the owner is
  exempt from? Composes the ``cross-tenant`` verdict with that reachability.
* ``reachability`` — the modes above all prove things about a table's own
  policies. This one asks whether a **view** hands the rows back anyway: a
  ``security_invoker = false`` view executes as its owner, so an anon-selectable
  path whose effective owner — the nearest enclosing definer view's owner on a
  ``view → view → table`` chain — is RLS-exempt (superuser/BYPASSRLS, or the
  table owner or an INHERIT member of it with RLS not FORCE'd) — or whose
  effective owner is granted every row by the table's own policies (a
  laundering definer view) — returns every row while ``anon`` correctly
  reports the table isolated. Anon "can open" a view via a table- or
  column-level SELECT grant to anon/PUBLIC or any role in the anon closure; a
  hop the effective owner cannot SELECT is a dead path; ``unverified`` when
  the role-membership graph is absent and the answer turns on membership.
  Composes the ``anon`` verdict with view reachability, the way ``escalation``
  composes ``cross-tenant`` with owner reachability.

They are complementary: the inverted ``auth.uid() IS NULL OR …`` policy leaks
to anon yet correctly scopes authenticated tenants — a ``leak`` in ``anon``,
``isolated`` in ``cross-tenant``.

The honest three-way verdict mirrors the project's "a verifier that degrades
to a linter" stance:

* ``isolated``   — **proven**: the read is UNSAT under the threat model — no
  row is visible to an unauthenticated client (anon) / to a session of a
  different tenant (cross-tenant).
* ``leak``       — **disproven**: a row *is* readable. The counterexample is a
  concrete characterizing row (``{"is_public": True}``); "every row" when an
  anon leak is unconditional (``USING (true)``, the ``auth.uid() IS NULL OR …``
  inversion); or, cross-tenant, "a row of another tenant".
* ``unverified`` — no claim: Z3 is unavailable, the predicate is outside the
  decidable fragment, the solver timed out, or (cross-tenant / write) the policy
  has no single tenant-scoping equality on an identity/discriminator column
  (the prover's tenant-axis set — SEC021's default names plus the ambiguous
  bare spellings SEC021 itself excludes; ``identity_columns`` replaces it) to
  verify against. This is where the verifier
  *degrades to the linter* — run `pgrls lint` for the heuristic rules.

Scope: the anon prover first checks whether the anonymous role is exempt from
the table's RLS at all (BYPASSRLS/superuser, or the table owner's privileges
without FORCE — Postgres then never consults the policies); then it and the
cross-tenant / write provers reason over each table's permissive ``SELECT`` /
``ALL`` policies. When a *leaking* permissive policy shares a table with a
``RESTRICTIVE`` floor, the floor is AND-ed into the proof and re-verified — but
only a floor that constrains *every* role and write-operation the permissive
admits (see ``_floor_applies``): a floor scoped to a role or command the
permissive outreaches is not composed, so the leak stands rather than risk a
false ``isolated``. An already-proven-``isolated`` permissive policy stays
``isolated`` (a restrictive floor only narrows access). ``cross-tenant`` mode verifies the single
``<column> = <session identity>`` shape `pgrls generate` emits; a total leak
(``USING (true)``) carries no scoping equality and is ``unverified`` there —
but is already caught as an anon leak. Tables with RLS disabled are out of
scope (that is SEC001's job, not an isolation proof).
"""
from __future__ import annotations

import functools
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pgrls.diff._z3_compare import (
    _DEFAULT_AUTH_FUNCTIONS,
    prove_anon_isolation,
    prove_cross_tenant_isolation,
)
from pgrls.model import Policy, Schema
from pgrls._render_common import make_dispatcher, pluralize, render_text_table
from pgrls.formatters._common import safe_location
from pgrls.formatters.sarif import format_sarif
from pgrls.violations import Violation

# The auth-context functions the anon prover models — NULL in the JWT-less
# session, `auth.role`/`auth.jwt` non-null in the anon-key session (single source of
# truth — the SEC038 / 3VL encoder's default). `pgrls verify --auth-function`
# extends this set with a project's own auth helper.
DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset(_DEFAULT_AUTH_FUNCTIONS)

Verdict = Literal["isolated", "leak", "unverified"]

# The threat models `pgrls verify` can prove. `anon` (default): can an
# anonymous session — JWT-less, or the Supabase anon-key caller whose
# `auth.role()` is 'anon' — read any row? `cross-tenant`: can a session
# authenticated as one tenant read a *different* tenant's row? `write`: can such
# a session *write* (INSERT/UPDATE/DELETE) another tenant's row? They are
# complementary — the inverted `auth.uid() IS NULL OR …` policy leaks to anon
# but correctly scopes authenticated tenants, so it is a leak in `anon` mode
# and isolated in `cross-tenant` mode.
# One anonymous-session GUC state: dotted GUC name → configured value (see
# `_anon_set_gucs`). A `MAYBE_SET` value means the introspecting session could
# read the GUC but it is not attributable to the server, so the prover keeps
# both value and null-flag free; a `None` value is the legacy "set, value
# uncaptured" state — opaque but definitely non-null.
GucState = dict[str, str | None]

Mode = Literal["anon", "cross-tenant", "write", "escalation", "reachability"]

# `write` reuses the cross-tenant prover verbatim — write-isolation is the same
# satisfiability question (`is_true ∧ column != session_tenant` SAT?), just
# applied to the policy's effective WRITE-check instead of its USING.
_PROVERS: dict[str, Callable[..., tuple[str, dict[str, object] | None]]] = {
    "anon": prove_anon_isolation,
    "cross-tenant": prove_cross_tenant_isolation,
    "write": prove_cross_tenant_isolation,
}

# Why a policy got no claim, per mode. `cross-tenant`/`write` add the "no single
# tenant-scoping equality" boundary (the prover declines unless the checked
# predicate declares exactly one `<column> = <session identity>` axis).
_UNVERIFIED_PREDICATE_REASON = {
    "anon": "USING predicate outside the decidable fragment",
    "cross-tenant": (
        "no provable tenant-scoping equality on an identity/discriminator column — see [lint.rules.SEC021].identity_columns — (or outside the decidable fragment)"
    ),
    "write": (
        "no provable tenant-scoping write-check on an identity/discriminator "
        "column — see [lint.rules.SEC021].identity_columns — (or outside the "
        "decidable fragment)"
    ),
}

# Reason when the AST the prover needs is absent (snapshot without parsed ASTs).
_NO_AST_REASON = {
    "anon": "USING not available",
    "cross-tenant": "USING not available",
    "write": "write-check not available",
}

_READ_COMMANDS = ("ALL", "SELECT")
# Commands whose policies can gate a WRITE. A write has TWO gates and both
# matter for isolation:
#
#   * the NEW-row gate (`WITH CHECK`, or a reused `USING`) — what row may be
#     left behind, i.e. can the session stamp a row for another tenant; and
#   * the OLD-row gate (`USING`) — which EXISTING rows the session may modify
#     or destroy, i.e. can it take over or delete another tenant's row.
#
# Modelling only the new-row gate proved "no cross-tenant write" for a policy
# with `USING (true) WITH CHECK (tenant = me)` — under which a session
# re-stamps any other tenant's row to itself — and excluded `FOR DELETE`
# entirely, so a `FOR DELETE USING (true)` policy that lets any tenant wipe the
# table was invisible. Both are live-verified on PG16. (Each needs a statement
# form that reads no column — a bare `DELETE FROM t` / `UPDATE t SET ...` with
# no WHERE and no RETURNING — otherwise the SELECT-applicable policy re-checks
# the row and blocks it; the same escape SEC040 documents.) DELETE is therefore
# a write command, gated solely by its `USING`.
_WRITE_COMMANDS = ("ALL", "INSERT", "UPDATE", "DELETE")

# Which commands' policies participate, per mode.
_MODE_COMMANDS: dict[Mode, tuple[str, ...]] = {
    "anon": _READ_COMMANDS,
    "cross-tenant": _READ_COMMANDS,
    "write": _WRITE_COMMANDS,
}

_VERDICT_LABEL = {"isolated": "PROVEN", "leak": "LEAK", "unverified": "UNVERIFIED"}

# Detail shown for a PROVEN table with no explanatory note, per threat model.
_NO_READ_DETAIL = {
    "anon": "no anonymous read",
    "cross-tenant": "no cross-tenant read",
    "write": "no cross-tenant write",
    "escalation": "no reachable owner bypass",
}

# Detail when a table has RLS on but no permissive policy for the mode's
# commands → Postgres default-denies, so it is trivially isolated.
_NO_PERMISSIVE_DETAIL = {
    "anon": "no permissive read policy — RLS default-denies",
    "cross-tenant": "no permissive read policy — RLS default-denies",
    "write": "no permissive write policy — RLS default-denies writes",
}


def effective_write_check(policy: Policy) -> Any:
    """The AST that gates the NEW row for a write policy, per Postgres's
    live-validated fallback rules:

    * ``WITH CHECK`` when present **fully overrides** ``USING`` for the new row
      (it is NOT AND-combined with USING) — rows 1/3/5b of the fallback table.
    * a ``FOR UPDATE`` / ``FOR ALL`` policy with NO ``WITH CHECK`` **reuses
      its ``USING``** as the new-row check — rows 4/5a (the soundness-critical
      fallback: omitting it would falsely prove a re-stamp impossible).
    * a bare ``FOR INSERT`` (neither clause) Postgres default-denies — it grants
      no write path, so there is nothing to prove → ``None`` (the caller skips
      it; it contributes no proof, neither leak nor isolated claim).
    * ``SELECT`` / ``DELETE`` never gate a write → ``None`` (excluded upstream).

    Returns the chosen AST, or ``None`` when the policy grants no write path
    (bare ``FOR INSERT``) or is not a write policy.
    """
    if policy.command not in _WRITE_COMMANDS:
        return None
    if policy.with_check_ast is not None:
        return policy.with_check_ast
    if policy.command in ("UPDATE", "ALL"):
        return policy.using_ast  # PG reuses USING as the new-row check
    return None  # bare FOR INSERT — default-deny, no write path


def old_row_write_gate(policy: Policy) -> Any:
    """The AST gating which EXISTING rows a write policy may modify or destroy.

    That is the policy's ``USING``, for every command that touches an existing
    row: ``UPDATE`` (the row being changed), ``DELETE`` (the row being removed)
    and ``ALL`` (both). ``INSERT`` creates a row and has no old-row gate.

    This is the half `effective_write_check` does NOT cover, and omitting it was
    unsound in both directions a write can cross tenants:

    * ``FOR UPDATE USING (true) WITH CHECK (tenant = me)`` — the new-row check
      is scoped, so checking only it proved "no cross-tenant write", yet the
      open old-row gate lets a session re-stamp ANOTHER tenant's row to itself
      (verified live on PG16: the row's owner changed and its body came along).
    * ``FOR DELETE USING (true)`` — no new-row check exists at all, so the
      policy contributed nothing while letting any tenant wipe the table.
    """
    if policy.command not in ("UPDATE", "DELETE", "ALL"):
        return None
    return policy.using_ast


def _or_gates(gates: list[Any]) -> Any:
    """Compose a policy's write gates into one predicate to prove.

    A cross-tenant write exists if the new-row gate admits a foreign-tenant row
    **or** the old-row gate does, so the isolation question is the disjunction:
    ``OR`` is UNSAT for a foreign row exactly when BOTH gates are, and SAT
    exactly when at least one leaks — with the witness characterizing whichever
    one does. Identical gates (a ``FOR ALL USING (x)`` with no ``WITH CHECK``,
    where both halves are ``x``) collapse to a single term so the common case
    is byte-for-byte the predicate the prover saw before.
    """
    from pglast.ast import BoolExpr  # noqa: PLC0415
    from pglast.enums import BoolExprType  # noqa: PLC0415

    present = [g for g in gates if g is not None]
    if not present:
        return None
    deduped: list[Any] = []
    for gate in present:
        if not any(gate is seen or gate == seen for seen in deduped):
            deduped.append(gate)
    if len(deduped) == 1:
        return deduped[0]
    return BoolExpr(boolop=BoolExprType.OR_EXPR, args=tuple(deduped))


def checked_ast(policy: Policy, mode: Mode) -> Any:
    """The AST the prover should check for `policy` under `mode`.

    For ``write`` that is BOTH write gates OR-ed together — the new-row check
    and the old-row gate (see `old_row_write_gate`) — so a leak through either
    is proven. For the read modes it is the policy's ``USING``.
    """
    if mode != "write":
        return policy.using_ast
    return _or_gates([effective_write_check(policy), old_row_write_gate(policy)])


def _compose_with_floor(permissive: Any, floor_asts: list[Any]) -> Any:
    """AND a permissive policy's predicate with the table's restrictive-floor
    predicates. A row is visible only if it satisfies (*some* permissive) AND
    (*all* restrictive), so proving ``permissive AND floor_1 AND … AND floor_k``
    decides whether the restrictive floor blocks that permissive policy's leak —
    reusing the same single-predicate prover on the composed AST."""
    from pglast.ast import BoolExpr  # noqa: PLC0415
    from pglast.enums import BoolExprType  # noqa: PLC0415

    return BoolExpr(boolop=BoolExprType.AND_EXPR, args=(permissive, *floor_asts))

# SARIF rule descriptor metadata for the prover, one per `--mode`. A given run
# is single-mode, so only the active id ever appears in `tool.driver.rules`.
# These are the *prover's* rule ids — deliberately NOT the lint catalog's
# SEC###/PERF### ids: verify *proves* a property, lint *flags* a heuristic, and
# a Code-Scanning consumer must be able to tell the two apart. They flow through
# lint's `format_sarif` (via the projected `Violation`s below) so the SARIF
# version / $schema / driver block / level mapping stay identical to `pgrls
# lint`/`pgrls diff`. The ids satisfy SARIF §3.49.7 (`name` is an identifier,
# no whitespace), and `_help_uri_for` routes the `pgrls-` prefix to the README
# verify anchor (verify rules have no per-rule `docs/RULES.md` page).
_SARIF_RULE_ID: dict[Mode, str] = {
    "anon": "pgrls-anon-isolation",
    "cross-tenant": "pgrls-cross-tenant-isolation",
    "write": "pgrls-write-isolation",
    "escalation": "pgrls-escalation-isolation",
    "reachability": "pgrls-view-reachability-isolation",
}
_SARIF_RULE_TITLE: dict[Mode, str] = {
    "anon": "Anonymous read-isolation proof",
    "cross-tenant": "Cross-tenant read-isolation proof",
    "write": "Cross-tenant write-isolation proof",
    "escalation": "Reachable RLS-bypass escalation proof",
    "reachability": "View-mediated anonymous-read isolation proof",
}


@dataclass(frozen=True)
class PolicyProof:
    """The verdict for one permissive read policy."""

    policy: str
    verdict: Verdict
    witness: dict[str, object] | None  # leak only: row, or {} = "all rows"
    reason: str | None  # unverified only: why no claim was made


@dataclass(frozen=True)
class TableVerdict:
    qualified_name: str
    verdict: Verdict  # rollup across the table's permissive read policies
    note: str | None
    proofs: tuple[PolicyProof, ...]


@dataclass(frozen=True)
class Verification:
    tables: tuple[TableVerdict, ...]
    mode: Mode = "anon"

    @property
    def has_leak(self) -> bool:
        return any(t.verdict == "leak" for t in self.tables)

    @property
    def summary(self) -> dict[str, int]:
        # `reachability` appends one verdict per (view, table) DOOR, so one
        # table behind three views is three entries. Roll them up to one
        # verdict per table — worst wins — or the line contradicts itself
        # ("1 RLS table: 0 proven isolated, 3 leaking").
        rank = {"isolated": 0, "unverified": 1, "leak": 2}
        worst: dict[str, str] = {}
        for t in self.tables:
            prior = worst.get(t.qualified_name)
            if prior is None or rank[t.verdict] > rank[prior]:
                worst[t.qualified_name] = t.verdict
        counts = {"isolated": 0, "leak": 0, "unverified": 0}
        for verdict in worst.values():
            counts[verdict] += 1
        return {"tables": len(worst), **counts}


@dataclass(frozen=True)
class LeakDelta:
    """The leak-level delta between a base and a head Verification (same mode).

    ``new_leaks`` is the CI gate: a table this change turned from proven
    ``isolated`` (or absent from base) into a proven ``leak``. A base
    ``unverified`` table is deliberately NOT a baseline for "new" — a head leak
    there is reported ``preexisting`` (not attributable to the change), because
    the base never *proved* isolation. Soundness: never cry "you introduced a
    leak" off an unprovable base.
    """

    mode: Mode
    new_leaks: tuple[TableVerdict, ...]
    preexisting_leaks: tuple[TableVerdict, ...]
    fixed_leaks: tuple[str, ...]  # qualified names, sorted
    new_unverified: tuple[TableVerdict, ...]  # base isolated/absent → head unverified

    @property
    def summary(self) -> dict[str, int]:
        return {
            "new_leaks": len(self.new_leaks),
            "preexisting_leaks": len(self.preexisting_leaks),
            "fixed_leaks": len(self.fixed_leaks),
            "new_unverified": len(self.new_unverified),
        }


def diff_verifications(base: Verification, head: Verification) -> LeakDelta:
    """Classify a head Verification against a base one (same threat model).

    A *new* leak is a proven ``leak`` in head whose table was proven ``isolated``
    in base, or is absent from base entirely (a table the change added). A base
    ``unverified`` table is not a baseline: a head leak there is ``preexisting``,
    never new. ``fixed_leaks`` are base leaks that head now proves ``isolated``
    (or the table was dropped); a base leak that became merely ``unverified`` in
    head is NOT counted as fixed — it may still leak, we just can no longer prove
    it (the symmetric counterpart of never crediting an unprovable base with a
    new leak).
    """
    # `reachability` emits one verdict per (view, table) DOOR, so keying on
    # the table name alone kept only the last door — and a change that closed
    # one door while opening another was then classified "pre-existing"
    # instead of new, which would not fail the gate.
    def key(v: Verification, t: TableVerdict) -> tuple[str, ...]:
        if v.mode == "reachability" and t.proofs:
            return (t.qualified_name, t.proofs[0].policy)
        return (t.qualified_name,)

    base_by = {key(base, t): t for t in base.tables}
    head_by = {key(head, t): t for t in head.tables}
    new_leaks: list[TableVerdict] = []
    preexisting: list[TableVerdict] = []
    new_unverified: list[TableVerdict] = []
    for t in head.tables:
        b = base_by.get(key(head, t))
        if t.verdict == "leak":
            if b is None or b.verdict == "isolated":
                new_leaks.append(t)
            else:  # base leaked or was unverifiable → not caused by this change
                preexisting.append(t)
        elif t.verdict == "unverified" and (b is None or b.verdict == "isolated"):
            new_unverified.append(t)
    fixed = tuple(
        sorted(
            {
                k[0]
                for k, b in base_by.items()
                if b.verdict == "leak"
                and (k not in head_by or head_by[k].verdict == "isolated")
            }
        )
    )
    return LeakDelta(
        head.mode,
        tuple(new_leaks),
        tuple(preexisting),
        fixed,
        tuple(new_unverified),
    )


def _rollup(proofs: list[PolicyProof]) -> Verdict:
    """A table is a leak if any policy leaks; else unverified if any policy is
    unverified; else (every policy proven isolated) isolated."""
    if any(p.verdict == "leak" for p in proofs):
        return "leak"
    if any(p.verdict == "unverified" for p in proofs):
        return "unverified"
    return "isolated"


def _write_ops(command: str) -> frozenset[str]:
    """The write operations a policy of this command gates. DELETE counts: it
    destroys an existing row, gated by the policy's USING. SELECT is excluded
    from the write bucket upstream."""
    if command == "ALL":
        return frozenset({"INSERT", "UPDATE", "DELETE"})
    return frozenset({command})


def _floor_applies(permissive: Policy, restrictive: Policy, mode: Mode) -> bool:
    """Whether a ``RESTRICTIVE`` floor provably narrows *every* row the leaking
    ``permissive`` policy admits — the precondition for soundly AND-ing it into
    the proof.

    A floor that constrains only *some* of the permissive's sessions or write
    operations must NOT be composed: AND-ing it in would over-restrict the
    predicate and could turn a real leak into a false ``isolated``. When a floor
    does not cover the permissive we simply skip it, so the leak stands.

    - **Role coverage:** the floor must constrain every session that can
      exercise the permissive. ``TO PUBLIC`` covers everyone; otherwise the
      permissive's roles must be a subset of the floor's — and a ``PUBLIC``
      permissive (usable by every role) is only covered by a ``PUBLIC`` floor.
    - **Command coverage (write mode):** the floor must gate every write
      operation the permissive gates. A ``FOR UPDATE`` floor never constrains a
      ``FOR INSERT`` leak (and vice-versa); a ``FOR ALL`` permissive is only
      covered by a ``FOR ALL`` floor. Read modes act on ``SELECT`` alone, where
      every relevant policy co-applies.
    """
    r_roles = set(restrictive.roles)
    if "PUBLIC" not in r_roles:
        p_roles = set(permissive.roles)
        if "PUBLIC" in p_roles or not p_roles <= r_roles:
            return False
    if mode == "write":
        return _write_ops(permissive.command) <= _write_ops(restrictive.command)
    return True


def _anon_login_roles(schema: Schema, anon_roles: set[str] | None) -> frozenset[str]:
    """The login roles an anonymous session can arrive through.

    Role-level settings bind to the LOGIN role, not to what the session
    later `SET ROLE`s to — and membership does not propagate them. An
    anonymous session is either a direct `anon` login or a login role that
    then `SET ROLE anon` (PostgREST's `authenticator`, a *member* of anon).
    So this is the DOWNWARD closure over all edges (SET ROLE needs no
    INHERIT): anon, its members, their members. The upward closure a first
    cut used was backwards — it counted `ALTER ROLE readers SET` (anon a
    member of readers: anon never sees it) and missed `authenticator`'s.
    """
    seed = {r for r in (anon_roles if anon_roles else {"anon"}) if r.upper() != "PUBLIC"}
    if schema.role_memberships is None:
        return frozenset(seed)
    reach = set(seed)
    changed = True
    while changed:
        changed = False
        for edge in schema.role_memberships:
            if edge.role in reach and edge.member not in reach:
                reach.add(edge.member)
                changed = True
    return frozenset(reach)


def _anon_set_gucs(schema: Schema, anon_roles: set[str] | None) -> tuple[GucState, ...]:
    """The GUC states an anonymous session can arrive in — one per login
    path, each mapping the dotted GUCs found already set to their values.

    Database / server-level settings apply on every path; a login role's
    own settings override them on its path (`_anon_login_roles`: `anon`
    itself, or `authenticator` before `SET ROLE anon`). The prover checks
    every state and a leak in any is the verdict — the paths are all real.
    Values are kept concrete: `current_setting('app.flag') = 'on'` with the
    setting at 'off' is isolated (measured: 0 rows), where an opaque
    non-null stand-in would have claimed a leak.
    """
    base: GucState = {n.lower(): v for n, v in schema.set_gucs}
    states: list[GucState] = []
    for role in sorted(_anon_login_roles(schema, anon_roles)):
        state = dict(base)
        state.update({n.lower(): v for r, n, v in schema.role_set_gucs if r == role})
        if state not in states:
            states.append(state)
    return tuple(states) if states else (base,)


def _anon_reachable_roles(
    schema: Schema, anon_roles: set[str]
) -> tuple[frozenset[str], bool]:
    """The roles an anonymous session's policies can be applied under, and
    whether that set is COMPLETE (the role-membership graph was captured).

    A policy ``TO R`` applies to a session iff its role is ``R`` or a transitive
    member of ``R`` (or ``R`` is ``PUBLIC``). So the anon-reachable set is the
    upward `pg_auth_members` closure of the configured anon role(s), plus
    ``PUBLIC``. When `schema.role_memberships is None` (an offline / `--against`
    / hand-built Schema) the graph is unavailable — the returned set is just the
    seed and the bool is False, so `_anon_policy_reachability` reports
    ``"unknown"`` (→ abstain) for a leaking policy outside the seed rather than
    guess ``unreachable`` (a false ``isolated``).
    """
    seed = set(anon_roles) | {"PUBLIC"}
    if schema.role_memberships is None:
        return frozenset(seed), False
    reachable = set(seed)
    changed = True
    while changed:  # transitive closure; role graphs are tiny
        changed = False
        for edge in schema.role_memberships:
            if edge.member in reachable and edge.role not in reachable:
                reachable.add(edge.role)
                changed = True
    return frozenset(reachable), True


def _anon_policy_reachability(
    schema: Schema, policy: Policy, anon_roles: set[str]
) -> str:
    """Whether an anonymous session can invoke `policy`.

    ``"reachable"`` — its roles intersect the anon-reachable `pg_auth_members`
    closure (so an anon leak in its predicate is real). ``"unreachable"`` — they
    don't, and the closure is COMPLETE (the graph was captured), so anon can
    never invoke it. ``"unknown"`` — the role graph was not captured (offline /
    ``--against`` / hand-built schema) and the roles fall outside
    ``{anon, PUBLIC}``, so reachability can't be decided → the caller abstains.

    Consulted ONLY for a policy whose predicate already *leaks* under anon: an
    isolated predicate admits no anon rows regardless of who invokes it, so its
    reachability is moot. Restrictive floors need no separate gate either —
    ``_floor_applies`` only composes a floor whose roles cover the (reachable)
    leaking permissive, which implies the floor itself applies to anon.
    """
    reachable, graph_available = _anon_reachable_roles(schema, anon_roles)
    # Canonicalize the public pseudo-role (Postgres reserves the name, so a
    # lowercase ``public`` is always PUBLIC, never a real role) and fail OPEN on
    # a degenerate empty role set — a leak is never silently dropped on an
    # un-canonicalized or malformed hand-built Schema.
    roles = {"PUBLIC" if r.lower() == "public" else r for r in policy.roles}
    if not roles or roles & reachable:
        return "reachable"
    return "unreachable" if graph_available else "unknown"


def build_verification(
    schema: Schema,
    *,
    auth_functions: set[str] | None = None,
    mode: Mode = "anon",
    anon_roles: set[str] | None = None,
    identity_columns: frozenset[str] | None = None,
    set_gucs: tuple[GucState, ...] | None = None,
) -> Verification:
    """Prove tenant isolation for every RLS-enabled table in `schema`.

    `mode` selects the threat model: ``"anon"`` (default) proves no row is
    readable by an *unauthenticated* session; ``"cross-tenant"`` proves no row
    of one tenant is readable by a session authenticated as a *different*
    tenant; ``"write"`` proves no such session can *write or delete* a row of
    another tenant. The same table/policy walk, restrictive-floor handling, and
    rollup apply to all three — what differs is which policy commands
    participate (``write`` looks at INSERT/UPDATE/ALL, not SELECT/DELETE), which
    AST the prover checks (``write`` checks the effective write-check, not
    USING), the prover, and the "no claim" reasons.

    `auth_functions`, when given, *replaces* the default auth function set
    (auth.uid/role/jwt, current_setting). In ``anon`` mode every name in it is
    treated as NULL (the unauthenticated state); in ``cross-tenant`` mode each
    is a free, non-null session identity. `None` uses the defaults. (The
    `pgrls verify --auth-function` CLI unions a project's helper with the
    defaults before calling this, which is why the *flag* extends rather than
    replaces.) Tables are sorted by qualified name for deterministic output.

    ``escalation`` and ``reachability`` are different shapes — they compose an
    existing verdict (cross-tenant / anon respectively) with a reachability
    graph rather than walking policies directly — so they are dispatched to
    `build_escalation` / `build_reachability`.

    `identity_columns`, when given, replaces the identity/discriminator column
    names the cross-tenant / write provers accept as the tenant axis
    (`sec021.AXIS_IDENTITY_COLUMNS` otherwise — SEC021's own flagging set plus
    the ambiguous bare spellings that rule excludes); a policy whose only scoping equality is on some
    other column is `unverified`, not proven.
    """
    if mode == "escalation":
        return build_escalation(
            schema, auth_functions=auth_functions, anon_roles=anon_roles
        )
    if mode == "reachability":
        return build_reachability(
            schema, auth_functions=auth_functions, anon_roles=anon_roles
        )
    prove = _PROVERS[mode]
    if mode == "anon":
        # Dotted GUCs the anonymous session inherits already set (database /
        # server level, plus the role-level settings of each login path an
        # anonymous caller can arrive on — `_anon_login_roles`, NOT the
        # upward `_anon_reachable_roles` closure): a read of one is its
        # configured value, not the raise the unset-GUC assumption relies on.
        prove = functools.partial(
            prove,
            set_gucs=(
                set_gucs if set_gucs is not None else _anon_set_gucs(schema, anon_roles)
            ),
        )
    else:
        # The cross-tenant axis must be an identity/discriminator column, or
        # the proof is vacuous (`status != session.status` says nothing about
        # tenants). None → the SEC021 default name set.
        prove = functools.partial(prove, identity_columns=identity_columns)
    commands = _MODE_COMMANDS[mode]
    floor_kind = "write" if mode == "write" else "read"
    # An *empty* anon set is degenerate — there is always at least the PUBLIC
    # pseudo-role (every session, anon included) — so fall back to the default
    # rather than let it collapse the seed to `{PUBLIC}` and false-clear a
    # `TO anon` leak. (Truthiness, not `is not None`.)
    resolved_anon_roles = anon_roles if anon_roles else {"anon", "PUBLIC"}
    tables: list[TableVerdict] = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        if not table.rls_enabled:
            continue  # not an isolation claim — SEC001's domain, not verify's
        # Before reading a single predicate: is the anonymous session exempt
        # from this table's RLS altogether? If the anon role holds BYPASSRLS,
        # or holds the table owner's privileges on a table that is not
        # FORCE'd, Postgres never consults the policies — so no predicate,
        # however well scoped, isolates anything. Measured on PG16: with
        # `GRANT plainowner TO anon` a live anon login read every row while
        # this mode reported PROVEN. Checked ahead of the no-permissive-policy
        # branch, because a table with RLS on and NO policies is default-deny
        # for everyone EXCEPT an exempt role, which still reads all of it.
        if mode == "anon" and _anon_session_exempt(
            schema, table, resolved_anon_roles
        ):
            exempt_by = ", ".join(
                sorted(_anon_exempting_roles(schema, table, resolved_anon_roles))
            ) or ", ".join(sorted(resolved_anon_roles - {"PUBLIC"}))
            tables.append(
                TableVerdict(
                    table.qualified_name,
                    "leak",
                    "the anonymous session is exempt from this table's RLS "
                    f"({exempt_by} holds BYPASSRLS, or the privileges of owner "
                    f"{table.owner} on a table without FORCE ROW LEVEL "
                    "SECURITY) — the policies are never consulted; see "
                    "verify --mode escalation and SEC048",
                    (PolicyProof(f"role:{exempt_by}", "leak", {}, None),),
                )
            )
            continue
        relevant = [p for p in table.policies if p.command in commands]
        permissive = [p for p in relevant if p.permissive]
        restrictives = [p for p in relevant if not p.permissive]

        if not permissive:
            # RLS on with no permissive policy for this mode's commands →
            # Postgres default-denies → trivially isolated.
            tables.append(
                TableVerdict(
                    table.qualified_name,
                    "isolated",
                    _NO_PERMISSIVE_DETAIL[mode],
                    (),
                )
            )
            continue

        proofs: list[PolicyProof] = []
        for policy in permissive:
            ast = checked_ast(policy, mode)
            if ast is None:
                # A bare FOR INSERT (no WITH CHECK) grants no write path —
                # Postgres default-denies it, so it contributes no proof. Any
                # other missing AST is a genuine "can't check" → unverified.
                if mode == "write" and policy.command == "INSERT":
                    continue
                proofs.append(
                    PolicyProof(
                        policy.name, "unverified", None, _NO_AST_REASON[mode]
                    )
                )
                continue
            verdict, witness = prove(ast, auth_functions)
            # In the anon threat model the predicate is not the whole story: a
            # policy whose predicate *leaks* only leaks to anon if an anonymous
            # session can actually invoke it. A leaking policy anon cannot reach
            # (roles outside the anon-reachable closure) exposes nothing → the
            # leak is spurious; when the role graph is unavailable we abstain
            # rather than guess. An *isolated* predicate needs no such gate — it
            # admits no anon rows regardless of who invokes it — so this only
            # intercepts leaks.
            if mode == "anon" and verdict == "leak":
                reach = _anon_policy_reachability(
                    schema, policy, resolved_anon_roles
                )
                if reach == "unreachable":
                    proofs.append(PolicyProof(policy.name, "isolated", None, None))
                    continue
                if reach == "unknown":
                    proofs.append(
                        PolicyProof(
                            policy.name,
                            "unverified",
                            None,
                            "predicate leaks under anon, but the role-membership "
                            "graph was not captured — cannot decide whether an "
                            "anonymous session reaches this policy's role(s) "
                            f"({', '.join(sorted(policy.roles))}); re-run against "
                            "a live database",
                        )
                    )
                    continue
                # reach == "reachable" → the anon leak is real; fall through.
            # Only floors that constrain *every* role and write-operation this
            # permissive admits may be soundly AND-ed in (see `_floor_applies`);
            # a partially-applicable floor would over-restrict → false PROVEN.
            applicable_floors = [
                r for r in restrictives if _floor_applies(policy, r, mode)
            ]
            if verdict == "leak" and applicable_floors:
                # Compose the leaking permissive policy with the applicable
                # restrictive floor (a row is visible only if it satisfies some
                # permissive AND all restrictive) and re-prove: the floor may
                # block the leaking row (→ isolated) or not (→ the leak stands).
                floor_asts = [checked_ast(r, mode) for r in applicable_floors]
                if any(fa is None for fa in floor_asts):
                    # A floor whose predicate can't be modeled → can't compose
                    # soundly → no claim (never a possibly-wrong verdict).
                    proofs.append(
                        PolicyProof(
                            policy.name,
                            "unverified",
                            None,
                            f"restrictive {floor_kind} floor predicate could not "
                            "be modeled",
                        )
                    )
                else:
                    c_verdict, c_witness = prove(
                        _compose_with_floor(ast, floor_asts), auth_functions
                    )
                    if c_verdict == "leak":
                        proofs.append(
                            PolicyProof(policy.name, "leak", c_witness, None)
                        )
                    elif c_verdict == "isolated":
                        # The restrictive floor provably blocks the leaking row.
                        proofs.append(
                            PolicyProof(policy.name, "isolated", None, None)
                        )
                    else:
                        proofs.append(
                            PolicyProof(
                                policy.name,
                                "unverified",
                                None,
                                f"restrictive {floor_kind} floor predicate is "
                                "outside the decidable fragment",
                            )
                        )
            elif verdict == "leak":
                proofs.append(PolicyProof(policy.name, "leak", witness, None))
            elif verdict == "unverified":
                proofs.append(
                    PolicyProof(
                        policy.name,
                        "unverified",
                        None,
                        _UNVERIFIED_PREDICATE_REASON[mode],
                    )
                )
            else:
                proofs.append(PolicyProof(policy.name, "isolated", None, None))

        note = (
            f"restrictive {floor_kind} floor composed into the proof"
            if any(
                _floor_applies(p, r, mode)
                for p in permissive
                for r in restrictives
            )
            else None
        )
        tables.append(
            TableVerdict(table.qualified_name, _rollup(proofs), note, tuple(proofs))
        )
    return Verification(tuple(tables), mode)


def build_escalation(
    schema: Schema,
    *,
    auth_functions: set[str] | None = None,
    anon_roles: set[str] | None = None,
) -> Verification:
    """Prove/refute the SEC048 owner-reachability escalation paths.

    A low-trust role that is a *member* of a table's owner (via the
    `pg_auth_members` closure already computed in `Schema.owner_reachable_members`)
    can ``SET ROLE`` to that owner; if the owner is not superuser / ``BYPASSRLS``
    (SEC048 filters those out at introspection time) and the table is RLS-enabled
    but **not** ``FORCE``'d, the owner is exempt from the table's RLS — so the
    member reads every row. Whether that is a *leak* depends on whether the
    table's RLS was actually isolating tenants, which is exactly what the
    ``cross-tenant`` prover decides. So escalation = the cross-tenant verdict ⋈
    the reachability graph, per affected table:

    * cross-tenant **isolated** (the RLS genuinely scopes rows, incl. the
      default-deny "no permissive policy" case) → the bypass defeats real
      isolation → **leak**, witness ``{}`` (every row; the bypass is
      unconditional). The reaching roles + owner are carried in the note.
    * cross-tenant **leak**, *total* (witness ``{}`` — every row already leaks
      cross-tenant) → the owner bypass exposes nothing the direct path didn't →
      **isolated** (ceded to ``verify --mode cross-tenant``).
    * cross-tenant **leak**, *partial / conditional* (a characterizing-row
      witness, e.g. only ``is_public`` rows, or a no-single-row ``None``
      witness) → a direct cross-tenant session reads only the leaking subset,
      but the owner bypass reads EVERY row — incl. the other tenants' rows the
      partial leak hides → **leak**, witness ``{}``.
    * cross-tenant **unverified** (the predicate is outside the decidable
      fragment) → cannot claim the RLS was isolating → **unverified** (abstain).

    Only tables owned by a reachable owner appear in the result (the SEC048
    population); a table no low-trust role can reach its owner of is simply not a
    candidate. SECDEF-body escalation (SEC042 / VIEW004) is out of this v1 scope.
    """
    xt = build_verification(schema, auth_functions=auth_functions, mode="cross-tenant")
    xt_by_table = {t.qualified_name: t for t in xt.tables}

    # owner role name -> sorted distinct low-trust members that reach it.
    reachers_by_owner: dict[str, set[str]] = {}
    for m in schema.owner_reachable_members:
        for owner in m.via_owners:
            reachers_by_owner.setdefault(owner, set()).add(m.member)

    tables: list[TableVerdict] = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        if not table.rls_enabled or table.force_rls:
            # FORCE'd → the owner is itself RLS-scoped → no bypass (and SEC048
            # would not have fired). RLS-off is SEC001's domain, not an
            # isolation/escalation claim.
            continue
        reaching = reachers_by_owner.get(table.owner)
        if not reaching:
            continue  # no low-trust role reaches this table's owner
        roles_phrase = ", ".join(sorted(reaching))
        path = f"reachable by {roles_phrase} via owner {table.owner} (RLS not FORCE'd)"
        xtv = xt_by_table.get(table.qualified_name)
        # Every escalation candidate is RLS-enabled, so it always has a
        # cross-tenant verdict; treat a defensive miss as "isolated" (the
        # strongest, leak-direction assumption).
        xt_verdict = xtv.verdict if xtv is not None else "isolated"

        if xt_verdict == "isolated":
            proof = PolicyProof(table.owner, "leak", {}, None)
            tables.append(TableVerdict(table.qualified_name, "leak", path, (proof,)))
        elif xt_verdict == "leak":
            # The owner bypass reads EVERY row, unconditionally. A cross-tenant
            # leak "exposes nothing new" ONLY when it was already *total* — the
            # prover signals that with an empty `{}` witness (every row leaks
            # cross-tenant). A *partial* cross-tenant leak (a characterizing-row
            # witness — e.g. only `is_public` rows leak) still hides the other
            # tenants' NON-public rows from a direct session, but the owner
            # bypass reads those too, so the bypass is a real *additional* leak.
            xt_leak = next(
                (p for p in (xtv.proofs if xtv else ()) if p.verdict == "leak"),
                None,
            )
            if xt_leak is not None and xt_leak.witness == {}:
                proof = PolicyProof(table.owner, "isolated", None, None)
                tables.append(
                    TableVerdict(
                        table.qualified_name,
                        "isolated",
                        "table RLS already leaks every row cross-tenant "
                        "(see verify --mode cross-tenant) — owner bypass exposes "
                        "nothing new",
                        (proof,),
                    )
                )
            else:
                # Partial (or conditional) cross-tenant leak: the bypass exposes
                # rows the direct cross-tenant query cannot reach.
                proof = PolicyProof(table.owner, "leak", {}, None)
                tables.append(
                    TableVerdict(
                        table.qualified_name,
                        "leak",
                        f"{path} — the owner bypass also exposes rows the "
                        "cross-tenant leak does not (e.g. other tenants' "
                        "non-public rows)",
                        (proof,),
                    )
                )
        else:  # unverified
            reason = next(
                (
                    p.reason
                    for p in (xtv.proofs if xtv else ())
                    if p.verdict == "unverified" and p.reason
                ),
                "cross-tenant isolation unproven",
            )
            proof = PolicyProof(table.owner, "unverified", None, reason)
            tables.append(
                TableVerdict(
                    table.qualified_name,
                    "unverified",
                    f"cannot prove the table isolates tenants ({reason}); {path}",
                    (proof,),
                )
            )
    # SEC042: anon-callable SECURITY DEFINER functions owned by an RLS-exempt
    # role, whose body reads an RLS table the anon caller's own RLS would deny.
    # Empty → default (see `build_verification` — a `{PUBLIC}`-only seed would
    # under-report the SEC042 anon exposure).
    resolved_anon_roles = anon_roles if anon_roles else {"anon", "PUBLIC"}
    tables.extend(
        _escalation_secdef_findings(schema, auth_functions, resolved_anon_roles)
    )
    tables.sort(key=lambda t: t.qualified_name)
    return Verification(tuple(tables), "escalation")


def _anon_priv_closure(schema: Schema, anon_roles: set[str]) -> frozenset[str] | None:
    """The roles whose PRIVILEGES an anonymous session holds.

    Distinct from `_anon_reachable_roles`, which is the upward closure over
    every membership edge and answers "which policies apply". Privileges flow
    only along INHERIT edges (`has_privs_of_role`), so a `NOINHERIT` member
    holds none of the granted role's rights — measured: `GRANT readers TO anon
    WITH INHERIT FALSE` left a direct read `permission denied` while the
    upward closure said anon could read. `None` when the graph is not captured.
    """
    if schema.role_memberships is None:
        return None
    closure: set[str] = set()
    for role in anon_roles:
        if role.upper() == "PUBLIC":
            continue
        one = _inherit_closure(schema, role)
        if one is None:  # pragma: no cover - guarded above
            return None
        closure |= one
    return frozenset(closure)


def _anon_holds_select(
    schema: Schema, rel: Any, anon_roles: set[str], *, table_level_only: bool = False
) -> bool:
    """Can the anonymous session `SELECT` from `rel` on its own privileges?

    Ownership, `pg_read_all_data` and an INHERIT-inherited grant all confer
    read with no direct grant of their own. `table_level_only` asks the
    stronger question the reachability cede needs — whether the WHOLE row is
    readable — since a column-level `GRANT SELECT (id)` opens a view without
    exposing the secret column a definer view hands over.
    """
    grantees = {g.role for g in rel.grants if "SELECT" in g.privileges}
    if not table_level_only:
        grantees |= {
            cg.role
            for cg in getattr(rel, "column_grants", ())
            if "SELECT" in cg.privileges
        }
    if "PUBLIC" in grantees or grantees & anon_roles:
        return True
    closure = _anon_priv_closure(schema, anon_roles)
    if closure is None:
        # Without the graph only a direct grant could decide it, and the
        # check above already covered that — so there is nothing more to say.
        return False
    if getattr(rel, "owner", None) and rel.owner in closure:
        return True
    if "pg_read_all_data" in closure:
        return True
    return bool(grantees & closure)


def _anon_exempting_roles(
    schema: Schema, table: Any, anon_roles: set[str]
) -> set[str]:
    """Which of the configured anon roles are the ones actually exempt — so
    the finding names the role at fault rather than every role configured."""
    bypass = {r.name for r in schema.bypassrls_roles}
    named = {r for r in anon_roles if r.upper() != "PUBLIC"}
    out = named & bypass
    if not table.force_rls and table.owner:
        for role in named:
            closure = _anon_priv_closure(schema, {role})
            if closure is not None and table.owner in closure:
                out.add(role)
    return out


def _anon_session_exempt(schema: Schema, table: Any, anon_roles: set[str]) -> bool:
    """Is the anonymous session itself exempt from `table`'s RLS?

    The predicate is not the whole story: if the anon role holds BYPASSRLS, or
    holds the table owner's privileges on a table that is not `FORCE`'d,
    Postgres skips the policies entirely. Measured on PG16: with `GRANT
    plainowner TO anon` the policies were never consulted and a live anon login
    read every row while the prover reported PROVEN; `FORCE` cut it to zero,
    and `WITH INHERIT FALSE` made it `permission denied`.
    """
    bypass = {r.name for r in schema.bypassrls_roles}
    if bypass & anon_roles:
        return True
    if table.force_rls or not table.owner:
        return False
    closure = _anon_priv_closure(schema, anon_roles)
    # No graph (a pre-v26 baseline, an offline `--sql-file` source, a
    # hand-built Schema) → this reports "not exempt", which is the
    # fail-OPEN direction: ownership-based exemption cannot be ruled out.
    # It matches `_effective_user_exempt`'s stance for a missing owner and
    # keeps offline runs usable, but it is the one place in this module
    # where absent evidence resolves to a proof rather than an abstention.
    return closure is not None and table.owner in closure


def _anon_reads_every_row(
    schema: Schema,
    table: Any,
    auth_functions: set[str] | None,
    anon_roles: set[str],
    guc_states: tuple[GucState, ...],
    memo: dict[str, bool] | None = None,
) -> bool:
    """Does the DIRECT anonymous read already return every row of `table`?

    The question a cede asks before deciding a second door adds nothing. It
    needs "every row in EVERY modelled anonymous session", which a `{}`
    witness does not give — that witness comes from the first session that
    leaked (see `_z3_compare.anon_leak_is_total`).

    A permissive policy is not the whole answer. Postgres ANDs every
    applicable RESTRICTIVE policy on top, so `USING (true)` under a
    restrictive tenant filter returns ONE row, not all of them — measured:
    anon read 1 row directly and 2 through a definer view over it, while
    reading the permissive policy alone said "already reads everything" and
    cleared the door. Every anon-reachable floor is composed in; a floor we
    cannot model means we cannot claim totality, so we decline.

    (Composing floors that `_floor_applies` would reject is deliberate here.
    Over-restricting can only SUPPRESS a cede, which is the safe direction —
    the opposite of the PROVEN claim that gate guards.)
    """
    from pgrls.diff._z3_compare import anon_leak_is_total  # noqa: PLC0415

    if memo is not None and table.qualified_name in memo:
        return memo[table.qualified_name]

    def answer(value: bool) -> bool:
        if memo is not None:
            memo[table.qualified_name] = value
        return value

    # An exempt anonymous session never consults the policies at all, so it
    # reads every row by definition — and the `role:` proof that records it
    # carries no policy for the loop below to find.
    if _anon_session_exempt(schema, table, anon_roles):
        return answer(True)

    auth = auth_functions if auth_functions is not None else None
    restrictives = [
        p
        for p in table.policies
        if p.command in _MODE_COMMANDS["anon"]
        and not p.permissive
        and _anon_policy_reachability(schema, p, anon_roles) != "unreachable"
    ]
    floor_asts = [checked_ast(r, "anon") for r in restrictives]
    if any(fa is None for fa in floor_asts):
        return answer(False)

    for policy in table.policies:
        if policy.command not in _MODE_COMMANDS["anon"] or not policy.permissive:
            continue
        if _anon_policy_reachability(schema, policy, anon_roles) != "reachable":
            continue
        ast = checked_ast(policy, "anon")
        if ast is None:
            continue
        if floor_asts:
            ast = _compose_with_floor(ast, floor_asts)
        if anon_leak_is_total(ast, auth, set_gucs=guc_states):
            return answer(True)
    return answer(False)


def _relation_is_anon_selectable(
    schema: Schema, rel: Any, anon_roles: set[str]
) -> bool:
    """Can the anonymous session `SELECT` from `rel` — a view or a table?

    A grant to any role in the anon closure (`_anon_reachable_roles` — the
    same closure policy reachability uses, plus PUBLIC), at TABLE level or
    on ANY column: a column-level `GRANT SELECT (id, body) ON v TO anon` is a
    door too (measured: anon read the row). When the graph is not captured
    only a literal anon/PUBLIC grant counts.
    """
    reachable, _ = _anon_reachable_roles(schema, anon_roles)
    if any(g.role in reachable and "SELECT" in g.privileges for g in rel.grants):
        return True
    if any(
        cg.role in reachable and "SELECT" in cg.privileges
        for cg in getattr(rel, "column_grants", ())
    ):
        return True
    # Grants are not the only way in: owning the relation, holding its owner's
    # privileges, or `pg_read_all_data` all open it with no ACL at all
    # (measured: a view with a NULL `relacl` read every row for an anon role
    # holding `pg_read_all_data`, while every verify mode reported clean).
    return _anon_holds_select(schema, rel, anon_roles)


def build_reachability(
    schema: Schema,
    *,
    auth_functions: set[str] | None = None,
    anon_roles: set[str] | None = None,
) -> Verification:
    """Prove/refute anon reachability of RLS rows *through a view*.

    ``verify --mode anon`` proves a table's own policies deny an anonymous
    read. It says nothing about a **view** over that table — and a
    ``security_invoker = false`` view runs as its owner, so an anon-selectable
    one owned by an RLS-exempt role hands back every row the table's policies
    were written to withhold. The table is genuinely isolated; the view is a
    second door. This mode proves whether that door is open.

    The firing gate, every clause validated live on PG16 against a table whose
    policy scopes rows to ``current_setting('app.tenant')`` (anon sets no such
    GUC, so the direct read yields nothing):

    * anon can open the view — a table- OR column-level ``SELECT`` grant to
      anon/PUBLIC or to any role in the anon closure (measured: a column grant
      and a grant to a role anon is a member of both read the row); **and**
    * some view on the path is ``security_invoker = false`` — the nearest such
      view to the table sets the effective RLS user; an all-invoker chain
      re-applies the caller's RLS, and the live anon read was denied
      outright; **and**
    * the effective RLS user's owner is exempt from the base table's RLS
      (`_effective_user_exempt`: superuser/BYPASSRLS, or — with the table not
      FORCE'd — the table owner or an INHERIT member of it), **or** the
      table's own policies grant that owner every row under the anonymous
      auth context (the laundering case, decided by the anon prover with the
      owner as the session role). A view owned by an ordinary third role with
      a plain ``SELECT`` grant returned **zero** rows, ``FORCE`` on the base
      table cut the owning-view case from every row to zero, and a hop the
      effective owner cannot ``SELECT`` is a dead path (``permission denied``).

    The verdict is then the base table's ``anon`` verdict joined with that
    reachability, exactly as `build_escalation` joins the cross-tenant verdict
    with owner reachability:

    * anon **isolated** → the view defeats real isolation → **leak**, witness
      ``{}`` (the view is unconditional — it returns every row).
    * anon **leak**, *total* (``{}`` witness — the table already hands anon
      every row) AND anon actually holds ``SELECT`` on the table → the view
      exposes nothing new → **isolated**, ceded to ``verify --mode anon``.
      Without that grant the direct read is ``permission denied`` while the
      view still returns every row, so the door stands and the verdict is
      **leak**.
    * anon **leak**, *partial* (a characterizing-row witness) → the view still
      reads the rows the partial leak withholds → **leak**.
    * anon **unverified** → no claim that the table was isolating → abstain.

    Scope: doors are regular views. A materialized view stores rows captured
    when it was refreshed, so ``security_invoker`` does not apply to reads of
    it at all — a different mechanism: an anon-selectable matview is SEC054 /
    VIEW003's finding, and a regular view *over* one is reported
    ``unverified`` here (measured: a definer view over a superuser-refreshed
    matview handed anon every row). Paths are walked hop by hop over ``View.direct_references``: the
    effective RLS user for a table is the owner of the nearest enclosing
    ``security_invoker = false`` view on the path (measured: ``outer(off,
    owner A) → inner(off, owner superuser) → T`` bypasses T as the superuser
    even though A is not exempt and inner is not anon-selectable), and an
    owner that is an INHERIT *member* of the table owner is owner-equivalent (a
    NOINHERIT member is not)
    (Postgres's ``has_privs_of_role``). When the role-membership graph is not
    captured and the answer turns on membership, the verdict is
    ``unverified`` rather than silence.
    """
    resolved_anon_roles = anon_roles if anon_roles else {"anon", "PUBLIC"}
    tables_by_key = {(t.schema, t.name): t for t in schema.tables}
    views_by_key = {(v.schema, v.name): v for v in schema.views}
    # Anon can open any regular view it holds SELECT on. Whether that read
    # bypasses a table's RLS depends on the hops BENEATH it, not on this view's
    # own invoker flag: an invoker-on outer view over an invoker-off definer
    # view still runs the inner body as the inner owner.
    outers = [
        v
        for v in schema.views
        if not v.is_materialized
        and _relation_is_anon_selectable(schema, v, resolved_anon_roles)
    ]
    # A definer view whose owner is NOT RLS-exempt can still launder rows: if
    # the table's own permissive policies grant that owner every row (`TO
    # app_role USING (true)`), the view hands them to anon. Ask the anon prover
    # the same question with the OWNER as the session role — the predicates
    # are evaluated with the anonymous caller's auth context (auth.* NULL /
    # anon-key), exactly as Postgres does inside the view body.
    owner_cache: dict[str, dict[str, TableVerdict]] = {}
    # Inside a definer view body `current_setting()` reads the CALLER's
    # session, so the set-GUC facts are the anonymous session's — not the
    # owner's (measured: `ALTER ROLE anon SET app.x` leaked through a view
    # whose owner never had it).
    caller_set_gucs = _anon_set_gucs(schema, anon_roles)
    # The ∀ question depends only on (schema, table); the walk asks it once
    # per DOOR, which was a 4.7x slowdown on a 50-table schema.
    total_read_memo: dict[str, bool] = {}

    def owner_verdict(owner: str, table: Any) -> TableVerdict | None:
        if owner not in owner_cache:
            v = build_verification(
                schema, auth_functions=auth_functions, mode="anon",
                anon_roles={owner}, set_gucs=caller_set_gucs,
            )
            owner_cache[owner] = {t.qualified_name: t for t in v.tables}
        return owner_cache[owner].get(table.qualified_name)

    paths = _reachability_paths(
        schema, outers, tables_by_key, views_by_key, owner_verdict, resolved_anon_roles
    )
    if not paths:
        return Verification((), "reachability")

    an = build_verification(
        schema, auth_functions=auth_functions, mode="anon",
        anon_roles=anon_roles,
    )
    an_by_table = {t.qualified_name: t for t in an.tables}

    tables: list[TableVerdict] = []
    for rp in paths:
        outer, table, eff = rp.outer, rp.table, rp.effective
        runs_as = (
            f"materialized view owned by {eff.owner}"
            if getattr(eff, "is_materialized", False)
            else f"runs as {eff.owner}"
        )
        door = (
            f"{outer.qualified_name}"
            + (f" → {' → '.join(rp.hops)}" if rp.hops else "")
            + f" ({runs_as})"
        )
        selectable = f"is SELECT-able by {', '.join(sorted(resolved_anon_roles))}"
        if rp.exempt is None:
            reason = rp.unknown_reason or "cannot decide the effective user's access"
            proof = PolicyProof(outer.qualified_name, "unverified", None, reason)
            tables.append(
                TableVerdict(
                    table.qualified_name,
                    "unverified",
                    f"cannot decide whether the view bypasses RLS ({reason}); "
                    f"{door} {selectable}",
                    (proof,),
                )
            )
            continue
        # A laundering door is only as wide as the owner's own admission:
        # `{}` is every row, anything else some rows (a characterizing row,
        # or None when the prover could not pin one).
        total = not rp.via_policy or rp.owner_witness == {}
        if rp.via_policy:
            why = (
                f"owner {eff.owner} is not RLS-exempt, but the table's own "
                f"policies grant it {'every row' if total else 'rows'} under the "
                "anonymous auth context — the definer view launders them"
            )
        elif getattr(eff, "owner_is_superuser", False):
            why = f"superuser owner {eff.owner}"
        elif eff.owner_bypasses_rls:
            why = f"BYPASSRLS owner {eff.owner} (holds SELECT on the table)"
        elif eff.owner == table.owner:
            why = f"owner {eff.owner} owns the table and RLS is not FORCE'd"
        else:
            why = (
                f"owner {eff.owner} is an INHERIT member of table owner "
                f"{table.owner} (owner-equivalent) and RLS is not FORCE'd"
            )
        path = f"{door}: {why}; {selectable}"
        witness: dict[str, object] | None = {} if total else rp.owner_witness
        reads = "every row" if total else f"the rows the table's policies admit to {eff.owner}"
        anv = an_by_table.get(table.qualified_name)
        # Every candidate is RLS-enabled so it has an anon verdict; treat a
        # defensive miss as `isolated` — the leak-direction assumption.
        an_verdict = anv.verdict if anv is not None else "isolated"

        if an_verdict == "isolated":
            proof = PolicyProof(outer.qualified_name, "leak", witness, None)
            tables.append(
                TableVerdict(
                    table.qualified_name,
                    "leak",
                    f"anon reads {reads} via {path}",
                    (proof,),
                )
            )
        elif an_verdict == "leak":
            # The question is "does the table ALREADY hand anon everything",
            # so a total (`{}` witness) leak wins over a partial one; taking
            # the first leak proof made the answer depend on policy order.
            an_leaks = [
                p for p in (anv.proofs if anv else ()) if p.verdict == "leak"
            ]
            an_leak = next(
                (p for p in an_leaks if p.witness == {}),
                an_leaks[0] if an_leaks else None,
            )
            # …but only if anon can actually read the WHOLE table. `--mode
            # anon` proves the PREDICATE admits rows; it never checks
            # privileges. A `USING (true)` table with no grant to anon is
            # `permission denied` directly (measured) while the definer view
            # over it returns every row — so ceding here cleared the only real
            # door. A column-level `GRANT SELECT (id)` is not enough either:
            # the direct read of the secret column is still denied while the
            # view hands it over. And the privilege closure must follow
            # INHERIT edges only — a `NOINHERIT` member holds nothing
            # (measured: `permission denied` on the direct read).
            if (
                an_leak is not None
                and _anon_reads_every_row(
                    schema, table, auth_functions, resolved_anon_roles,
                    caller_set_gucs, total_read_memo,
                )
                and _anon_holds_select(
                    schema, table, resolved_anon_roles, table_level_only=True
                )
            ):
                proof = PolicyProof(outer.qualified_name, "isolated", None, None)
                tables.append(
                    TableVerdict(
                        table.qualified_name,
                        "isolated",
                        "the table already leaks every row to anon (see "
                        "verify --mode anon) — the view exposes nothing new",
                        (proof,),
                    )
                )
            elif (
                not total
                and _anon_holds_select(
                    schema, table, resolved_anon_roles, table_level_only=True
                )
            ):
                # The table already leaks some rows to anon directly and the
                # view admits its owner some rows — possibly the very same
                # (measured: `TO PUBLIC USING (is_public)` read one row direct
                # and the same one through a plain-owner definer view).
                # Whether the view adds a row is not decided here.
                reason = (
                    "the table already leaks some rows to anon directly and the "
                    f"definer view admits only the rows the policies grant {eff.owner}; "
                    "cannot decide whether the view exposes rows the direct read withholds"
                )
                proof = PolicyProof(outer.qualified_name, "unverified", None, reason)
                tables.append(
                    TableVerdict(table.qualified_name, "unverified", f"{reason}; {path}", (proof,))
                )
            elif not total:
                # …but anon cannot read the table at all, so "the direct read
                # already exposes these rows" is false — every row the door
                # returns is one the direct read withholds (measured: the
                # direct read is `permission denied` while the view returns
                # the policy-admitted row). The door is the only way in.
                tables.append(
                    TableVerdict(
                        table.qualified_name,
                        "leak",
                        f"anon reads {reads} via {path} — while a direct read "
                        "of the table is denied to anon",
                        (PolicyProof(outer.qualified_name, "leak", witness, None),),
                    )
                )
            else:
                proof = PolicyProof(outer.qualified_name, "leak", {}, None)
                # Two different reasons land here, and saying "including the
                # rows the direct anon leak withholds" is false for the
                # second: either the direct leak is partial, or it is total
                # but anon cannot actually read the table.
                direct = (
                    "including the rows the direct anon leak withholds"
                    if an_leak is None or an_leak.witness != {}
                    else "while a direct read of the table is denied to anon"
                )
                tables.append(
                    TableVerdict(
                        table.qualified_name,
                        "leak",
                        f"anon reads every row via {path} — {direct}",
                        (proof,),
                    )
                )
        else:  # unverified
            reason = next(
                (
                    p.reason
                    for p in (anv.proofs if anv else ())
                    if p.verdict == "unverified" and p.reason
                ),
                "anon isolation unproven",
            )
            proof = PolicyProof(outer.qualified_name, "unverified", None, reason)
            tables.append(
                TableVerdict(
                    table.qualified_name,
                    "unverified",
                    f"cannot prove the table denies anon reads ({reason}); {path}",
                    (proof,),
                )
            )
    tables.sort(key=lambda t: (t.qualified_name, t.proofs[0].policy))
    return Verification(tuple(tables), "reachability")


@dataclass(frozen=True)
class _ReachPath:
    """One anon-openable door onto an RLS table.

    `outer` is the view anon can SELECT from; `hops` the intermediate view
    names beneath it; `effective` the view whose owner Postgres evaluates the
    table's RLS as (the nearest enclosing `security_invoker = false` view on
    the path); `exempt` whether that owner escapes the table's RLS — `None`
    when the answer is undecidable here (`unknown_reason` says why); and
    `via_policy` when the owner is not exempt but the table's own policies
    grant it every row (a laundering definer view).
    """

    outer: Any
    table: Any
    hops: tuple[str, ...]
    effective: Any
    exempt: bool | None
    via_policy: bool = False
    unknown_reason: str | None = None
    # For a laundering door: the owner-session leak witness — `{}` when the
    # policies admit the owner every row, a characterizing row when only
    # some, `None` when conditional. The door is only that wide.
    owner_witness: dict[str, object] | None = None


def _inherit_closure(schema: Schema, role: str) -> frozenset[str] | None:
    """The roles whose privileges `role` holds — Postgres's `has_privs_of_role`:
    the upward closure over INHERIT memberships only (a NOINHERIT edge grants
    `SET ROLE`, not the privileges — measured: a NOINHERIT member's view got
    `permission denied`). `None` when the graph was not captured.
    """
    if schema.role_memberships is None:
        return None
    reach = {role}
    changed = True
    while changed:  # transitive closure; role graphs are tiny
        changed = False
        for edge in schema.role_memberships:
            if edge.inherit and edge.member in reach and edge.role not in reach:
                reach.add(edge.role)
                changed = True
    return frozenset(reach)


def _inherits_privs_of(schema: Schema, role: str, target: str) -> bool | None:
    """Does `role` hold `target`'s privileges? `None` = graph not captured."""
    if role == target:
        return True
    closure = _inherit_closure(schema, role)
    return None if closure is None else target in closure


def _effective_user_exempt(schema: Schema, eff: Any, table: Any) -> bool | None:
    """Is the effective RLS user (the owner of view `eff`) exempt from
    `table`'s RLS? Every clause below was measured on PG16 (see
    `build_reachability`): BYPASSRLS/superuser is exempt even under FORCE;
    FORCE strips ownership-based exemption; otherwise owning the table — or
    being owner-equivalent through an INHERIT membership — is exempt.
    """
    if eff is None:
        return False  # the anon caller itself: never exempt
    if eff.owner_bypasses_rls:
        return True
    if not eff.owner:
        return False  # pre-v25 snapshot: fail-closed, claim no bypass
    if table.force_rls:
        return False
    return _inherits_privs_of(schema, eff.owner, table.owner)


def _role_reads_relation(schema: Schema, eff: Any, rel: Any) -> bool | None:
    """Can the effective user (owner of view `eff`) SELECT from `rel` — a
    view on the path, or the base table itself?

    A superuser reads anything. BYPASSRLS alone does not: a BYPASSRLS
    non-superuser view owner got `permission denied for table` without a
    grant (measured) — it escapes the policies, not the privilege check.
    Otherwise: owning the relation; holding its owner's privileges (an
    INHERIT member — measured: every row through the chain, no grant at
    all); or a SELECT grant, table- or column-level, to PUBLIC or to a role
    in the effective user's INHERIT closure. A broken hop is a dead path
    (measured: `permission denied for view inner`, no leak). `None` when the
    graph is not captured and no direct grant decides it — report, never
    guess either way.
    """
    if eff is None or getattr(eff, "owner_is_superuser", False) or rel.owner == eff.owner:
        return True
    grantees = {g.role for g in rel.grants if "SELECT" in g.privileges} | {
        cg.role for cg in getattr(rel, "column_grants", ()) if "SELECT" in cg.privileges
    }
    if "PUBLIC" in grantees or eff.owner in grantees:
        return True
    closure = _inherit_closure(schema, eff.owner)
    if closure is None:
        return None
    if rel.owner in closure:
        return True
    # The predefined role `pg_read_all_data` confers SELECT on everything
    # without any grant of its own (measured: revoking the direct grant and
    # granting this role instead read the same rows through the same view).
    # Missing it turned a live bypass into total silence.
    if "pg_read_all_data" in closure:
        return True
    return bool(grantees & closure)


def _rls_tables_beneath(
    rel: Any,
    tables_by_key: dict[tuple[str, str], Any],
    views_by_key: dict[tuple[str, str], Any],
) -> list[Any]:
    """Every RLS-enabled table `rel` reads, through nested views as well.

    A matview whose query goes through another view names no table directly,
    so enumerating only its direct table refs contributed no verdict at all
    for the table underneath it.
    """
    found: dict[str, Any] = {}
    seen: set[tuple[str, str]] = set()

    def walk(node: Any) -> None:
        for ref in (node.direct_references or node.references):
            table = tables_by_key.get(ref)
            if table is not None:
                if table.rls_enabled:
                    found.setdefault(table.qualified_name, table)
                continue
            child = views_by_key.get(ref)
            if child is not None and ref not in seen:
                seen.add(ref)
                walk(child)

    walk(rel)
    return list(found.values())


def _reachability_paths(
    schema: Schema,
    outers: list[Any],
    tables_by_key: dict[tuple[str, str], Any],
    views_by_key: dict[tuple[str, str], Any],
    owner_verdict: Any,
    anon_roles: set[str],
) -> list[_ReachPath]:
    """Walk each anon-openable view down to the RLS tables it reaches.

    At each hop the effective RLS user becomes the view's owner if the view
    is `security_invoker = false`, else it is inherited from the enclosing
    hop (the caller — never exempt — at the top). Descending into a child
    view, and finally reading the base table, requires the effective user to
    be able to SELECT it (`_role_reads_relation`; the anonymous caller's own
    grants while no definer view has been entered). A materialized-view hop
    is reported `unverified`: its rows were captured at REFRESH time under
    the MATVIEW OWNER's RLS context (measured: a definer view over a
    superuser-refreshed matview handed anon every row), which is not
    modeled. A pre-v26 view (no `direct_references`) falls back to its
    collapsed `references`.

    A table is a door when the effective user is RLS-exempt, OR when the
    table's own policies grant that user rows (`owner_verdict` — the
    laundering case, the door only as wide as that admission). One path per
    (outer, table): a decided door wins over an undecided one, and a total
    one over a laundering one.
    """
    best: dict[tuple[str, str], _ReachPath] = {}

    def _width(p: _ReachPath) -> int:
        """How wide the door is — the WIDEST one under an outer view wins.

        Two laundering doors under one outer view used to collapse to
        whichever was walked first, so adding a NARROW door made a provable
        one disappear: measured, `outer → c1(ownera, tenant='a')` and
        `outer → c2(ownerb, USING true)` reported UNVERIFIED together while
        `c2` alone reported LEAK with every row.
        """
        if p.exempt is not True:
            return 0                      # undecided
        if not p.via_policy:
            return 3                      # exempt owner: every row
        return 2 if p.owner_witness == {} else 1   # laundering: total, then partial

    def record(p: _ReachPath) -> None:
        key = (p.outer.qualified_name, p.table.qualified_name)
        prior = best.get(key)
        if prior is None or _width(p) > _width(prior):
            best[key] = p

    def unverified(outer: Any, t: Any, hops: tuple[str, ...], eff: Any, why: str) -> None:
        record(_ReachPath(outer, t, hops, eff, None, unknown_reason=why))

    def walk(view: Any, hops: tuple[str, ...], outer: Any, seen: frozenset[tuple[str, str]]) -> None:
        # Each hop decides its OWN effective user; nothing is inherited from
        # the enclosing hop, which is why this takes no `eff` argument.
        # `security_invoker = true` RESETS the effective user to the session
        # user — it does not inherit the enclosing definer view's owner.
        # Measured on PG16: definer(owner BYPASSRLS) → invoker → table
        # returned the policy-filtered row, not every row, and revoking the
        # ANON caller's own SELECT on the table denied the read outright.
        eff = None if view.security_invoker else view
        refs = view.direct_references or view.references
        for ref in refs:
            child = views_by_key.get(ref)
            if child is not None:
                if ref in seen:
                    continue
                readable = (
                    _role_reads_relation(schema, eff, child)
                    if eff is not None
                    else _relation_is_anon_selectable(schema, child, anon_roles)
                )
                if readable is False:
                    continue  # broken intermediate grant: dead path
                child_hops = hops + (child.qualified_name,)
                if child.is_materialized:
                    for t in _rls_tables_beneath(child, tables_by_key, views_by_key):
                        unverified(outer, t, child_hops, child, (
                            f"{child.qualified_name} is a materialized view: its rows were "
                            "captured at REFRESH time under the matview owner's RLS "
                            "context, which is not modeled"))
                    continue
                if readable is None and eff is not None:
                    # Undecidable hop — only `_role_reads_relation` returns
                    # None, and that branch runs only with an effective user.
                    # Report it rather than guess either way, walking nested
                    # views for the same reason the matview branch above does.
                    for t in _rls_tables_beneath(child, tables_by_key, views_by_key):
                        unverified(outer, t, child_hops, eff, (
                            f"role-membership graph not captured; cannot decide whether "
                            f"{eff.owner} can read {child.qualified_name}"))
                    continue
                walk(child, child_hops, outer, seen | {ref})
                continue
            table = tables_by_key.get(ref)
            if table is None or not table.rls_enabled or eff is None:
                continue
            reads = _role_reads_relation(schema, eff, table)
            if reads is False:
                continue  # no SELECT on the base table: permission denied, dead path
            exempt = _effective_user_exempt(schema, eff, table)
            if exempt is True and reads is None:
                unverified(outer, table, hops, eff, (
                    f"role-membership graph not captured; cannot decide whether "
                    f"{eff.owner} holds SELECT on {table.qualified_name}"))
            elif exempt is True:
                record(_ReachPath(outer, table, hops, eff, True))
            elif exempt is None:
                unverified(outer, table, hops, eff, (
                    f"role-membership graph not captured; cannot decide whether "
                    f"{eff.owner} holds table owner {table.owner}'s privileges"))
            else:
                ov = owner_verdict(eff.owner, table)
                if ov is not None and ov.verdict == "leak":
                    if reads is None:
                        unverified(outer, table, hops, eff, (
                            f"role-membership graph not captured; cannot decide whether "
                            f"{eff.owner} holds SELECT on {table.qualified_name}"))
                        continue
                    leak = next(p for p in ov.proofs if p.verdict == "leak")
                    record(_ReachPath(outer, table, hops, eff, True, via_policy=True,
                                      owner_witness=leak.witness))
                elif ov is not None and ov.verdict == "unverified":
                    unverified(outer, table, hops, eff, (
                        f"cannot decide whether the table's policies admit rows to "
                        f"{eff.owner} under the anonymous auth context"))

    for outer in outers:
        walk(outer, (), outer, frozenset({(outer.schema, outer.name)}))
    return sorted(best.values(), key=lambda p: (p.table.qualified_name, p.outer.qualified_name))


def _sql_body_parses(secdef_fn: Any) -> bool:
    """Whether a SECDEF function body is a parseable SQL statement — the same
    analyzability gate VIEW004 uses, checked WITHOUT emitting its warnings (the
    body parser is only called below when this is True)."""
    if secdef_fn.language != "sql":
        return False
    import pglast  # noqa: PLC0415 — lazy; pglast is a heavy optional path

    from pgrls.ast_utils import function_body_sql  # noqa: PLC0415

    try:
        pglast.parse_sql(function_body_sql(secdef_fn.body))
    except pglast.parser.ParseError:
        return False
    return True


def _escalation_anon_rollup(
    reads: set[str],
    an_by_table: dict[str, TableVerdict],
    total_read: Callable[[str], bool] | None = None,
) -> tuple[Verdict, dict[str, object] | None, str]:
    """Roll up the escalation verdict for a SECDEF body that reads `reads`
    (RLS-table qnames), from each read table's ``anon`` verdict. Same
    discrimination as the owner-bypass case: an anon-isolated table → leak (the
    function exposes rows anon couldn't read); a table the direct anon read
    already returns ENTIRELY → the function exposes nothing new; a partial anon
    leak → leak; an unprovable predicate → unverified.

    "Entirely" must hold in EVERY modelled anonymous session, which is what
    `total_read` answers. A `{}` witness only says the first leaking session
    read everything — measured: `USING (auth.role() = 'anon')` gave the
    anon-key caller every row and a JWT-less one none, so an anon-callable
    SECDEF function over it was cleared while a JWT-less anon read every row
    through it."""
    verdicts: list[Verdict] = []
    for tq in sorted(reads):
        tv = an_by_table.get(tq)
        if tv is None or tv.verdict == "isolated":
            verdicts.append("leak")
        elif tv.verdict == "leak":
            already = total_read(tq) if total_read is not None else False
            verdicts.append("isolated" if already else "leak")
        else:
            verdicts.append("unverified")
    if "leak" in verdicts:
        return "leak", {}, " — an anonymous caller of the function reads rows its own RLS would deny"
    if "unverified" in verdicts:
        return "unverified", None, " — anon isolation is unprovable on a read table"
    return (
        "isolated",
        None,
        " — anon already reads those rows directly; the function exposes nothing new",
    )


def _has_range_function(stmt: Any) -> bool:
    """Whether `stmt` has a set-returning function call as a ``FROM`` source (a
    ``RangeFunction``). Such a source is not a ``RangeVar``, so extract_range_vars
    never surfaces it — walk for it directly."""
    from pglast.ast import Node, RangeFunction  # noqa: PLC0415

    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, RangeFunction):
            found = True
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(stmt)
    return found


# Common built-in scalar/aggregate functions that operate on their arguments (or
# system state) and never read a user table — safe to see in a SECDEF body even
# unqualified. An introspected function body (raw `pg_proc.prosrc`) stores
# builtins as the author wrote them — normally WITHOUT a schema (a bare
# `count(*)`, not `pg_catalog.count(*)`) — so the schema check alone can't
# recognize them. A builtin *missing* from this set merely falls back to
# abstention (sound). The set holds only genuine `pg_catalog` builtins and omits
# anything that touches data (`nextval`, `query_to_xml`, …); the one residual
# trust widening is a user function deliberately *named after* a builtin and
# called bare — it would be cleared rather than abstained, negligible in
# practice and in line with how bare auth-function names are already trusted.
_SAFE_BUILTIN_FUNCS: frozenset[str] = frozenset({
    # aggregates
    "count", "sum", "avg", "min", "max", "array_agg", "string_agg", "json_agg",
    "jsonb_agg", "json_object_agg", "jsonb_object_agg", "bool_and", "bool_or",
    "every", "bit_and", "bit_or", "stddev", "stddev_pop", "stddev_samp",
    "variance", "var_pop", "var_samp",
    # string
    "lower", "upper", "initcap", "length", "char_length", "character_length",
    "bit_length", "octet_length", "trim", "btrim", "ltrim", "rtrim", "substr",
    "substring", "left", "right", "lpad", "rpad", "replace", "translate",
    "split_part", "concat", "concat_ws", "format", "reverse", "repeat",
    "position", "strpos", "overlay", "md5", "starts_with", "to_hex", "ascii",
    "chr", "quote_ident", "quote_literal", "quote_nullable",
    # numeric
    "abs", "ceil", "ceiling", "floor", "round", "trunc", "sign", "mod", "power",
    "sqrt", "cbrt", "exp", "ln", "log", "log10", "div", "gcd", "lcm",
    "greatest", "least", "width_bucket",
    # null / conditional
    "coalesce", "nullif",
    # date / time
    "now", "current_date", "current_time", "current_timestamp", "localtime",
    "localtimestamp", "clock_timestamp", "statement_timestamp",
    "transaction_timestamp", "age", "date_part", "date_trunc", "extract",
    "make_date", "make_time", "make_timestamp", "make_timestamptz",
    "make_interval", "to_char", "to_date", "to_timestamp", "to_number",
    # json / jsonb
    "to_json", "to_jsonb", "json_build_object", "jsonb_build_object",
    "json_build_array", "jsonb_build_array", "json_object", "jsonb_object",
    "json_extract_path", "jsonb_extract_path", "json_extract_path_text",
    "jsonb_extract_path_text", "jsonb_set", "jsonb_insert", "jsonb_strip_nulls",
    "jsonb_pretty", "json_typeof", "jsonb_typeof", "json_array_length",
    "jsonb_array_length", "row_to_json", "array_to_json",
    # array
    "array_length", "cardinality", "array_append", "array_prepend", "array_cat",
    "array_remove", "array_replace", "array_position", "array_positions",
    "array_to_string", "string_to_array", "array_ndims", "array_lower",
    "array_upper",
    # type / misc (read no user data)
    "pg_typeof", "format_type", "gen_random_uuid",
})


def _has_opaque_funccall(stmt: Any, auth_functions: frozenset[str] | set[str]) -> bool:
    """Whether `stmt` contains a *scalar* function call (a ``FuncCall``, not a
    ``FROM``-clause ``RangeFunction``) to a function we cannot see through — one
    that is neither a known auth/session function nor a recognized built-in.
    Such a call may transitively read an RLS table (through the SECDEF owner's
    bypass) that the range-var walk never surfaces — e.g. ``SELECT get_secret()``
    or ``SELECT 1 WHERE leaks()`` — so a body containing one is opaque
    (UNVERIFIED), the same treatment a set-returning function in ``FROM`` already
    gets. Auth/session calls (``auth.uid()``), ``pg_catalog`` /
    ``information_schema``-qualified calls, and bare calls to a known built-in
    (``count``, ``lower`` — see ``_SAFE_BUILTIN_FUNCS``) do not read user tables
    and so do not, by themselves, force abstention."""
    from pglast.ast import FuncCall, Node  # noqa: PLC0415

    from pgrls.ast_utils import func_name_parts  # noqa: PLC0415

    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, FuncCall):
            qualified, bare = func_name_parts(n)
            fn_schema = (
                qualified.rsplit(".", 1)[0]
                if qualified and "." in qualified
                else None
            )
            if not (
                qualified in auth_functions
                or bare in auth_functions
                or fn_schema in ("pg_catalog", "information_schema")
                or (fn_schema is None and bare in _SAFE_BUILTIN_FUNCS)
            ):
                found = True
                return
            # A recognized-safe outer call may still wrap an opaque call in its
            # arguments (``coalesce(get_secret(), 0)``) — keep walking children.
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(stmt)
    return found


def _secdef_body_unresolved(
    parsed: Any,
    base_quals: set[tuple[str, str]],
    base_bares: set[str],
    auth_functions: frozenset[str] | set[str],
) -> bool:
    """Whether a SECDEF body reads from a data source we cannot see through — a
    *view*, a relation outside the introspected base tables, a set-returning
    *function* call in ``FROM``, or a *scalar* function call (``SELECT
    get_secret()``) to a non-builtin, non-auth function. Such a source may
    transitively read an RLS table the range-var walk never sees, so a body that
    has one must be treated as opaque (UNVERIFIED) rather than cleared.

    CTE names are a local alias, not a data source — but they scope **only
    within their own statement** (a CTE in one statement of a multi-statement
    body does not bind a later statement's relation refs), so they are collected
    per-statement, mirroring VIEW004's body parser. And a CTE whose name
    *collides with a base table* shadows it: the body parser then treats a bare
    ref to that name as the CTE, hiding any read of the real table inside the
    CTE definition — a blind spot we cannot reason about, so we abstain."""
    from pgrls.ast_utils import extract_range_vars  # noqa: PLC0415
    from pgrls.rules.view004 import _cte_names  # noqa: PLC0415

    for raw in parsed:
        stmt = getattr(raw, "stmt", raw)
        cte_names = _cte_names(stmt)
        if cte_names & base_bares:
            return True
        for schemaname, relname in extract_range_vars(stmt):
            if relname in cte_names:
                continue
            if schemaname is not None:
                if (schemaname, relname) not in base_quals:
                    return True
            elif relname not in base_bares:
                return True
        if _has_range_function(stmt):
            return True
        if _has_opaque_funccall(stmt, auth_functions):
            return True
    return False


def _escalation_secdef_findings(
    schema: Schema, auth_functions: set[str] | None, anon_roles: set[str]
) -> list[TableVerdict]:
    """SEC042 escalation: an anon / ``PUBLIC``-EXECUTE-able SECURITY DEFINER
    function owned by an RLS-exempt role (superuser / ``BYPASSRLS``) runs its
    body with the owner's RLS exemption, so an anonymous caller (``POST
    /rpc/fn``) reads whatever RLS tables the body touches — rows its own RLS
    would deny. We prove that against each read table's ``anon`` verdict.

    Reuses VIEW004's body parser to extract the RLS tables a SQL body reads. A
    body is **unverified** when it is opaque (PL/pgSQL or dynamic SQL) *or* when
    it reads from a source we cannot see through — a view, a function-call FROM,
    or a relation outside the introspected base tables — since that source may
    transitively read a protected table. Only a body whose every data source is
    a known *non-RLS* base table is cleared (not a finding). ``anon_roles`` is
    the SEC042 exposure set (default ``{anon, PUBLIC}``).

    The VIEW004 view-mediated *caller* case — a view selecting a SECDEF call —
    is still out of scope here, but no longer for the reason this comment used
    to give: `View.grants` HAS been captured since snapshot v23 (SEC052), so
    "the model does not capture it" is stale. What is missing is the join
    itself; ``--mode reachability`` covers the view-over-*table* bypass, and a
    view whose body calls a SECDEF function is the remaining case.
    """
    secdef_fns = schema.security_definer_functions
    rls_tables = {(t.schema, t.name) for t in schema.tables if t.rls_enabled}
    if not secdef_fns or not rls_tables:
        return []
    an = build_verification(
        schema, auth_functions=auth_functions, mode="anon", anon_roles=anon_roles
    )
    an_by_table = {t.qualified_name: t for t in an.tables}
    # "the direct anon read already returns this table entirely" must hold in
    # EVERY modelled anonymous session, not just the first one that leaked.
    _tables_by_q = {t.qualified_name: t for t in schema.tables}
    _esc_gucs = _anon_set_gucs(schema, anon_roles)
    _esc_roles = anon_roles if anon_roles else {"anon", "PUBLIC"}
    _esc_memo: dict[str, bool] = {}
    # EXECUTE reaches through the role graph like every other anon check in
    # this module: measured, a function granted only to `readers` with
    # `GRANT readers TO anon` was callable by anon (has_function_privilege
    # = t) and read every row, while a literal set intersection against
    # {anon, PUBLIC} reported "No reachable escalation paths".
    # A SECDEF body running as the TABLE's own owner skips that table's
    # policies whenever the table is not FORCE'd — an exemption relative to
    # the table, which `owner_bypasses_rls` (superuser / BYPASSRLS) does not
    # capture. Measured: anon read 0 rows directly and every row through such
    # a function, while this mode reported "No reachable escalation paths".
    _owner_exempt_anywhere = {
        t.owner
        for t in schema.tables
        if t.rls_enabled and not t.force_rls and t.owner
    }

    def _fn_exempt_for(f: Any, table: Any) -> bool:
        if f.owner_bypasses_rls:
            return True
        owner = getattr(f, "owner", "") or ""
        if not owner or table is None or table.force_rls or not table.owner:
            return False
        return _inherits_privs_of(schema, owner, table.owner) is True

    _exec_reachable = (
        set(_esc_roles)
        | set(_anon_priv_closure(schema, _esc_roles) or frozenset())
        | {"PUBLIC"}
    )

    def total_read(qname: str) -> bool:
        """Does anon ALREADY read this whole table directly?

        Both halves are required. `--mode anon` decides what the predicate
        admits; it never checks privileges. Measured: `USING (true)` with no
        grant to anon is `permission denied` on a direct read while an
        anon-callable SECURITY DEFINER function over it returned every row —
        the SEC042 threat exactly, and ceding cleared it.
        """
        table = _tables_by_q.get(qname)
        return (
            table is not None
            and _anon_reads_every_row(
                schema, table, auth_functions, _esc_roles, _esc_gucs, _esc_memo
            )
            and _anon_holds_select(
                schema, table, _esc_roles, table_level_only=True
            )
        )

    bare_to_qual: dict[str, list[tuple[str, str]]] = {}
    for s, n in sorted(rls_tables):
        bare_to_qual.setdefault(n, []).append((s, n))
    base_quals = {(t.schema, t.name) for t in schema.tables}
    base_bares = {t.name for t in schema.tables}
    # Auth/session calls in a body don't read user tables — exclude them (and
    # pg_catalog builtins) from the opaque-scalar-call abstention. `None` means
    # "use the default set", matching the provers' resolution.
    resolved_auth = (
        auth_functions if auth_functions is not None else DEFAULT_AUTH_FUNCTIONS
    )
    import pglast  # noqa: PLC0415 — heavy optional parser path
    from pgrls.ast_utils import function_body_sql  # noqa: PLC0415
    from pgrls.rules.view004 import _secdef_fn_leaks  # noqa: PLC0415 — body parser reuse

    by_qname: dict[str, list[Any]] = {}
    for f in secdef_fns:
        by_qname.setdefault(f.qualified_name, []).append(f)

    findings: list[TableVerdict] = []
    for qname in sorted(by_qname):
        # Candidate iff some overload is owner-RLS-exempt AND anon-executable.
        candidate = [
            f
            for f in by_qname[qname]
            if (
                f.owner_bypasses_rls
                or (getattr(f, "owner", "") or "") in _owner_exempt_anywhere
            )
            and (set(f.execute_roles) & _exec_reachable)
        ]
        if not candidate:
            continue
        reads: set[str] = set()
        any_opaque = False
        any_unseen = False  # reads via a view / function / unknown relation
        for f in candidate:
            if not _sql_body_parses(f):
                any_opaque = True
                continue
            reads |= _secdef_fn_leaks(f, qname, rls_tables, bare_to_qual)
            parsed = pglast.parse_sql(function_body_sql(f.body))
            if _secdef_body_unresolved(
                parsed, base_quals, base_bares, resolved_auth
            ):
                any_unseen = True
        inconclusive = any_opaque or any_unseen
        roles = ", ".join(
            sorted({r for f in candidate for r in (set(f.execute_roles) & _exec_reachable)})
        )
        head = (
            f"SECURITY DEFINER function EXECUTE-able by {roles}, owned by an "
            "RLS-exempt role"
        )
        if reads:
            # Exemption is relative to the TABLE, so drop the reads for which
            # no candidate overload's owner is actually exempt — otherwise a
            # function owned by an ordinary role would be credited with a
            # bypass it does not have.
            reads = {
                q
                for q in reads
                if any(_fn_exempt_for(f, _tables_by_q.get(q)) for f in candidate)
            }
        if reads:
            verdict, witness, tail = _escalation_anon_rollup(
                reads, an_by_table, total_read
            )
            if inconclusive and verdict == "isolated":
                # The reads we *can* see prove "nothing new", but the function
                # also has an opaque overload or reads via a view/function we
                # cannot see through, which may read a protected table — so we
                # cannot clear it. Abstain rather than false-clear.
                verdict, witness, tail = (
                    "unverified",
                    None,
                    " — but it also reads via an opaque body or an unseen "
                    "view/function that may read an RLS table",
                )
            note = f"{head}, reads {', '.join(sorted(reads))}{tail}"
            reason = tail.strip(" —") if verdict == "unverified" else None
            proof = PolicyProof(sorted(reads)[0], verdict, witness, reason)
            findings.append(TableVerdict(qname, verdict, note, (proof,)))
        elif inconclusive:
            why = (
                "has an opaque body (PL/pgSQL or dynamic SQL)"
                if any_opaque and not any_unseen
                else "reads via a view, a function, or a relation outside the "
                "analyzed schema"
                if any_unseen and not any_opaque
                else "has an opaque body and reads via an unseen view/function"
            )
            note = f"{head}, {why} — cannot prove what it reads"
            proof = PolicyProof(qname, "unverified", None, why)
            findings.append(TableVerdict(qname, "unverified", note, (proof,)))
        # else: every data source is a known non-RLS base table → the body
        # provably reads no protected data → not a finding.
    return findings


def _witness_phrase(witness: dict[str, object] | None, mode: Mode = "anon") -> str:
    """Human phrase for a leak witness, per threat model.

    A characterizing row, the unconditional case (``{}`` — every row / a row of
    any other tenant), or a conditional leak no single row characterizes
    (``None``). The cross-tenant phrasing frames the row as another tenant's;
    the write phrasing covers every way a write crosses tenants: stamping a new
    row for one, taking over its existing row, or deleting it.
    """
    if mode == "escalation":
        # The bypass is unconditional (witness is always ``{}`` — every row);
        # the *path* (owner reachability, or an anon-callable SECDEF function) is
        # carried in the table note.
        return (
            "every row is readable through a reachable escalation path that "
            "bypasses RLS"
        )
    if mode == "write":
        if witness is None:
            return (
                "a conditional cross-tenant write — no single row characterizes it"
            )
        if not witness:
            return "another tenant's row can be written or deleted"
        pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
        return f"another tenant's row with {pairs} can be written or deleted"
    if mode == "cross-tenant":
        if witness is None:
            return "a conditional cross-tenant leak — no single row characterizes it"
        if not witness:
            return "a row of any other tenant is readable"
        pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
        return f"a row of another tenant with {pairs} is readable"
    if witness is None:
        return "a conditional leak — no single row characterizes it"
    if not witness:
        return "every row is anonymously readable"
    pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
    return f"a row with {pairs} is anonymously readable"


def _witness_scope(
    verdict: Verdict, witness: dict[str, object] | None, mode: Mode
) -> str | None:
    """Machine-readable witness scope for JSON. ``None`` off the leak path,
    ``conditional`` (no single row), ``row`` (a characterizing row), or the
    unconditional bucket — ``all_rows`` for anon, ``any_other_tenant`` for
    cross-tenant / write (an empty such witness is NOT "every row")."""
    if verdict != "leak":
        return None
    if mode == "escalation":
        return "owner_bypass"  # every row, via the reachable owner's RLS exemption
    if witness is None:
        return "conditional"
    if not witness:
        return "any_other_tenant" if mode in ("cross-tenant", "write") else "all_rows"
    return "row"


def _summary_line(v: Verification) -> str:
    s = v.summary
    return (
        f"{s['tables']} RLS {pluralize(s['tables'], 'table')}: "
        f"{s['isolated']} proven isolated, {s['leak']} leaking, "
        f"{s['unverified']} unverified."
    )


def _verdict_detail(t: TableVerdict, mode: Mode) -> str:
    """The DETAIL cell for a table verdict — the witness phrase (leak), the
    abstain reason (unverified), or the no-read note (isolated)."""
    if t.verdict == "leak":
        leak = next((p for p in t.proofs if p.verdict == "leak"), None)
        detail = _witness_phrase(leak.witness if leak else None, mode)
        if t.note:  # escalation carries the reach path here (else None)
            detail = f"{detail} — {t.note}"
        return detail
    if t.verdict == "unverified":
        return next(
            (p.reason for p in t.proofs if p.verdict == "unverified" and p.reason),
            t.note or "no claim",
        )
    return t.note or _NO_READ_DETAIL[mode]


def render_text(v: Verification) -> str:
    if not v.tables:
        if v.mode == "escalation":
            return "No reachable escalation paths to verify."
        if v.mode == "reachability":
            return "No anon-reachable view path onto an RLS table was found."

        return "No RLS-enabled tables to verify."
    headers = ("TABLE", "VERDICT", "DETAIL")
    rows = [
        (
            safe_location(t.qualified_name),
            _VERDICT_LABEL[t.verdict],
            _verdict_detail(t, v.mode),
        )
        for t in v.tables
    ]
    out = render_text_table(headers, rows)
    out.append("")
    out.append(_summary_line(v))
    return "\n".join(out)


def _table_json(t: TableVerdict, mode: Mode) -> dict[str, object]:
    """One table's verdict as a JSON-serializable dict (shared by ``render_json``
    and the ``--against`` delta renderer)."""
    return {
        "table": t.qualified_name,
        "verdict": t.verdict,
        "note": t.note,
        "policies": [
            {
                "policy": p.policy,
                "verdict": p.verdict,
                "witness": p.witness,
                "witness_scope": _witness_scope(p.verdict, p.witness, mode),
                "reason": p.reason,
            }
            for p in t.proofs
        ],
    }


def render_json(v: Verification) -> str:
    payload = {
        "mode": v.mode,
        "summary": v.summary,
        "tables": [_table_json(t, v.mode) for t in v.tables],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_delta_text(delta: LeakDelta) -> str:
    """Human report for ``verify --against`` — which leaks this change
    introduced, which pre-existed, which it fixed."""
    out = [f"pgrls verify --against  (mode: {delta.mode})", ""]
    if delta.new_leaks:
        out.append(f"NEW leaks introduced by this change ({len(delta.new_leaks)}):")
        rows = [
            (safe_location(t.qualified_name), _verdict_detail(t, delta.mode))
            for t in delta.new_leaks
        ]
        out.extend(render_text_table(("TABLE", "DETAIL"), rows))
    else:
        out.append("No new leaks introduced by this change.")
    out.append("")
    if delta.new_unverified:
        names = ", ".join(safe_location(t.qualified_name) for t in delta.new_unverified)
        out.append(
            f"Newly unverified (was proven isolated or absent in the baseline) "
            f"({len(delta.new_unverified)}): {names}"
        )
    if delta.preexisting_leaks:
        names = ", ".join(
            safe_location(t.qualified_name) for t in delta.preexisting_leaks
        )
        out.append(
            f"Pre-existing leaks, not from this change "
            f"({len(delta.preexisting_leaks)}): {names}"
        )
    if delta.fixed_leaks:
        out.append(
            f"Leaks fixed by this change ({len(delta.fixed_leaks)}): "
            f"{', '.join(delta.fixed_leaks)}"
        )
    s = delta.summary
    out.append("")
    out.append(
        f"{s['new_leaks']} new, {s['preexisting_leaks']} pre-existing, "
        f"{s['fixed_leaks']} fixed."
    )
    return "\n".join(out)


def render_delta_json(delta: LeakDelta) -> str:
    payload = {
        "mode": delta.mode,
        "against": True,
        "summary": delta.summary,
        "new_leaks": [_table_json(t, delta.mode) for t in delta.new_leaks],
        "preexisting_leaks": [
            _table_json(t, delta.mode) for t in delta.preexisting_leaks
        ],
        "fixed_leaks": list(delta.fixed_leaks),
        "new_unverified": [_table_json(t, delta.mode) for t in delta.new_unverified],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_sarif(v: Verification, *, strict: bool = False) -> str:
    """Render a Verification as a SARIF v2.1.0 document for GitHub Code Scanning.

    Reuses lint's `format_sarif` by projecting each *actionable* table verdict
    into a `pgrls.violations.Violation` — the exact precedent `pgrls diff` sets
    with `_change_to_violation`. This keeps the SARIF version, `$schema`,
    `tool.driver` block, severity→level mapping, and the empty-location guard in
    ONE place, so verify, lint, and diff can never drift.

    The result-set mirrors verify's exit-code contract — a result is present iff
    the run would fail the gate:

    * **LEAK** → one `error`-level result per leaking table, located at
      ``schema.table.policy`` (the leaking policy), message = the witness phrase.
      Always fails the build.
    * **PROVEN (isolated)** → no result (the SARIF "all clear" state).
    * **UNVERIFIED** → no result by default (it does not fail a non-strict gate);
      under ``strict`` one `note`-level result per unverified table, located at
      ``schema.table``, message = the table's unverified reason — matching the
      ``--strict`` gate, which *does* fail on UNVERIFIED.

    The prover is one rule per ``--mode`` — the five ids in ``_SARIF_RULE_ID``
    (anon, cross-tenant, write, escalation, reachability); a strict UNVERIFIED
    note reuses the same
    rule id (its `defaultConfiguration.level` stays `error` while the per-result
    `level` is `note` — per-result level always wins, exactly as in lint).

    `strict` is keyword-only with a `False` default so the function still
    satisfies the 1-arg renderer signature `make_dispatcher` expects; the CLI
    passes ``strict=`` through directly for the SARIF case (see cli.verify).
    """
    rule_id = _SARIF_RULE_ID[v.mode]
    title = _SARIF_RULE_TITLE[v.mode]
    violations: list[Violation] = []
    for t in v.tables:
        if t.verdict == "leak":
            leak = next((p for p in t.proofs if p.verdict == "leak"), None)
            violations.append(
                Violation(
                    rule_id=rule_id,
                    severity="error",
                    title=title,
                    message=(
                        f"{t.qualified_name}: "
                        + _witness_phrase(leak.witness if leak else None, v.mode)
                        + (f" — {t.note}" if t.note else "")
                    ),
                    # Pin the finding to the leaking policy (mirrors lint's
                    # schema.table.policy fullyQualifiedName). Fall back to the
                    # table when no representative leak proof exists (defensive —
                    # a leak rollup always has at least one leak proof).
                    location=(
                        f"{t.qualified_name}.{leak.policy}"
                        if leak
                        else t.qualified_name
                    ),
                )
            )
        elif strict and t.verdict == "unverified":
            # Same table-level reason render_text surfaces.
            reason = next(
                (p.reason for p in t.proofs if p.verdict == "unverified" and p.reason),
                t.note or "no claim",
            )
            violations.append(
                Violation(
                    rule_id=rule_id,
                    severity="info",  # → SARIF `note` (below-warning, lint-consistent)
                    title=title,
                    message=f"{t.qualified_name}: {reason}",
                    location=t.qualified_name,
                )
            )
    return format_sarif(violations)


# `render_sarif`'s `strict` is keyword-only with a default, so it type-checks as
# the 1-arg renderer `make_dispatcher` calls — the dispatcher path yields the
# non-strict SARIF. The CLI special-cases `--strict` by calling
# `render_sarif(v, strict=True)` directly rather than threading the flag through
# the shared 1-arg dispatcher (which coverage/report/perf/history also use).
render, VERIFY_FORMATS = make_dispatcher(
    {"text": render_text, "json": render_json, "sarif": render_sarif}
)
