"""Effective tenant-isolation proof for `pgrls verify`.

Where `pgrls lint` *flags* a suspicious policy (SEC004 / SEC038) and `pgrls
matrix` *summarizes* who-can-read-what, `pgrls verify` **proves** — with Z3 —
a concrete safety property and hands back a counterexample when it fails. Two
complementary threat models (`--mode`):

* ``anon`` (default) — for every RLS-protected table, can an *anonymous*
  session (every auth function — auth.uid()/role()/jwt(), current_setting(...)
  — returning NULL, the unauthenticated state) read any row?
* ``cross-tenant`` — can a session authenticated as *one* tenant read a
  *different* tenant's row? For the policy's own tenant-scoping equality
  ``<column> = <session identity>``, a row is exposed iff it can be visible
  while ``column`` differs from the session's tenant.
* ``write`` — can a session authenticated as *one* tenant **write** (INSERT or
  UPDATE) a row stamped for a *different* tenant? Same satisfiability question
  as ``cross-tenant``, but proven over each write policy's *effective
  write-check* — its ``WITH CHECK`` when present, else (for ``FOR UPDATE`` /
  ``FOR ALL``) the ``USING`` that Postgres reuses as the new-row check. This is
  the most CVE-adjacent footgun (CVE-2025-48757): a policy that scopes reads but
  not writes lets a tenant stamp data for another tenant. The write-side lint
  rules SEC006 / SEC020 / SEC028 / SEC040 are its heuristic fallback.

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
  decidable fragment, the solver timed out, or (cross-tenant) the policy has no
  single tenant-scoping equality to verify against. This is where the verifier
  *degrades to the linter* — run `pgrls lint` for the heuristic rules.

Scope: both modes reason over each table's permissive ``SELECT`` / ``ALL``
policies. A *leaking* permissive policy on a table that also carries a
``RESTRICTIVE`` read floor is reported ``unverified`` rather than risk an
unsound verdict — v1 does not combine restrictive floors into the proof; an
already-proven-``isolated`` permissive policy stays ``isolated`` (a restrictive
floor only narrows access). ``cross-tenant`` mode verifies the single
``<column> = <session identity>`` shape `pgrls generate` emits; a total leak
(``USING (true)``) carries no scoping equality and is ``unverified`` there —
but is already caught as an anon leak. Tables with RLS disabled are out of
scope (that is SEC001's job, not an isolation proof).
"""
from __future__ import annotations

import json
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

# The functions treated as NULL under an anonymous session (single source of
# truth — the SEC038 / 3VL encoder's default). `pgrls verify --auth-function`
# extends this set with a project's own auth helper.
DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset(_DEFAULT_AUTH_FUNCTIONS)

Verdict = Literal["isolated", "leak", "unverified"]

# The threat models `pgrls verify` can prove. `anon` (default): can an
# *unauthenticated* session read any row? `cross-tenant`: can a session
# authenticated as one tenant read a *different* tenant's row? `write`: can such
# a session *write* (INSERT/UPDATE) a row stamped for another tenant? They are
# complementary — the inverted `auth.uid() IS NULL OR …` policy leaks to anon
# but correctly scopes authenticated tenants, so it is a leak in `anon` mode
# and isolated in `cross-tenant` mode.
Mode = Literal["anon", "cross-tenant", "write", "escalation"]

# `write` reuses the cross-tenant prover verbatim — write-isolation is the same
# satisfiability question (`is_true ∧ column != session_tenant` SAT?), just
# applied to the policy's effective WRITE-check instead of its USING.
_PROVERS = {
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
        "no provable tenant-scoping equality (or outside the decidable fragment)"
    ),
    "write": (
        "no provable tenant-scoping write-check "
        "(or outside the decidable fragment)"
    ),
}

# Reason when the AST the prover needs is absent (snapshot without parsed ASTs).
_NO_AST_REASON = {
    "anon": "USING not available",
    "cross-tenant": "USING not available",
    "write": "write-check not available",
}

_READ_COMMANDS = ("ALL", "SELECT")
# Commands whose policies can gate a WRITE (new-row check). SELECT/DELETE carry
# no write-check and never gate INSERT/UPDATE, so they are excluded from `write`.
_WRITE_COMMANDS = ("ALL", "INSERT", "UPDATE")

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


def _checked_ast(policy: Policy, mode: Mode) -> Any:
    """The AST the prover should check for `policy` under `mode`: the effective
    write-check for ``write``, else the policy's ``USING``."""
    return effective_write_check(policy) if mode == "write" else policy.using_ast

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
}
_SARIF_RULE_TITLE: dict[Mode, str] = {
    "anon": "Anonymous read-isolation proof",
    "cross-tenant": "Cross-tenant read-isolation proof",
    "write": "Cross-tenant write-isolation proof",
    "escalation": "Reachable owner-bypass escalation proof",
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
        counts = {"isolated": 0, "leak": 0, "unverified": 0}
        for t in self.tables:
            counts[t.verdict] += 1
        return {"tables": len(self.tables), **counts}


def _rollup(proofs: list[PolicyProof]) -> Verdict:
    """A table is a leak if any policy leaks; else unverified if any policy is
    unverified; else (every policy proven isolated) isolated."""
    if any(p.verdict == "leak" for p in proofs):
        return "leak"
    if any(p.verdict == "unverified" for p in proofs):
        return "unverified"
    return "isolated"


def build_verification(
    schema: Schema,
    *,
    auth_functions: set[str] | None = None,
    mode: Mode = "anon",
) -> Verification:
    """Prove tenant isolation for every RLS-enabled table in `schema`.

    `mode` selects the threat model: ``"anon"`` (default) proves no row is
    readable by an *unauthenticated* session; ``"cross-tenant"`` proves no row
    of one tenant is readable by a session authenticated as a *different*
    tenant; ``"write"`` proves no such session can *write* a row stamped for
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

    ``escalation`` is a different shape — it composes the cross-tenant result
    with the role-reachability graph rather than walking policies directly — so
    it is dispatched to `build_escalation`.
    """
    if mode == "escalation":
        return build_escalation(schema, auth_functions=auth_functions)
    prove = _PROVERS[mode]
    commands = _MODE_COMMANDS[mode]
    floor_kind = "write" if mode == "write" else "read"
    tables: list[TableVerdict] = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        if not table.rls_enabled:
            continue  # not an isolation claim — SEC001's domain, not verify's
        relevant = [p for p in table.policies if p.command in commands]
        permissive = [p for p in relevant if p.permissive]
        has_restrictive_floor = any(not p.permissive for p in relevant)

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
            ast = _checked_ast(policy, mode)
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
            if verdict == "leak" and has_restrictive_floor:
                # A restrictive floor may block this row; v1 does not combine
                # floors, so neither verdict is sound → no claim.
                proofs.append(
                    PolicyProof(
                        policy.name,
                        "unverified",
                        None,
                        f"restrictive {floor_kind} floor not combined in v1",
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
            f"restrictive {floor_kind} floor present — not combined in v1"
            if has_restrictive_floor
            else None
        )
        tables.append(
            TableVerdict(table.qualified_name, _rollup(proofs), note, tuple(proofs))
        )
    return Verification(tuple(tables), mode)


def build_escalation(
    schema: Schema, *, auth_functions: set[str] | None = None
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
    tables.extend(_escalation_secdef_findings(schema, auth_functions))
    tables.sort(key=lambda t: t.qualified_name)
    return Verification(tuple(tables), "escalation")


def _sql_body_parses(secdef_fn: Any) -> bool:
    """Whether a SECDEF function body is a parseable SQL statement — the same
    analyzability gate VIEW004 uses, checked WITHOUT emitting its warnings (the
    body parser is only called below when this is True)."""
    if secdef_fn.language != "sql":
        return False
    import pglast  # noqa: PLC0415 — lazy; pglast is a heavy optional path

    try:
        pglast.parse_sql(secdef_fn.body)
    except pglast.parser.ParseError:
        return False
    return True


def _escalation_anon_rollup(
    reads: set[str], an_by_table: dict[str, TableVerdict]
) -> tuple[Verdict, dict[str, object] | None, str]:
    """Roll up the escalation verdict for a SECDEF body that reads `reads`
    (RLS-table qnames), from each read table's ``anon`` verdict. Same witness
    discrimination as the owner-bypass case: an anon-isolated table → leak (the
    function exposes rows anon couldn't read); a *total* anon leak (witness ``{}``)
    → the function exposes nothing new; a *partial* anon leak → leak; an
    unprovable predicate → unverified."""
    verdicts: list[Verdict] = []
    for tq in sorted(reads):
        tv = an_by_table.get(tq)
        if tv is None or tv.verdict == "isolated":
            verdicts.append("leak")
        elif tv.verdict == "leak":
            leak = next((p for p in tv.proofs if p.verdict == "leak"), None)
            verdicts.append("isolated" if leak and leak.witness == {} else "leak")
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


def _escalation_secdef_findings(
    schema: Schema, auth_functions: set[str] | None
) -> list[TableVerdict]:
    """SEC042 escalation: an anon / ``PUBLIC``-EXECUTE-able SECURITY DEFINER
    function owned by an RLS-exempt role (superuser / ``BYPASSRLS``) runs its
    body with the owner's RLS exemption, so an anonymous caller (``POST
    /rpc/fn``) reads whatever RLS tables the body touches — rows its own RLS
    would deny. We prove that against each read table's ``anon`` verdict.

    Reuses VIEW004's body parser to extract the RLS tables a SQL body reads; an
    opaque body (PL/pgSQL or dynamic SQL) is **unverified** (we can't see what it
    reads). Reads no RLS table → not a finding. The VIEW004 case (view-mediated)
    needs the view's grants to know whether it is anon-selectable, which the
    model does not capture, so it is out of this scope.
    """
    secdef_fns = schema.security_definer_functions
    rls_tables = {(t.schema, t.name) for t in schema.tables if t.rls_enabled}
    if not secdef_fns or not rls_tables:
        return []
    an = build_verification(schema, auth_functions=auth_functions, mode="anon")
    an_by_table = {t.qualified_name: t for t in an.tables}
    bare_to_qual: dict[str, list[tuple[str, str]]] = {}
    for s, n in sorted(rls_tables):
        bare_to_qual.setdefault(n, []).append((s, n))
    from pgrls.rules.view004 import _secdef_fn_leaks  # noqa: PLC0415 — body parser reuse

    anon_roles = {"anon", "PUBLIC"}  # mirror SEC042's default exposure set
    by_qname: dict[str, list[Any]] = {}
    for f in secdef_fns:
        by_qname.setdefault(f.qualified_name, []).append(f)

    findings: list[TableVerdict] = []
    for qname in sorted(by_qname):
        # Candidate iff some overload is owner-RLS-exempt AND anon-executable.
        candidate = [
            f
            for f in by_qname[qname]
            if f.owner_bypasses_rls and (set(f.execute_roles) & anon_roles)
        ]
        if not candidate:
            continue
        reads: set[str] = set()
        any_opaque = False
        for f in candidate:
            if _sql_body_parses(f):
                reads |= _secdef_fn_leaks(f, qname, rls_tables, bare_to_qual)
            else:
                any_opaque = True
        roles = ", ".join(
            sorted({r for f in candidate for r in (set(f.execute_roles) & anon_roles)})
        )
        head = (
            f"SECURITY DEFINER function EXECUTE-able by {roles}, owned by an "
            "RLS-exempt role"
        )
        if reads:
            verdict, witness, tail = _escalation_anon_rollup(reads, an_by_table)
            note = f"{head}, reads {', '.join(sorted(reads))}{tail}"
            reason = tail.strip(" —") if verdict == "unverified" else None
            proof = PolicyProof(sorted(reads)[0], verdict, witness, reason)
            findings.append(TableVerdict(qname, verdict, note, (proof,)))
        elif any_opaque:
            note = f"{head}, has an opaque body — cannot prove what it reads"
            proof = PolicyProof(
                qname, "unverified", None, "opaque SECURITY DEFINER body"
            )
            findings.append(TableVerdict(qname, "unverified", note, (proof,)))
        # else: analyzable body reading no RLS table → not a finding.
    return findings


def _witness_phrase(witness: dict[str, object] | None, mode: Mode = "anon") -> str:
    """Human phrase for a leak witness, per threat model.

    A characterizing row, the unconditional case (``{}`` — every row / a row of
    any other tenant), or a conditional leak no single row characterizes
    (``None``). The cross-tenant phrasing frames the row as another tenant's;
    the write phrasing frames it as a row stamped for another tenant.
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
            return "a row stamped for any other tenant can be written"
        pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
        return f"a row stamped for another tenant with {pairs} can be written"
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


def render_text(v: Verification) -> str:
    if not v.tables:
        if v.mode == "escalation":
            return "No reachable owner-bypass escalation paths to verify."
        return "No RLS-enabled tables to verify."
    headers = ("TABLE", "VERDICT", "DETAIL")
    rows = []
    for t in v.tables:
        if t.verdict == "leak":
            leak = next((p for p in t.proofs if p.verdict == "leak"), None)
            detail = _witness_phrase(leak.witness if leak else None, v.mode)
            if t.note:  # escalation carries the reach path here (else None)
                detail = f"{detail} — {t.note}"
        elif t.verdict == "unverified":
            reason = next(
                (p.reason for p in t.proofs if p.verdict == "unverified" and p.reason),
                t.note or "no claim",
            )
            detail = reason
        else:
            detail = t.note or _NO_READ_DETAIL[v.mode]
        rows.append((safe_location(t.qualified_name), _VERDICT_LABEL[t.verdict], detail))
    out = render_text_table(headers, rows)
    out.append("")
    out.append(_summary_line(v))
    return "\n".join(out)


def render_json(v: Verification) -> str:
    payload = {
        "mode": v.mode,
        "summary": v.summary,
        "tables": [
            {
                "table": t.qualified_name,
                "verdict": t.verdict,
                "note": t.note,
                "policies": [
                    {
                        "policy": p.policy,
                        "verdict": p.verdict,
                        "witness": p.witness,
                        "witness_scope": _witness_scope(p.verdict, p.witness, v.mode),
                        "reason": p.reason,
                    }
                    for p in t.proofs
                ],
            }
            for t in v.tables
        ],
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

    The prover is one rule per ``--mode`` (`pgrls-anon-isolation` /
    `pgrls-cross-tenant-isolation`); a strict UNVERIFIED note reuses the same
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
