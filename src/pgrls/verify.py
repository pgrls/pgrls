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
Mode = Literal["anon", "cross-tenant", "write"]

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
}
_SARIF_RULE_TITLE: dict[Mode, str] = {
    "anon": "Anonymous read-isolation proof",
    "cross-tenant": "Cross-tenant read-isolation proof",
    "write": "Cross-tenant write-isolation proof",
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
    """
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


def _witness_phrase(witness: dict[str, object] | None, mode: Mode = "anon") -> str:
    """Human phrase for a leak witness, per threat model.

    A characterizing row, the unconditional case (``{}`` — every row / a row of
    any other tenant), or a conditional leak no single row characterizes
    (``None``). The cross-tenant phrasing frames the row as another tenant's;
    the write phrasing frames it as a row stamped for another tenant.
    """
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
        return "No RLS-enabled tables to verify."
    headers = ("TABLE", "VERDICT", "DETAIL")
    rows = []
    for t in v.tables:
        if t.verdict == "leak":
            leak = next((p for p in t.proofs if p.verdict == "leak"), None)
            detail = _witness_phrase(leak.witness if leak else None, v.mode)
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
