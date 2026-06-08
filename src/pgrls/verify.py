"""Effective tenant-isolation proof for `pgrls verify`.

Where `pgrls lint` *flags* a suspicious policy (SEC004 / SEC038) and `pgrls
matrix` *summarizes* who-can-read-what, `pgrls verify` **proves** — with Z3 —
a concrete safety property and hands back a counterexample when it fails:

    For every RLS-protected table, can an *anonymous* session (every auth
    function — auth.uid()/role()/jwt(), current_setting(...) — returning NULL,
    the unauthenticated state) read any row?

The honest three-way verdict mirrors the project's "a verifier that degrades
to a linter" stance:

* ``isolated``   — **proven**: ``USING`` is UNSAT under an anonymous session,
  so no row is ever visible to an unauthenticated client.
* ``leak``       — **disproven**: a row *is* anonymously readable. The
  counterexample is a concrete characterizing row
  (``{"is_public": True}``) or "all rows" when the leak is unconditional
  (``USING (true)``, the ``auth.uid() IS NULL OR …`` inversion).
* ``unverified`` — no claim: Z3 is unavailable, the predicate is outside the
  decidable fragment, or the solver timed out. This is where the verifier
  *degrades to the linter* — run `pgrls lint` for the heuristic rules.

Scope (v1): the anonymous-read threat model — the dominant Supabase/PostgREST
RLS failure (the inverted `auth.uid() IS NULL OR …` policy that exposes every
row to unauthenticated clients). It reasons over each table's permissive
``SELECT`` / ``ALL`` policies. A *leaking* permissive policy on a table that
also carries a ``RESTRICTIVE`` read floor is reported ``unverified`` rather
than risk an unsound verdict — v1 does not combine restrictive floors into the
proof; an already-proven-``isolated`` permissive policy stays ``isolated``
(a restrictive floor only narrows access). Authenticated cross-tenant isolation
(tenant A reading tenant B) is the next increment. Tables with RLS disabled are
out of scope (that is SEC001's job, not an isolation proof).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from pgrls.diff._z3_compare import _DEFAULT_AUTH_FUNCTIONS, prove_anon_isolation
from pgrls.model import Schema
from pgrls._render_common import make_dispatcher, pluralize, render_text_table
from pgrls.formatters._common import safe_location

# The functions treated as NULL under an anonymous session (single source of
# truth — the SEC038 / 3VL encoder's default). `pgrls verify --auth-function`
# extends this set with a project's own auth helper.
DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset(_DEFAULT_AUTH_FUNCTIONS)

Verdict = Literal["isolated", "leak", "unverified"]

_READ_COMMANDS = ("ALL", "SELECT")

_VERDICT_LABEL = {"isolated": "PROVEN", "leak": "LEAK", "unverified": "UNVERIFIED"}


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
    schema: Schema, *, auth_functions: set[str] | None = None
) -> Verification:
    """Prove anonymous-read isolation for every RLS-enabled table in `schema`.

    `auth_functions`, when given, *replaces* the default anon-NULL function set
    (auth.uid/role/jwt, current_setting) — every name in it is treated as NULL
    under an anonymous session, and `None` uses the defaults. (The
    `pgrls verify --auth-function` CLI unions a project's helper with the
    defaults before calling this, which is why the *flag* extends rather than
    replaces.) Tables are sorted by qualified name for deterministic output.
    """
    tables: list[TableVerdict] = []
    for table in sorted(schema.tables, key=lambda t: t.qualified_name):
        if not table.rls_enabled:
            continue  # not an isolation claim — SEC001's domain, not verify's
        read_policies = [p for p in table.policies if p.command in _READ_COMMANDS]
        permissive = [p for p in read_policies if p.permissive]
        has_restrictive_floor = any(not p.permissive for p in read_policies)

        if not permissive:
            # RLS on with no permissive read policy → Postgres default-denies
            # every read → trivially isolated.
            tables.append(
                TableVerdict(
                    table.qualified_name,
                    "isolated",
                    "no permissive read policy — RLS default-denies",
                    (),
                )
            )
            continue

        proofs: list[PolicyProof] = []
        for policy in permissive:
            if policy.using_ast is None:
                proofs.append(
                    PolicyProof(policy.name, "unverified", None, "USING not available")
                )
                continue
            verdict, witness = prove_anon_isolation(policy.using_ast, auth_functions)
            if verdict == "leak" and has_restrictive_floor:
                # A restrictive read floor may block this row; v1 does not
                # combine floors, so neither verdict is sound → no claim.
                proofs.append(
                    PolicyProof(
                        policy.name,
                        "unverified",
                        None,
                        "restrictive read floor not combined in v1",
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
                        "USING predicate outside the decidable fragment",
                    )
                )
            else:
                proofs.append(PolicyProof(policy.name, "isolated", None, None))

        note = (
            "restrictive read floor present — not combined in v1"
            if has_restrictive_floor
            else None
        )
        tables.append(
            TableVerdict(table.qualified_name, _rollup(proofs), note, tuple(proofs))
        )
    return Verification(tuple(tables))


def _witness_phrase(witness: dict[str, object] | None) -> str:
    """Human phrase for a leak witness: a characterizing row, 'every row'
    (unconditional), or a conditional leak with no single characterizing row."""
    if witness is None:
        return "a conditional leak — no single row characterizes it"
    if not witness:
        return "every row is anonymously readable"
    pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
    return f"a row with {pairs} is anonymously readable"


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
            detail = _witness_phrase(leak.witness if leak else None)
        elif t.verdict == "unverified":
            reason = next(
                (p.reason for p in t.proofs if p.verdict == "unverified" and p.reason),
                t.note or "no claim",
            )
            detail = reason
        else:
            detail = t.note or "no anonymous read"
        rows.append((safe_location(t.qualified_name), _VERDICT_LABEL[t.verdict], detail))
    out = render_text_table(headers, rows)
    out.append("")
    out.append(_summary_line(v))
    return "\n".join(out)


def render_json(v: Verification) -> str:
    payload = {
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
                        "witness_scope": (
                            None
                            if p.verdict != "leak"
                            else "conditional"
                            if p.witness is None
                            else "all_rows"
                            if not p.witness
                            else "row"
                        ),
                        "reason": p.reason,
                    }
                    for p in t.proofs
                ],
            }
            for t in v.tables
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


render, VERIFY_FORMATS = make_dispatcher(
    {"text": render_text, "json": render_json}
)
