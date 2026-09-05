"""Live runtime probe for `pgrls verify --probe`.

`pgrls verify` *proves* a tenant-isolation property with Z3 — a static
verdict over the introspected policy AST. `--probe` keeps that static proof
honest by running it against the live database: it connects as the threat-model
session (anonymous, or authenticated as one tenant), seeds a throwaway row, runs
the real query the proof reasons about, and diffs the *observed* behavior
against the Z3 verdict. The whole dance happens inside a transaction that is
**always rolled back** — no committed row is added, changed, or removed, and the
probe role it creates does not survive the rollback.

Three things can come out of the comparison (per table × `--mode`):

* **agree** — static and live concur (PROVEN ⇒ no rows / write rejected; LEAK ⇒
  rows visible / write admitted). The proof is backed by reality.
* **mismatch** — static and live *disagree*. Either the proof says isolated but
  the live policy leaks (a soundness break, or — more often — schema drift since
  the proof was computed), or the proof says leak but the synthesized row did not
  reproduce it (a conditional witness, or the policy changed). Either way the
  static report can no longer be trusted on its own.
* **leak_confirmed** — the money case. A LEAK reproduced live, *or* an
  UNVERIFIED policy (the verifier made no claim) turned out to leak when probed —
  upgrading an honest "no claim" into a reproduced, exit-non-zero leak.

The probe is deliberately conservative: anything it cannot model live it
**abstains** on (per table, with a one-line reason — never a crash). It cannot
create its probe role (no CREATEROLE / not superuser), cannot seed (no INSERT),
finds no scoping axis to pivot a cross-tenant probe on, the leak witness is
conditional (no single characterizing row), the policy references other tables,
or a column has an exotic type the placeholder synthesis can't fill — all of
these yield a clean `abstained` / `skipped`, not a false signal.

It reuses `pgrls.repro`'s GUC / identity / tenant-value synthesis verbatim (the
same machinery `--emit-repro` uses to build a runnable reproduction), so the
session the probe establishes is byte-identical to the one the emitted `.sql`
would — there is one definition of "become tenant A" / "stamp a row for tenant
B" across both surfaces.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Literal

import psycopg

from pgrls.diff._z3_compare import (
    _unwrap_scalar_sublink,
    cross_tenant_session_identity,
)
from pgrls.fixers._idents import quote_ident
from pgrls.model import MAYBE_SET, Column, Policy, Schema, Table
from pgrls.repro import (
    _AUTH_IDENTITY_GUC,
    _current_setting_guc,
    _funccall_qualified,
    _identity_value_type,
    _row_columns,
    _session_a_value,
    _session_identity_setup,
    _sql_str,
    _tenant_b_value,
)
from pgrls.testing.assertions import _row_count
from pgrls.verify import (
    Mode,
    PolicyProof,
    TableVerdict,
    Verdict,
    Verification,
    build_verification,
    checked_ast,
    _anon_set_gucs,
)
from pgrls._render_common import pluralize, render_text_table
from pgrls.formatters._common import safe_location

# The observable outcome of the live probe for one (table, policy, mode).
Observed = Literal[
    "no_rows",
    "rows_visible",
    "write_rejected",
    "write_admitted",
    "skipped",
    "abstained",
]
# How the observed outcome relates to the static Z3 verdict.
Agreement = Literal["agree", "mismatch", "leak_confirmed", "skipped", "abstained"]

# JWT-claim GUCs the auth.* stubs read (see repro._AUTH_STUB). Clearing them
# (set to '') makes auth.uid()/role()/jwt() return NULL — the anonymous state
# the `anon` threat model probes under. A policy reading a different GUC via a
# direct current_setting(...) adds its own GUC to this set per table.
_ANON_BASELINE_GUCS = (
    "request.jwt.claim.sub",
    "request.jwt.claim.role",
    "request.jwt.claims",
)

# The anon-KEY session (see `_z3_compare._Context.anon_jwt`): what PostgREST
# sets for a caller presenting the public anon key — a role claim of 'anon'
# and a claims blob carrying it, but no subject. Applied as a second attempt
# after the JWT-less baseline reads nothing.
_ANON_KEY_SESSION_GUCS = (
    ("request.jwt.claim.role", "anon"),
    ("request.jwt.claims", '{"role":"anon"}'),
)


@dataclass(frozen=True)
class ProbeResult:
    """The live-vs-static result for one table under one threat model.

    `policy` is the leaking / scoping policy the probe pivoted on (None when the
    table has no permissive policy for the mode and is trivially isolated, or
    when the probe abstained before selecting one). `seeded` is the witness /
    discriminator row the probe inserted (None when nothing was seeded — an
    abstain, or a bare write-mode insert attempt)."""

    qualified_name: str
    policy: str | None
    mode: Mode
    static_verdict: Verdict
    observed: Observed
    agreement: Agreement
    detail: str
    seeded: dict[str, object] | None


@dataclass(frozen=True)
class Probe:
    results: tuple[ProbeResult, ...]
    mode: Mode

    @property
    def has_mismatch(self) -> bool:
        return any(r.agreement == "mismatch" for r in self.results)

    @property
    def has_confirmed_leak(self) -> bool:
        return any(r.agreement == "leak_confirmed" for r in self.results)

    @property
    def summary(self) -> dict[str, int]:
        counts = {
            "agree": 0,
            "mismatch": 0,
            "leak_confirmed": 0,
            "skipped": 0,
            "abstained": 0,
        }
        for r in self.results:
            counts[r.agreement] += 1
        return {"tables": len(self.results), **counts}


# --- helpers ---------------------------------------------------------------


class _ProbeAbstain(Exception):
    """Raised inside a per-table probe to bail out with a clean reason.

    The caller turns it into a `ProbeResult` with ``observed`` /
    ``agreement`` of ``abstained`` (or ``skipped`` for a "nothing to prove"
    boundary) — never a traceback. The whole point of the probe is that it
    degrades gracefully, exactly like the verifier degrades to the linter."""

    def __init__(self, reason: str, *, skipped: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.skipped = skipped


def _short(exc: Exception) -> str:
    """A one-line rendering of a Postgres error for an abstain detail (the
    first line of the message, whitespace-collapsed)."""
    msg = str(exc).strip().splitlines()
    return msg[0].strip() if msg else exc.__class__.__name__


def _column_map(table: Table) -> dict[str, Column]:
    return {c.name: c for c in table.column_details}


def _anon_gucs(policy_ast: Any) -> list[str]:
    """The GUCs to clear so every auth value in `policy_ast` reads NULL.

    The baseline Supabase JWT-claim GUCs, plus any GUC a direct
    ``current_setting('<guc>')`` in the predicate reads (so a non-Supabase
    policy scoping on ``current_setting('app.tenant_id')`` is anonymized too).
    Reuses repro's `_current_setting_guc` / `_AUTH_IDENTITY_GUC` so the GUC
    mapping is the single source of truth shared with the emitted repro."""
    from pglast.ast import FuncCall, Node

    gucs = set(_ANON_BASELINE_GUCS)

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, FuncCall):
            guc = _current_setting_guc(n)
            if guc is not None:
                gucs.add(guc)
            qualified = _funccall_qualified(n)
            if qualified in _AUTH_IDENTITY_GUC:
                gucs.add(_AUTH_IDENTITY_GUC[qualified])
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(policy_ast)
    return sorted(gucs)


def _references_other_tables(policy_ast: Any) -> bool:
    """True if the predicate references another table / subquery, so a single
    synthesized row in the probed table cannot characterize its behavior (the
    same boundary repro flags as "needs a hand-edit").

    A bare scalar ``(SELECT <expr>)`` — the dominant Supabase / PERF001 idiom,
    e.g. ``(SELECT auth.uid())`` — references NO table, so it is unwrapped and
    its projection walked instead of treated as a foreign reference (mirrors the
    Z3 encoder's `_unwrap_scalar_sublink`). Only a real sub-select (``EXISTS``,
    an ``IN``-subquery, a multi-target / FROM-bearing select), a
    ``RangeSubselect``, or a ``SelectStmt`` counts as referencing another
    table."""
    from pglast.ast import Node, RangeSubselect, SelectStmt, SubLink

    found = False

    def walk(n: Any) -> None:
        nonlocal found
        if found or n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, SubLink):
            unwrapped = _unwrap_scalar_sublink(n)
            if unwrapped is n:
                # A genuine subquery (EXISTS / IN / FROM-bearing) → references
                # another table; cannot characterize with one synthesized row.
                found = True
                return
            # A bare scalar `(SELECT <expr>)` references no table — descend into
            # the projected expression, skipping the SELECT wrapper.
            walk(unwrapped)
            return
        if isinstance(n, (RangeSubselect, SelectStmt)):
            found = True
            return
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(policy_ast)
    return found


def _write_axis(
    table: Table, auth_functions: set[str] | None
) -> tuple[str, str] | None:
    """The ``(discriminator column, session-auth SQL)`` for a WRITE probe,
    derived from the table's READ scoping.

    A write-check is often unscoped (`WITH CHECK (true)` — the headline footgun
    verify reports UNVERIFIED), so it carries no tenant axis of its own. But the
    table's permissive SELECT/ALL policy USING usually does declare one
    (`tenant_id = auth.uid()`), and that is the column that stamps the tenant
    and the identity to authenticate as. Returns the first such axis, or None
    when no read policy declares a single scoping equality."""
    for policy in table.policies:
        if not policy.permissive or policy.command not in ("SELECT", "ALL"):
            continue
        if policy.using_ast is None:
            continue
        axis = cross_tenant_session_identity(policy.using_ast, auth_functions)
        if axis is not None:
            return axis
    return None


def _seed_row(
    table: Table,
    policy: Policy,
    proof: PolicyProof,
    mode: Mode,
    *,
    disc_col: str | None,
    auth_sql: str | None,
) -> tuple[list[tuple[str, str]], dict[str, object], str | None]:
    """Build the (column, literal) pairs for the row the probe inserts, the
    machine-readable ``seeded`` dict, and the session-A value to authenticate
    as (cross-tenant / write only; None for anon).

    Reuses repro's row / tenant-value synthesis verbatim: a cross-tenant probe
    stamps the discriminator for tenant B (≠ the session's tenant A) plus the
    leak witness's other columns; an anon probe inserts the witness row (or a
    placeholder row for an isolated / unverified table). Raises `_ProbeAbstain`
    when an exotic column type forces a NULL into a NOT NULL column (the INSERT
    would fail) — better to abstain than crash mid-transaction.
    """
    witness = proof.witness or {}
    if mode in ("cross-tenant", "write"):
        assert disc_col is not None and auth_sql is not None
        disc = _column_map(table).get(disc_col)
        disc_type = disc.data_type if disc is not None else "text"
        b_val = _tenant_b_value(disc_type, witness.get(disc_col))
        a_val = _session_a_value(_identity_value_type(auth_sql) or disc_type, b_val)
        row_witness: dict[str, object] = {
            k: v for k, v in witness.items() if k != disc_col
        }
        if disc is not None:
            row_witness[disc_col] = b_val
        row, _unpinned, null_fallback = _row_columns(table, row_witness)
        if null_fallback:
            raise _ProbeAbstain(
                f"NOT NULL column(s) {', '.join(null_fallback)} have a type the "
                "probe cannot synthesize a value for"
            )
        return row, row_witness, str(a_val)
    # anon: seed the witness row (a leak's characterizing row, or {} → a bare
    # placeholder row for an isolated/unverified table we expect anon NOT to see)
    row, _unpinned, null_fallback = _row_columns(table, witness)
    if null_fallback:
        raise _ProbeAbstain(
            f"NOT NULL column(s) {', '.join(null_fallback)} have a type the "
            "probe cannot synthesize a value for"
        )
    return row, dict(witness), None


def _insert_sql(table: Table, row: list[tuple[str, str]]) -> str:
    qtbl = f"{quote_ident(table.schema)}.{quote_ident(table.name)}"
    if not row:
        return f"INSERT INTO {qtbl} DEFAULT VALUES"
    cols = ", ".join(quote_ident(n) for n, _ in row)
    vals = ", ".join(v for _, v in row)
    return f"INSERT INTO {qtbl} ({cols}) VALUES ({vals})"


def _classify(
    static: Verdict, observed: Observed, mode: Mode
) -> tuple[Agreement, str]:
    """The AGREE / MISMATCH / LEAK_CONFIRMED contract (per the spec table).

    Reads (anon / cross-tenant): no_rows / rows_visible. Writes: write_rejected
    / write_admitted. The two columns are symmetric (a "negative" observation =
    no_rows or write_rejected; a "positive" one = rows_visible or
    write_admitted), so they collapse to one truth value here.
    """
    positive = observed in ("rows_visible", "write_admitted")
    if static == "isolated":
        if positive:
            return (
                "mismatch",
                "static PROVEN but the live policy exposed the row — "
                "proof contradicts reality (or the schema drifted)",
            )
        return ("agree", "PROVEN and the live policy hid the row")
    if static == "leak":
        if positive:
            return ("leak_confirmed", "static LEAK reproduced live")
        return (
            "mismatch",
            "static LEAK but the probe row was not exposed — the leak is "
            "conditional (see --emit-repro) or the policy changed",
        )
    # unverified — the verifier made no claim
    if positive:
        return (
            "leak_confirmed",
            "static UNVERIFIED but the live policy exposed the row — "
            "a reproduced leak the static proof could not claim",
        )
    return (
        "skipped",
        "static UNVERIFIED; the probe saw no leak — not a proof, run "
        "`pgrls lint` for the heuristic rules",
    )


def _probe_one(
    conn: psycopg.Connection[Any],
    table: Table,
    tv: TableVerdict,
    mode: Mode,
    auth_functions: set[str] | None,
    probe_role: str,
    n: int,
    guc_states: tuple[dict[str, str | None], ...] = ({},),
) -> ProbeResult:
    """Probe one table, inside its own savepoint (rolled back by the caller).

    Selects the representative permissive policy proof, synthesizes the threat
    session + seed row (reusing repro's helpers), runs the live query, and
    classifies the result against the static verdict. Any `_ProbeAbstain`
    becomes a clean abstained/skipped result; the savepoint guarantees the seed
    + session changes never escape this call."""
    # A table with no permissive policy for the mode (RLS default-deny) is
    # trivially isolated and carries no proof — nothing live to pivot on.
    if not tv.proofs:
        return ProbeResult(
            tv.qualified_name, None, mode, tv.verdict, "skipped", "skipped",
            "no permissive policy for this mode — RLS default-denies", None,
        )

    # The representative proof: a leak proof if the table leaks (it pins the
    # witness), else the first proof (isolated/unverified all share the verdict).
    proof = next(
        (p for p in tv.proofs if p.verdict == "leak"),
        tv.proofs[0],
    )
    policy = next((p for p in table.policies if p.name == proof.policy), None)
    if policy is None:
        # `anon` mode emits a `role:<name>` proof when the anonymous session is
        # exempt from the table's RLS outright — there is no policy to pivot
        # on, because the policies are never consulted.
        reason = (
            "the anonymous session is exempt from this table's RLS — no policy "
            "to probe; see verify --mode escalation"
            if proof.policy.startswith("role:")
            else "internal: proof references an unknown policy"
        )
        return ProbeResult(
            tv.qualified_name, proof.policy, mode, tv.verdict, "abstained",
            "abstained", reason, None,
        )

    policy_ast = checked_ast(policy, mode)
    sp = f"probe_{n}"
    with conn.cursor() as cur:
        cur.execute(f"SAVEPOINT {sp}")
        try:
            if policy_ast is None:
                raise _ProbeAbstain(
                    "no checkable predicate for this policy under this mode"
                )
            if proof.verdict == "leak" and proof.witness is None:
                raise _ProbeAbstain(
                    "leak is conditional — no single row characterizes it; "
                    "see --emit-repro"
                )
            if _references_other_tables(policy_ast):
                raise _ProbeAbstain(
                    "policy references other tables/subqueries; cannot "
                    "synthesize a probe row",
                    skipped=True,
                )

            disc_col: str | None = None
            auth_sql: str | None = None
            if mode == "cross-tenant":
                session = cross_tenant_session_identity(policy_ast, auth_functions)
                if session is None:
                    raise _ProbeAbstain(
                        "no single tenant-scoping axis to pivot a "
                        "cross-tenant probe on",
                        skipped=True,
                    )
                disc_col, auth_sql = session
            elif mode == "write":
                # The write-check itself may be unscoped (`WITH CHECK (true)` is
                # the headline footgun → UNVERIFIED), so the tenant axis comes
                # from the table's READ scoping (a permissive SELECT/ALL USING
                # that declares `<column> = <session identity>`). That tells us
                # which column stamps the tenant and how to authenticate as one,
                # so we can attempt a cross-tenant write.
                axis = _write_axis(table, auth_functions)
                if axis is None:
                    raise _ProbeAbstain(
                        "no read-scoping axis to pivot a write probe on "
                        "(no permissive SELECT/ALL policy declares a single "
                        "tenant column)",
                        skipped=True,
                    )
                disc_col, auth_sql = axis

            row, seeded, a_val = _seed_row(
                table, policy, proof, mode,
                disc_col=disc_col, auth_sql=auth_sql,
            )
            observed = _run_probe_steps(
                cur, table, policy_ast, mode, row,
                disc_col=disc_col, auth_sql=auth_sql, a_val=a_val,
                probe_role=probe_role, guc_states=guc_states,
            )
            agreement, detail = _classify(tv.verdict, observed, mode)
            return ProbeResult(
                tv.qualified_name, policy.name, mode, tv.verdict,
                observed, agreement, detail, seeded,
            )
        except _ProbeAbstain as exc:
            kind: Observed = "skipped" if exc.skipped else "abstained"
            agree: Agreement = "skipped" if exc.skipped else "abstained"
            return ProbeResult(
                tv.qualified_name, policy.name, mode, tv.verdict,
                kind, agree, exc.reason, None,
            )
        finally:
            cur.execute(f"ROLLBACK TO SAVEPOINT {sp}")


def _rls_active_for_probe_role(cur: psycopg.Cursor[Any], table: Table) -> bool:
    """Whether RLS is actually enforced for the *current* (probe) role on this
    table. ``row_security_active(regclass)`` returns False when the role bypasses
    RLS — e.g. an owner-equivalent role (a member of the table's owner) on a
    table without ``FORCE ROW LEVEL SECURITY`` — in which case any row/write it
    observes is permitted for a non-policy reason and must not be read as a leak.
    On an unexpected error we fail *closed* (return False → abstain): this gate
    exists to withhold judgment when we cannot tell a policy leak from an owner
    bypass, so uncertainty must resolve to abstain, never to a possible false
    MISMATCH. (A statically proven leak is failed regardless, by the gate in the
    CLI — abstaining here cannot mask one.) The builtin does not error for a
    valid granted regclass, so this branch is defensive."""
    qtbl = f"{quote_ident(table.schema)}.{quote_ident(table.name)}"
    try:
        cur.execute("SELECT row_security_active(%s::regclass)", (qtbl,))
        row = cur.fetchone()
    except psycopg.Error:
        return False
    return bool(row and row[0])


def _run_probe_steps(
    cur: psycopg.Cursor[Any],
    table: Table,
    policy_ast: Any,
    mode: Mode,
    row: list[tuple[str, str]],
    *,
    disc_col: str | None,
    auth_sql: str | None,
    a_val: str | None,
    probe_role: str,
    guc_states: tuple[dict[str, str | None], ...] = ({},),
) -> Observed:
    """Seed → become the threat session → observe. Returns the live outcome.

    SEED runs as the privileged connection role (the only non-superuser-safe
    seed under FORCE RLS: stamp the identity GUC so the SELECT-applicable check
    on the NEW row passes); then we drop the identity to the threat session and
    SET LOCAL ROLE into the unprivileged probe role so RLS + the policy — not a
    privileged connection — decide visibility. RESET ROLE at the end so the
    outer rollback runs as the connection role."""
    qtbl = f"{quote_ident(table.schema)}.{quote_ident(table.name)}"

    try:
        if mode in ("cross-tenant", "write"):
            assert auth_sql is not None
            if mode == "cross-tenant":
                # Seed a tenant-B row: set the session identity to B (so the
                # SELECT-applicable USING admits the INSERT under FORCE RLS),
                # insert as the privileged role, then leave. B's identity value
                # is recovered from the seeded row's discriminator literal so it
                # matches the row.
                b_id_stmts, _caveat = _session_identity_setup(
                    auth_sql, _row_disc_text(row, disc_col)
                )
                for s in b_id_stmts:
                    cur.execute(s)
                cur.execute(_insert_sql(table, row))
            # Become tenant A and drop into the unprivileged probe role.
            a_id_stmts, _ = _session_identity_setup(auth_sql, a_val or "")
            for s in a_id_stmts:
                cur.execute(s)
            cur.execute(f"SET LOCAL ROLE {quote_ident(probe_role)}")
        else:  # anon
            cur.execute(_insert_sql(table, row))  # seed as the privileged role
            for guc in _anon_gucs(policy_ast):
                cur.execute(f"SELECT set_config({_sql_str(guc)}, '', true)")
            cur.execute(f"SET LOCAL ROLE {quote_ident(probe_role)}")
    except psycopg.Error as exc:
        # A seed INSERT denied (e.g. no permissive write path under FORCE RLS for
        # a non-superuser owner), or the GUC/SET ROLE failed. Abstain cleanly —
        # the outer savepoint rollback recovers the aborted transaction.
        raise _ProbeAbstain(
            f"cannot seed/become the threat session: {_short(exc)}"
        ) from exc

    try:
        # The probe measures a *policy* leak only if RLS is actually enforced for
        # the probe role. If that role is owner-equivalent (a member of the
        # table's owner) and the table is not FORCE'd, Postgres exempts it from
        # RLS entirely — every row/write it then sees is permitted for a
        # non-policy reason. Abstain rather than credit that as a leak. (The
        # membership can be one the probe itself granted to reach a policy's
        # `TO <role>`, so this guard is essential, not hypothetical.)
        if not _rls_active_for_probe_role(cur, table):
            raise _ProbeAbstain(
                "RLS is not enforced for the probe session (an owner-equivalent "
                "role on a table without FORCE ROW LEVEL SECURITY) — the probe "
                "cannot measure a policy leak here"
            )
        if mode == "write":
            return _observe_write(cur, table, row)
        # Observe ONLY the row the probe planted, never the whole table. A
        # cross-tenant probe counts rows stamped for tenant B (the seeded
        # discriminator value) so a correctly-scoped table that merely holds a
        # real row for the synthetic *session* tenant A — e.g. an integer key
        # where tenant `1` exists — is not miscounted as a leak. Anon counts any
        # visible row: under an isolated anon verdict the session must see
        # nothing, so any row at all (planted or real) is the leak.
        if mode == "cross-tenant" and disc_col is not None:
            disc_lit = next((v for n, v in row if n == disc_col), None)
            if disc_lit is None:  # no stamped discriminator → can't scope safely
                raise _ProbeAbstain(
                    "could not stamp the probe row's tenant discriminator"
                )
            query = (
                f"SELECT 1 FROM {qtbl} "
                f"WHERE {quote_ident(disc_col)} = {disc_lit}"
            )
        else:
            query = f"SELECT * FROM {qtbl}"
        try:
            if mode == "anon":
                seen = _observe_anon_sessions(cur, query, guc_states)
            else:
                seen = _row_count(cur.connection, query)
        except psycopg.Error as exc:
            raise _ProbeAbstain(f"probe query failed: {_short(exc)}") from exc
        return "rows_visible" if seen > 0 else "no_rows"
    finally:
        # The observe may have aborted the transaction (an abstain on a failed
        # query); the caller's ROLLBACK TO SAVEPOINT — taken before the SET ROLE
        # — resets the role regardless, so don't let a failed RESET ROLE mask the
        # original outcome.
        try:
            cur.execute("RESET ROLE")
        except psycopg.Error:
            pass


def _observe_anon_sessions(
    cur: psycopg.Cursor[Any],
    query: str,
    guc_states: tuple[dict[str, str | None], ...],
) -> int:
    """Rows visible under ANY anonymous session — the static prover's
    question, so a correct LEAK is not met with a MISMATCH.

    Anonymous sessions differ two ways and every combination is tried: the
    login path (each `guc_states` entry — the GUCs a real anonymous session
    inherits from ``ALTER ROLE`` / ``ALTER DATABASE … SET`` or the server
    configuration, replayed here because the probe cannot log in as
    ``authenticator``; a custom GUC is settable by any role), and the caller
    — JWT-less, then the Supabase ANON-KEY caller: PostgREST sets the role
    claim to 'anon', so ``USING (auth.role() = 'anon')`` reads rows for it
    and nothing for a JWT-less one.
    """
    names = sorted({n for st in guc_states for n in st})
    # What this session inherits, captured BEFORE any state is applied: a GUC
    # whose value introspection could not capture is replayed from here, so a
    # later state cannot leave the previous state's value standing.
    inherited: dict[str, str] = {}
    for n in names:
        cur.execute(f"SELECT current_setting({_sql_str(n)}, true) AS v")
        got = cur.fetchone()
        inherited[n] = (got[0] if got and got[0] is not None else "")
    for state in guc_states or ({},):
        for n in names:
            if n in state and state[n] in (None, MAYBE_SET):
                # Set at server level with a value introspection could not
                # capture: restore what this session actually inherits.
                value = inherited[n]
            else:
                value = state.get(n) or ""
            cur.execute(f"SELECT set_config({_sql_str(n)}, {_sql_str(value)}, true)")
        for guc, _val in _ANON_KEY_SESSION_GUCS:
            cur.execute(f"SELECT set_config({_sql_str(guc)}, '', true)")
        seen = _row_count(cur.connection, query)
        if seen == 0:
            for guc, val in _ANON_KEY_SESSION_GUCS:
                cur.execute(
                    f"SELECT set_config({_sql_str(guc)}, {_sql_str(val)}, true)"
                )
            seen = _row_count(cur.connection, query)
        if seen > 0:
            return seen
    return 0


def _row_disc_text(row: list[tuple[str, str]], disc_col: str | None) -> str:
    """The session-identity text for tenant B, recovered from the seeded row's
    discriminator literal so the seed INSERT is admitted under FORCE RLS.

    The row literal is rendered for the COLUMN type (e.g. ``'…'::uuid``); strip
    a trailing ``::type`` cast and the surrounding quotes so it can be re-set as
    the GUC string the auth stub re-casts."""
    if disc_col is None:  # pragma: no cover - cross-tenant always has a disc
        return ""
    lit = next((v for n, v in row if n == disc_col), "")
    if "::" in lit:
        lit = lit.rsplit("::", 1)[0]
    if len(lit) >= 2 and lit[0] == "'" and lit[-1] == "'":
        lit = lit[1:-1].replace("''", "'")
    return lit


def _observe_write(
    cur: psycopg.Cursor[Any], table: Table, row: list[tuple[str, str]]
) -> Observed:
    """Try the cross-tenant INSERT as the threat session, savepoint-guarded.

    ``write_rejected`` only on ``InsufficientPrivilege`` (SQLSTATE 42501, "new
    row violates row-level security policy" — the RLS ``WITH CHECK`` denial we
    are probing for); ``write_admitted`` if it succeeds. Any *other* error (a
    FK / UNIQUE / NOT NULL / table ``CHECK`` the synthesized row happens to
    trip) tells us nothing about the RLS outcome — RLS may even have admitted
    the row before the constraint fired — so we ABSTAIN rather than miscredit it
    as a rejection (which would mask a real write-leak) or let the aborted
    transaction cascade into a crash. The savepoint rollback recovers the
    transaction on every path."""
    w = f"w_{secrets.token_hex(4)}"
    cur.execute(f"SAVEPOINT {w}")
    try:
        cur.execute(_insert_sql(table, row))
    except psycopg.errors.InsufficientPrivilege:
        cur.execute(f"ROLLBACK TO SAVEPOINT {w}")
        return "write_rejected"
    except psycopg.Error as exc:
        cur.execute(f"ROLLBACK TO SAVEPOINT {w}")
        raise _ProbeAbstain(
            "cross-tenant write hit a non-RLS constraint, so the RLS outcome "
            f"is inconclusive: {_short(exc)}"
        ) from exc
    cur.execute(f"ROLLBACK TO SAVEPOINT {w}")
    return "write_admitted"


def _abstain_all(
    verification: Verification, mode: Mode, reason: str
) -> Probe:
    """Every probed table → abstained, with `reason` (the one-time gate failed —
    e.g. the connection cannot create the probe role)."""
    results = tuple(
        ProbeResult(
            tv.qualified_name, None, mode, tv.verdict,
            "abstained", "abstained", reason, None,
        )
        for tv in verification.tables
    )
    return Probe(results, mode)


# --- public API ------------------------------------------------------------


def _scoping_policy_and_axis(
    table: Table, auth_functions: set[str] | None
) -> tuple[Policy, str, str] | None:
    """The first permissive SELECT/ALL policy that declares a single tenant
    scoping equality, plus its ``(discriminator column, session-auth SQL)``.
    Like `_write_axis` but also returns the policy (needed to seed the row)."""
    for policy in table.policies:
        if not policy.permissive or policy.command not in ("SELECT", "ALL"):
            continue
        if policy.using_ast is None:
            continue
        axis = cross_tenant_session_identity(policy.using_ast, auth_functions)
        if axis is not None:
            return policy, axis[0], axis[1]
    return None


def _run_escalation_steps(
    cur: psycopg.Cursor[Any],
    table: Table,
    row: list[tuple[str, str]],
    *,
    disc_col: str,
    auth_sql: str,
    a_val: str | None,
    member: str,
    owner: str,
) -> Observed:
    """Seed a tenant-B row, authenticate the session as a *different* tenant A,
    then ``SET ROLE`` to the reaching member and ``SET ROLE`` from there to the
    owner. A correctly-scoped tenant-A session is denied tenant B's row, so
    *either* role seeing it confirms the owner bypass:

    * an **INHERIT** member already carries the owner's RLS exemption (Postgres
      bypasses RLS for any role that ``has_privs_of_role`` the owner), so it sees
      tenant B's row directly — no ``SET ROLE`` needed;
    * a **NOINHERIT** member is scoped until it ``SET ROLE``s to the owner, which
      then bypasses RLS on the not-FORCE'd table.

    The member→owner ``SET ROLE`` chain also confirms the static reachability: if
    the member cannot reach the owner the chain raises and the probe abstains.
    ``RESET ROLE`` in a finally; the caller's savepoint rollback resets the role
    and reverts the seed regardless."""
    qtbl = f"{quote_ident(table.schema)}.{quote_ident(table.name)}"
    try:
        # Seed a tenant-B row: set the session identity to B (so a FORCE-RLS
        # write check, if any, admits it), insert as the privileged connection.
        b_stmts, _ = _session_identity_setup(auth_sql, _row_disc_text(row, disc_col))
        for s in b_stmts:
            cur.execute(s)
        cur.execute(_insert_sql(table, row))
        # Authenticate as tenant A — a correctly-scoped A session is denied B's
        # row, so any role that still reads it is bypassing RLS.
        a_stmts, _ = _session_identity_setup(auth_sql, a_val or "")
        for s in a_stmts:
            cur.execute(s)
    except psycopg.Error as exc:
        raise _ProbeAbstain(
            f"cannot seed/become the threat session: {_short(exc)}"
        ) from exc

    disc_lit = next((v for n, v in row if n == disc_col), None)
    if disc_lit is None:
        raise _ProbeAbstain("could not stamp the probe row's tenant discriminator")
    query = f"SELECT 1 FROM {qtbl} WHERE {quote_ident(disc_col)} = {disc_lit}"
    try:
        try:
            cur.execute(f"SET ROLE {quote_ident(member)}")
            member_seen = _row_count(cur.connection, query)
            # The heart of the escalation: the member reaches the owner.
            cur.execute(f"SET ROLE {quote_ident(owner)}")
            owner_seen = _row_count(cur.connection, query)
        except psycopg.Error as exc:
            raise _ProbeAbstain(
                f"SET ROLE chain (member {member} → owner {owner}) or probe "
                f"query failed: {_short(exc)}"
            ) from exc
    finally:
        try:
            cur.execute("RESET ROLE")
        except psycopg.Error:  # pragma: no cover - savepoint rollback also resets
            pass

    # Tenant B's row is denied to a scoped tenant-A session, so the member
    # (directly, if it inherits the owner) OR the owner (via SET ROLE) reading
    # it is the bypass.
    return "rows_visible" if (member_seen > 0 or owner_seen > 0) else "no_rows"


def _escalation_probe_one(
    conn: psycopg.Connection[Any],
    tables: dict[str, Table],
    reachers: dict[str, list[str]],
    xt_verdicts: dict[str, Verdict],
    tv: TableVerdict,
    auth_functions: set[str] | None,
    n: int,
) -> ProbeResult:
    """Live-confirm one escalation finding. Only the SEC048 owner-reachability
    LEAKs are probed; a SEC042 SECDEF-body finding (a function qname, absent
    from `tables`) is skipped (its live confirmation is a follow-on)."""
    qn = tv.qualified_name
    table = tables.get(qn)
    if table is None:
        return ProbeResult(
            qn, None, "escalation", tv.verdict, "skipped", "skipped",
            "SECDEF-body escalation (SEC042) live confirmation is a follow-on",
            None,
        )
    if tv.verdict != "leak":
        return ProbeResult(
            qn, None, "escalation", tv.verdict, "skipped", "skipped",
            "no proven owner-bypass leak to confirm", None,
        )
    owner = table.owner
    members = reachers.get(owner or "", [])
    proof = next((p for p in tv.proofs if p.verdict == "leak"), None)
    sp = f"esc_probe_{n}"
    with conn.cursor() as cur:
        cur.execute(f"SAVEPOINT {sp}")
        try:
            if not owner or not members:
                raise _ProbeAbstain(
                    "no reachable low-trust member for the table owner"
                )
            if proof is None:  # pragma: no cover - a leak verdict has a leak proof
                raise _ProbeAbstain("no leak proof to pivot on")
            # Sound-witness gate: confirm a seeded tenant-B row is hidden from a
            # correctly-scoped tenant-A session, which holds only when the table
            # provably *isolates* tenants. When the table itself partially leaks
            # cross-tenant, a single seeded row may be visible to a scoped
            # session too (e.g. an unstamped nullable column the policy admits as
            # NULL), so the owner bypass cannot be cleanly isolated — abstain and
            # defer to `--mode cross-tenant`. (The static SEC048 LEAK stands.)
            if xt_verdicts.get(qn) != "isolated":
                raise _ProbeAbstain(
                    "table also leaks cross-tenant, so a seeded row is not a "
                    "clean owner-bypass witness — see `verify --mode cross-tenant`",
                    skipped=True,
                )
            # Need a tenant-scoping SELECT/ALL policy: it gives the column to
            # stamp tenant B and the identity to authenticate as tenant A, so a
            # correctly-scoped session is provably denied B's row.
            picked = _scoping_policy_and_axis(table, auth_functions)
            if picked is None:
                raise _ProbeAbstain(
                    "no permissive SELECT/ALL policy declares a single tenant "
                    "axis to pivot the bypass on",
                    skipped=True,
                )
            policy, disc_col, auth_sql = picked
            if _references_other_tables(policy.using_ast):
                raise _ProbeAbstain(
                    "scoping policy references other tables/subqueries; cannot "
                    "synthesize a probe row",
                    skipped=True,
                )
            member = sorted(members)[0]
            row, seeded, a_val = _seed_row(
                table, policy, proof, "cross-tenant",
                disc_col=disc_col, auth_sql=auth_sql,
            )
            observed = _run_escalation_steps(
                cur, table, row,
                disc_col=disc_col, auth_sql=auth_sql, a_val=a_val,
                member=member, owner=owner,
            )
            agreement, detail = _classify(tv.verdict, observed, "escalation")
            return ProbeResult(
                qn, owner, "escalation", tv.verdict, observed, agreement,
                f"{detail} (via member {member} → owner {owner})", seeded,
            )
        except _ProbeAbstain as exc:
            kind: Observed = "skipped" if exc.skipped else "abstained"
            agree: Agreement = "skipped" if exc.skipped else "abstained"
            return ProbeResult(
                qn, owner, "escalation", tv.verdict, kind, agree, exc.reason, None,
            )
        finally:
            cur.execute(f"ROLLBACK TO SAVEPOINT {sp}")


def _run_escalation_probe(
    conn: psycopg.Connection[Any],
    schema: Schema,
    verification: Verification,
    *,
    auth_functions: set[str] | None,
) -> Probe:
    """Probe escalation findings against the live DB. Unlike the anon /
    cross-tenant / write probe it needs no synthetic probe role — it reaches the
    bypass through the *real* member and owner roles `owner_reachable_members`
    found, via a ``SET ROLE`` chain. One transaction, rolled back in a finally."""
    tables = {t.qualified_name: t for t in schema.tables}
    reachers: dict[str, list[str]] = {}
    for m in schema.owner_reachable_members:
        for o in m.via_owners:
            reachers.setdefault(o, []).append(m.member)
    # The owner-bypass witness is clean only on a table that provably isolates
    # tenants; a table that itself leaks cross-tenant contaminates the seeded
    # row, so gate on its cross-tenant verdict.
    xt = build_verification(schema, auth_functions=auth_functions, mode="cross-tenant")
    xt_verdicts = {t.qualified_name: t.verdict for t in xt.tables}
    try:
        results = [
            _escalation_probe_one(
                conn, tables, reachers, xt_verdicts, tv, auth_functions, n
            )
            for n, tv in enumerate(verification.tables)
        ]
        return Probe(tuple(results), "escalation")
    finally:
        # Non-destructiveness invariant: never commit the seed rows or SET ROLE.
        conn.rollback()


def run_probe(
    conn: psycopg.Connection[Any],
    schema: Schema,
    verification: Verification,
    *,
    mode: Mode,
    auth_functions: set[str] | None = None,
    probe_role: str = "pgrls_probe_runner",
    anon_roles: set[str] | None = None,
) -> Probe:
    """Probe each verified table live and diff it against the static verdict.

    `conn` MUST be a non-autocommit connection: the whole probe runs in one
    transaction that is **rolled back** in a `finally`, so nothing it seeds or
    creates is committed. The one-time gate creates an unprivileged
    NOLOGIN/NOSUPERUSER/NOBYPASSRLS probe role and grants it USAGE + SELECT,
    INSERT on each probed table; if the connection cannot create a role (no
    CREATEROLE and not superuser) the whole run abstains cleanly.

    `verification` is the static result for `mode` (built by
    `build_verification`); `auth_functions` mirrors what that used so the probe
    pivots on the same scoping axis. Returns a `Probe` whose `results` parallel
    the verification's tables in order.

    ``escalation`` is a different live shape — it reaches the bypass through the
    *real* member/owner roles via a ``SET ROLE`` chain rather than a synthetic
    probe role — so it is dispatched to `_run_escalation_probe`.
    """
    if mode == "escalation":
        return _run_escalation_probe(
            conn, schema, verification, auth_functions=auth_functions
        )
    tables = {t.qualified_name: t for t in schema.tables}
    try:
        gate_error = _setup_probe_role(
            conn, schema, verification, probe_role, mode=mode,
            anon_roles=anon_roles,
        )
        if gate_error is not None:
            return _abstain_all(verification, mode, gate_error)

        results: list[ProbeResult] = []
        guc_states = _anon_set_gucs(schema, anon_roles)
        for n, tv in enumerate(verification.tables):
            table = tables.get(tv.qualified_name)
            if table is None:  # pragma: no cover - verification built from schema
                results.append(
                    ProbeResult(
                        tv.qualified_name, None, mode, tv.verdict,
                        "abstained", "abstained",
                        "table not found in schema", None,
                    )
                )
                continue
            results.append(
                _probe_one(
                    conn, table, tv, mode, auth_functions, probe_role, n,
                    guc_states=guc_states,
                )
            )
        return Probe(tuple(results), mode)
    finally:
        # Non-destructiveness invariant: revert the probe role, every grant, and
        # all seed rows. The probe never commits.
        conn.rollback()


# Policy `TO` entries that need no GRANT to make a policy apply to the probe
# role: PUBLIC applies to every role, and the session pseudo-roles are not real
# grantable roles. Everything else is a named role the probe role must be a
# member of for a `TO <role>` policy to apply.
_NON_GRANTABLE_ROLES: frozenset[str] = frozenset({
    "PUBLIC",
    "CURRENT_USER",
    "SESSION_USER",
    "CURRENT_ROLE",
})


def _setup_probe_role(
    conn: psycopg.Connection[Any],
    schema: Schema,
    verification: Verification,
    probe_role: str,
    *,
    mode: Mode = "anon",
    anon_roles: set[str] | None = None,
) -> str | None:
    """Create the unprivileged probe role and grant it read/seed access.

    Returns None on success, or a one-line abstain reason when the connection
    cannot create the role (no CREATEROLE and not superuser). Savepoint-guarded
    so a denial leaves the transaction usable for the abstain path.
    """
    probed = {tv.qualified_name for tv in verification.tables}
    schemas = sorted(
        {t.schema for t in schema.tables if t.qualified_name in probed}
    )
    tables = [t for t in schema.tables if t.qualified_name in probed]
    qrole = quote_ident(probe_role)
    sp = f"probe_setup_{secrets.token_hex(4)}"
    with conn.cursor() as cur:
        cur.execute(f"SAVEPOINT {sp}")
        try:
            cur.execute(
                f"CREATE ROLE {qrole} NOLOGIN NOSUPERUSER NOBYPASSRLS"
            )
        except psycopg.errors.InsufficientPrivilege:
            cur.execute(f"ROLLBACK TO SAVEPOINT {sp}")
            return (
                "cannot create probe role (connection lacks CREATEROLE / "
                "not superuser)"
            )
        except psycopg.errors.DuplicateObject:
            # A stale role of the same name already exists (a prior aborted
            # probe that somehow committed, or a real role). Roll back the
            # savepoint and abstain rather than reuse a role we did not create
            # (its privileges are unknown — reusing it could be unsound).
            cur.execute(f"ROLLBACK TO SAVEPOINT {sp}")
            return (
                f"probe role {probe_role!r} already exists; pass --probe-role "
                "with an unused name"
            )
        cur.execute(f"RELEASE SAVEPOINT {sp}")
        # A non-superuser must be a member of the role to SET ROLE into it.
        cur.execute(f"GRANT {qrole} TO CURRENT_USER")
        for s in schemas:
            cur.execute(f"GRANT USAGE ON SCHEMA {quote_ident(s)} TO {qrole}")
        for t in tables:
            qtbl = f"{quote_ident(t.schema)}.{quote_ident(t.name)}"
            cur.execute(f"GRANT SELECT, INSERT ON {qtbl} TO {qrole}")
        # Make each policy's named `TO` role apply to the probe role: an RLS
        # policy `TO authenticated` only applies to a session that is (a member
        # of) `authenticated`, so without this a `TO <role>` policy would
        # default-deny the unprivileged probe role and the probe would
        # mis-report (the dominant Supabase shape scopes policies `TO
        # authenticated`). Best-effort + savepoint-guarded per role: a role that
        # does not exist, or that the connection cannot administer, is skipped —
        # the probe then falls back to its prior behavior for that policy. The
        # probe role stays NOSUPERUSER/NOBYPASSRLS (membership confers neither),
        # so RLS still decides row visibility.
        policy_roles = {
            role
            for t in tables
            for policy in t.policies
            for role in policy.roles
            if role not in _NON_GRANTABLE_ROLES
        }
        # ...but only the roles the MODELLED session actually holds. An
        # anonymous caller is not a member of `authenticated`, so granting the
        # probe every policy role made its "anon" session authenticated: on a
        # `FOR SELECT TO authenticated USING (true)` table the static PROVEN
        # ("no anonymous read") is correct, yet the over-privileged probe read
        # the row and reported MISMATCH — accusing a sound proof of
        # contradicting reality, at error severity, exit 1. Under `anon` the
        # probe may hold only the configured anon roles (default `anon`;
        # PUBLIC applies to everyone and is not grantable), mirroring the
        # role-gating the anon prover itself applies. The authenticated modes
        # (cross-tenant / write) DO model a logged-in tenant, so they keep the
        # full set — that is what makes a `TO authenticated` policy apply.
        if mode == "anon":
            allowed = anon_roles if anon_roles is not None else {"anon", "PUBLIC"}
            policy_roles &= {r for r in allowed if r not in _NON_GRANTABLE_ROLES}
        for role in sorted(policy_roles):
            rsp = f"probe_role_{secrets.token_hex(4)}"
            cur.execute(f"SAVEPOINT {rsp}")
            try:
                cur.execute(f"GRANT {quote_ident(role)} TO {qrole}")
            except psycopg.Error:
                cur.execute(f"ROLLBACK TO SAVEPOINT {rsp}")
            else:
                cur.execute(f"RELEASE SAVEPOINT {rsp}")
    return None


# --- renderers -------------------------------------------------------------

_STATIC_LABEL = {"isolated": "PROVEN", "leak": "LEAK", "unverified": "UNVERIFIED"}
_OBSERVED_LABEL = {
    "no_rows": "no rows",
    "rows_visible": "rows visible",
    "write_rejected": "write rejected",
    "write_admitted": "write admitted",
    "skipped": "skipped",
    "abstained": "abstained",
}
_RESULT_LABEL = {
    "agree": "AGREE",
    "mismatch": "MISMATCH",
    "leak_confirmed": "LEAK CONFIRMED",
    "skipped": "skipped",
    "abstained": "abstained",
}


def _summary_line(p: Probe) -> str:
    s = p.summary
    return (
        f"{s['tables']} {pluralize(s['tables'], 'table')} probed: "
        f"{s['agree']} agree, {s['mismatch']} mismatch, "
        f"{s['leak_confirmed']} leak confirmed, {s['skipped']} skipped, "
        f"{s['abstained']} abstained."
    )


def render_text(p: Probe) -> str:
    if not p.results:
        return "No RLS-enabled tables to probe."
    headers = ("TABLE", "MODE", "STATIC", "OBSERVED", "RESULT")
    rows = [
        (
            safe_location(r.qualified_name),
            r.mode,
            _STATIC_LABEL[r.static_verdict],
            _OBSERVED_LABEL[r.observed],
            _RESULT_LABEL[r.agreement],
        )
        for r in p.results
    ]
    out = render_text_table(headers, rows)
    out.append("")
    out.append(_summary_line(p))
    return "\n".join(out)


def render_json(p: Probe) -> str:
    import json

    payload = {
        "mode": p.mode,
        "probe": True,
        "summary": p.summary,
        "tables": [
            {
                "table": r.qualified_name,
                "policy": r.policy,
                "static_verdict": r.static_verdict,
                "observed": r.observed,
                "agreement": r.agreement,
                "seeded": r.seeded,
                "detail": r.detail,
            }
            for r in p.results
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# One SARIF rule per `--mode` — the probe's analog of verify's
# `_SARIF_RULE_ID`, kept distinct (`-probe`) so a probe result is never
# conflated with a static verify result in a combined Code Scanning view.
_PROBE_SARIF_RULE_ID: dict[Mode, str] = {
    "anon": "pgrls-probe-anon",
    "cross-tenant": "pgrls-probe-cross-tenant",
    "write": "pgrls-probe-write",
    "escalation": "pgrls-probe-escalation",
}
_PROBE_SARIF_RULE_TITLE: dict[Mode, str] = {
    "anon": "Live probe: anonymous read isolation",
    "cross-tenant": "Live probe: cross-tenant read isolation",
    "write": "Live probe: cross-tenant write isolation",
    "escalation": "Live probe: reachable owner-bypass escalation",
}


def render_sarif(p: Probe, *, strict: bool = False) -> str:
    """Render a Probe as a SARIF v2.1.0 document for GitHub Code Scanning.

    Reuses lint's `format_sarif` by projecting each *actionable* probe result
    into a `pgrls.violations.Violation` — the same precedent verify / diff set —
    so the SARIF version, `$schema`, `tool.driver` block, severity→level
    mapping, and the empty-location guard stay in ONE place and can never drift.

    The result-set mirrors the probe's exit-code contract (a result is present
    iff the run fails the gate):

    * **MISMATCH** → one `error` result at ``schema.table`` (the static proof and
      the live database disagree). Always fails.
    * **LEAK CONFIRMED** → one `error` result at ``schema.table.policy`` (a
      live-reproduced leak). Always fails.
    * **static LEAK** (whatever the live outcome — reproduced, or the probe
      abstained) → one `error` result: a soundly proven leak fails the gate even
      when the probe cannot reproduce it, so `--probe` is never weaker than plain
      `verify`.
    * **AGREE / skipped** (non-leak static verdict) → no result (all clear).
    * **abstained** (non-leak static verdict) → no result by default; under
      ``strict`` one `note` result at ``schema.table`` (matching the ``--strict``
      gate, which fails on abstain).

    `strict` is keyword-only (default False) so this still satisfies a 1-arg
    renderer signature; the CLI threads ``strict=`` through for the SARIF case.
    """
    from pgrls.formatters.sarif import format_sarif
    from pgrls.violations import Violation

    rule_id = _PROBE_SARIF_RULE_ID[p.mode]
    title = _PROBE_SARIF_RULE_TITLE[p.mode]
    violations: list[Violation] = []
    for r in p.results:
        if r.agreement in ("mismatch", "leak_confirmed"):
            violations.append(
                Violation(
                    rule_id=rule_id,
                    severity="error",
                    title=title,
                    message=(
                        f"{r.qualified_name}: {_RESULT_LABEL[r.agreement]} "
                        f"— {r.detail}"
                    ),
                    # leak_confirmed pins the leaking policy (schema.table.policy,
                    # mirroring lint/verify); mismatch is a table-level proof↔
                    # reality disagreement, so it pins the table.
                    location=(
                        f"{r.qualified_name}.{r.policy}"
                        if r.agreement == "leak_confirmed" and r.policy
                        else r.qualified_name
                    ),
                )
            )
        elif r.static_verdict == "leak":
            # A statically PROVEN leak the live probe did not itself confirm:
            # here the agreement is `abstained` or `skipped` (a reproduced leak
            # is `leak_confirmed`, handled by the branch above). The proven leak
            # still fails the gate (`--probe` is never weaker than plain verify),
            # so it must appear as an error — otherwise a red check carries no
            # alert.
            violations.append(
                Violation(
                    rule_id=rule_id,
                    severity="error",
                    title=title,
                    message=(
                        f"{r.qualified_name}: static verdict LEAK "
                        f"(live probe: {r.agreement}) — {r.detail}"
                    ),
                    location=(
                        f"{r.qualified_name}.{r.policy}"
                        if r.policy
                        else r.qualified_name
                    ),
                )
            )
        elif strict and r.agreement in ("abstained", "skipped"):
            # Both mean "no proof was obtained": `abstained` is the probe
            # declining to run, `skipped` is a statically UNVERIFIED table the
            # probe ran on without seeing a leak — which its own detail calls
            # not a proof. Under --strict both fail the exit gate, so both must
            # appear here; otherwise Code Scanning shows nothing for the very
            # table that failed the build. Mirrors verify's SARIF, where
            # UNVERIFIED surfaces as a `note` under --strict.
            violations.append(
                Violation(
                    rule_id=rule_id,
                    severity="info",  # → SARIF `note`
                    title=title,
                    message=f"{r.qualified_name}: {r.agreement} — {r.detail}",
                    location=r.qualified_name,
                )
            )
    return format_sarif(violations)


PROBE_FORMATS: tuple[str, ...] = ("text", "json", "sarif")


def render(p: Probe, output_format: str) -> str:
    if output_format == "json":
        return render_json(p)
    if output_format == "sarif":
        return render_sarif(p)
    return render_text(p)
