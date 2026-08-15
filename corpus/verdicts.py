"""Adjudicated **verdict** corpus for `pgrls verify`.

The sibling `cases.py` corpus measures which *lint rules* fire. This one
measures what the **prover** concludes: for a small, self-contained schema,
the exact per-table verdict `verify` returns in a given `--mode`.

Why this exists. Two exploitable false clears shipped in 0.52.0 — `--mode
write` proved isolation on a schema one tenant could wipe, and `--mode anon`
was fixed only after reporting a LEAK on the canonical tenant policy. Both
were caught by hand. Neither could have been caught by `cases.py`, which only
ever asks "did rule X fire"; a verdict regression is invisible to it. Every
case below is a verdict a human adjudicated against real Postgres behaviour,
so a change that silently flips `leak` to `isolated` fails the build.

The bar for adding a case: the expected verdict must be checkable against what
Postgres actually does, not merely against what the prover currently says.
Pinning today's output is how a wrong verdict becomes a permanent fixture.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import psycopg

from pgrls.introspect import introspect
from pgrls.verify import (
    Mode,
    build_escalation,
    build_reachability,
    build_verification,
)

# Roles the view/owner cases need. Created once; `_RESET` drops only `public`,
# so role state survives between cases and the grants are re-issued per case.
_VERDICT_PRELUDE = """
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon')
    THEN CREATE ROLE anon NOLOGIN; END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='corpus_owner')
    THEN CREATE ROLE corpus_owner NOLOGIN; END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='corpus_bypass')
    THEN CREATE ROLE corpus_bypass NOLOGIN BYPASSRLS; END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='corpus_plain')
    THEN CREATE ROLE corpus_plain NOLOGIN; END IF;
END $$;
-- Self-contained on purpose: the policies below are `TO authenticated`, and
-- Postgres rejects a policy naming a role that does not exist. `cases.py`
-- happens to create this too, but relying on that would make this corpus fail
-- depending on which suite ran first.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated')
    THEN CREATE ROLE authenticated NOLOGIN; END IF;
END $$;
"""

_RESET = """
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT CREATE, USAGE ON SCHEMA public
    TO corpus_owner, corpus_bypass, corpus_plain;
GRANT USAGE ON SCHEMA public TO anon, authenticated;
"""

# Roles are CLUSTER-wide: dropping the `public` schema between cases does not
# remove them. `corpus_bypass` holds BYPASSRLS, which SEC016 flags — so leaving
# it behind makes SEC016 fire on every case of the *lint* corpus that runs
# afterwards, in the same database. (Observed exactly that: `pytest corpus/`
# passed on a fresh database and then failed on the second run against the
# same one.) Anything this module creates, this module removes.
_TEARDOWN = """
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
DROP OWNED BY corpus_owner, corpus_bypass, corpus_plain, anon;
DROP ROLE IF EXISTS corpus_owner, corpus_bypass, corpus_plain, anon;
"""


@dataclass(frozen=True)
class VerdictCase:
    """One schema, one mode, and the COMPLETE set of verdicts expected.

    `expect` is the sorted multiset of `(qualified_name, verdict)` the mode
    must return — complete, so an *extra* finding fails just as loudly as a
    missing one. A table reachable through two leaky views legitimately
    appears twice.

    `expect_paths` additionally pins *which* view or owner each finding came
    through (the proof's identifier), for the modes where that is the point.
    """

    name: str
    mode: Mode
    sql: str
    expect: tuple[tuple[str, str], ...]
    note: str
    expect_paths: tuple[str, ...] = field(default=())


# A base table whose policy scopes rows to a custom GUC. An anonymous session
# has run no `SET`, so `current_setting('app.tenant')` raises and the direct
# read returns nothing — the table genuinely isolates. Every view case below
# perturbs exactly one thing about a view over it.
_SCOPED_TABLE = """
SET ROLE corpus_owner;
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO authenticated
    USING (tenant = (SELECT current_setting('app.tenant', true)));
"""

VERDICT_CASES: list[VerdictCase] = [
    # ---- reachability: the six live-measured view cases -------------------
    VerdictCase(
        name="reach_owner_exempt_view_leaks",
        mode="reachability",
        sql=_SCOPED_TABLE + """
CREATE VIEW docs_v AS SELECT * FROM docs;
GRANT SELECT ON docs_v TO anon;
RESET ROLE;
""",
        expect=(("public.docs", "leak"),),
        expect_paths=("public.docs_v",),
        note=(
            "security_invoker off + owner owns the table + RLS not FORCE'd. "
            "Measured on PG16: anon reads every row through the view, "
            "including another tenant's, while the table itself denies it."
        ),
    ),
    VerdictCase(
        name="reach_security_invoker_view_is_silent",
        mode="reachability",
        sql=_SCOPED_TABLE + """
CREATE VIEW docs_v AS SELECT * FROM docs;
ALTER VIEW docs_v SET (security_invoker = true);
GRANT SELECT ON docs_v TO anon;
RESET ROLE;
""",
        expect=(),
        note=(
            "An invoker view re-applies the CALLER's RLS. Measured: anon is "
            "denied outright. Must stay silent."
        ),
    ),
    VerdictCase(
        name="reach_forced_base_table_is_silent",
        mode="reachability",
        sql=_SCOPED_TABLE + """
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE VIEW docs_v AS SELECT * FROM docs;
GRANT SELECT ON docs_v TO anon;
RESET ROLE;
""",
        expect=(),
        note=(
            "FORCE strips the owner's exemption. Measured: the same view that "
            "returned every row returns 0 once the base table is FORCE'd."
        ),
    ),
    VerdictCase(
        name="reach_unrelated_owner_is_silent",
        mode="reachability",
        sql=_SCOPED_TABLE + """
GRANT SELECT ON docs TO corpus_plain;
RESET ROLE;
SET ROLE corpus_plain;
CREATE VIEW docs_v AS SELECT * FROM docs;
GRANT SELECT ON docs_v TO anon;
RESET ROLE;
""",
        expect=(),
        note=(
            "A view owned by an ordinary third role with a plain SELECT grant "
            "is NOT exempt — RLS applies to that owner. Measured: 0 rows. "
            "This is the case that keeps the mode from flooding."
        ),
    ),
    VerdictCase(
        name="reach_bypassrls_owner_leaks",
        mode="reachability",
        sql=_SCOPED_TABLE + """
GRANT SELECT ON docs TO corpus_bypass;
RESET ROLE;
SET ROLE corpus_bypass;
CREATE VIEW docs_v AS SELECT * FROM docs;
GRANT SELECT ON docs_v TO anon;
RESET ROLE;
""",
        expect=(("public.docs", "leak"),),
        expect_paths=("public.docs_v",),
        note=(
            "A BYPASSRLS owner is exempt regardless of who owns the table. "
            "Measured: anon reads every row."
        ),
    ),
    VerdictCase(
        name="reach_bypassrls_owner_leaks_even_under_force",
        mode="reachability",
        sql=_SCOPED_TABLE + """
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
GRANT SELECT ON docs TO corpus_bypass;
RESET ROLE;
SET ROLE corpus_bypass;
CREATE VIEW docs_v AS SELECT * FROM docs;
GRANT SELECT ON docs_v TO anon;
RESET ROLE;
""",
        expect=(("public.docs", "leak"),),
        expect_paths=("public.docs_v",),
        note=(
            "FORCE does not constrain BYPASSRLS. Measured rather than taken "
            "from the docs: anon still reads every row."
        ),
    ),
    VerdictCase(
        name="reach_ungranted_view_is_silent",
        mode="reachability",
        sql=_SCOPED_TABLE + """
CREATE VIEW docs_v AS SELECT * FROM docs;
RESET ROLE;
""",
        expect=(),
        note=(
            "An exempt-owner invoker-off view anon cannot SELECT from is not "
            "a path anon can take. No grant, no finding."
        ),
    ),

    # ---- anon: the MF5 false-LEAK regression -----------------------------
    VerdictCase(
        name="anon_canonical_tenant_policy_is_isolated",
        mode="anon",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO authenticated
    USING (tenant = (SELECT current_setting('app.tenant', true)));
""",
        expect=(("public.docs", "isolated"),),
        note=(
            "The predicate a correct multi-tenant deployment writes. Shipped "
            "as a false LEAK through 0.52.0 (fixed in #272): an anonymous "
            "session has run no SET, so the GUC read yields no row. Regression "
            "guard — this must never report leak again."
        ),
    ),

    # ---- write: the MF3 false-ISOLATED regressions -----------------------
    VerdictCase(
        name="write_open_using_gate_is_a_leak",
        mode="write",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR UPDATE TO authenticated
    USING (true)
    WITH CHECK (tenant = (SELECT current_setting('app.tenant', true)));
""",
        expect=(("public.docs", "leak"),),
        note=(
            "The OLD-row gate is wide open: a session re-stamps another "
            "tenant's row to itself via a column-reading-free UPDATE. Proved "
            "isolated through 0.52.0 (fixed in #275) because only WITH CHECK "
            "was modelled. Reproduced live on PG16."
        ),
    ),
    VerdictCase(
        name="write_delete_escape_disjunct_is_a_leak",
        mode="write",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR DELETE TO authenticated
    USING (tenant = (SELECT current_setting('app.tenant', true))
           OR body IS NOT NULL);
""",
        expect=(("public.docs", "leak"),),
        note=(
            "The MF3 regression guard proper: DELETE is a write command gated "
            "by its USING. Before #275 DELETE was excluded from the write "
            "bucket entirely and contributed no proof at all. The scoping "
            "equality gives the prover a tenant axis, and the second disjunct "
            "escapes it — so another tenant's row is deletable, provably."
        ),
    ),
    VerdictCase(
        name="write_bare_true_delete_abstains",
        mode="write",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR DELETE TO authenticated USING (true);
""",
        expect=(("public.docs", "unverified"),),
        note=(
            "Boundary case, and NOT a false clear — `unverified` is the honest "
            "answer. A bare `true` carries no `<column> = <session identity>` "
            "for the prover to negate, so it cannot name 'another tenant's "
            "row'. Note the module docstring's escape hatch — 'a total leak is "
            "unverified in cross-tenant but already caught as an anon leak' — "
            "does NOT apply to this shape: with no read policy at all, anon "
            "and cross-tenant both (correctly) report `isolated`, so nothing "
            "proves the leak. What carries it is `--strict` (which fails on "
            "unverified) and the write-side lint rules SEC006 / SEC040. "
            "Pinned so a future change that turns this into a confident "
            "`isolated` is caught immediately."
        ),
    ),
    VerdictCase(
        name="write_scoped_both_gates_is_isolated",
        mode="write",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR ALL TO authenticated
    USING (tenant = (SELECT current_setting('app.tenant', true)))
    WITH CHECK (tenant = (SELECT current_setting('app.tenant', true)));
""",
        expect=(("public.docs", "isolated"),),
        note=(
            "The shape `pgrls generate` emits — both gates scoped identically. "
            "The MF3 fix composes them by disjunction, so this must stay "
            "isolated: a fix that made every write policy leak would pass the "
            "two cases above and fail here."
        ),
    ),

    # ---- cross-tenant ----------------------------------------------------
    VerdictCase(
        name="cross_tenant_scoped_policy_is_isolated",
        mode="cross-tenant",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO authenticated
    USING (tenant = (SELECT current_setting('app.tenant', true)));
""",
        expect=(("public.docs", "isolated"),),
        note="The tenant-scoping equality the cross-tenant prover exists for.",
    ),
    VerdictCase(
        name="cross_tenant_open_policy_is_a_leak",
        mode="cross-tenant",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO authenticated
    USING (tenant = (SELECT current_setting('app.tenant', true))
           OR body IS NOT NULL);
""",
        expect=(("public.docs", "leak"),),
        note=(
            "A second disjunct that ignores the tenant key admits every row "
            "with a body — a real cross-tenant read."
        ),
    ),

    # ---- escalation ------------------------------------------------------
    VerdictCase(
        name="escalation_no_reachable_owner_is_empty",
        mode="escalation",
        sql="""
CREATE TABLE docs (id int primary key, tenant text NOT NULL, body text);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON docs FOR SELECT TO authenticated
    USING (tenant = (SELECT current_setting('app.tenant', true)));
""",
        expect=(),
        note=(
            "No low-trust role is a member of the table's owner, so there is "
            "no SET ROLE path to escalate along — the mode reports nothing."
        ),
    ),
]


_BUILDERS = {
    "reachability": build_reachability,
    "escalation": build_escalation,
}


def _verify(schema: Any, mode: Mode) -> Any:
    build = _BUILDERS.get(mode)
    if build is not None:
        return build(schema)
    return build_verification(schema, mode=mode)


@dataclass(frozen=True)
class VerdictResult:
    case: VerdictCase
    actual: tuple[tuple[str, str], ...]
    actual_paths: tuple[str, ...]

    @property
    def ok(self) -> bool:
        if self.actual != self.case.expect:
            return False
        if self.case.expect_paths and self.actual_paths != self.case.expect_paths:
            return False
        return True


def measure_verdicts(
    conn_url: str, cases: list[VerdictCase] | None = None
) -> list[VerdictResult]:
    """Apply, introspect and verify every case on the DB at `conn_url`.

    The connection's role must be able to DROP/CREATE schemas and SET ROLE to
    the corpus roles (a throwaway superuser is fine).
    """
    selected = VERDICT_CASES if cases is None else cases
    results: list[VerdictResult] = []
    with psycopg.connect(conn_url, autocommit=True) as conn:
        try:
            _measure_into(conn, selected, results)
        finally:
            # Runs even when a case raises, so a mid-run failure cannot leave
            # a BYPASSRLS role behind to corrupt the next suite.
            with conn.cursor() as cur:
                cur.execute(_TEARDOWN)
    return results


def _measure_into(
    conn: Any, selected: list[VerdictCase], results: list[VerdictResult]
) -> None:
    with conn.cursor() as cur:
        cur.execute(_VERDICT_PRELUDE)
    for case in selected:
        with conn.cursor() as cur:
            cur.execute(_RESET)
            cur.execute(case.sql)
            # A case that ends mid-SET ROLE would introspect as the wrong
            # role; make the reset unconditional rather than trusting each
            # fixture to remember.
            cur.execute("RESET ROLE")
        schema = introspect(conn, ["public"])
        v = _verify(schema, case.mode)
        actual = tuple(sorted((t.qualified_name, t.verdict) for t in v.tables))
        paths = tuple(
            sorted(
                p.policy
                for t in v.tables
                for p in t.proofs
                if t.verdict == "leak"
            )
        )
        results.append(VerdictResult(case=case, actual=actual, actual_paths=paths))


def failures(results: list[VerdictResult]) -> list[VerdictResult]:
    return [r for r in results if not r.ok]


def describe(r: VerdictResult) -> str:
    lines = [
        f"{r.case.name} [--mode {r.case.mode}]",
        f"  expected: {r.case.expect or '(no findings)'}",
        f"  actual:   {r.actual or '(no findings)'}",
    ]
    if r.case.expect_paths:
        lines.append(f"  expected paths: {r.case.expect_paths}")
        lines.append(f"  actual paths:   {r.actual_paths}")
    lines.append(f"  {r.case.note}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - manual run
    from corpus.harness import corpus_db

    url = os.environ.get("PGRLS_TEST_DATABASE_URL")
    if url:
        rs = measure_verdicts(url)
    else:
        with corpus_db() as u:
            rs = measure_verdicts(u)
    bad = failures(rs)
    for r in rs:
        print(("PASS " if r.ok else "FAIL ") + r.case.name)
    if bad:
        print()
        for r in bad:
            print(describe(r))
            print()
    print(f"{len(rs) - len(bad)}/{len(rs)} verdict cases match")
