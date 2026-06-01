"""Adjudicated precision corpus — measurement engine.

Each :class:`~corpus.cases.Case` is a small, self-contained schema. The
harness applies it to a *fresh* ``public`` schema on a throwaway
Postgres, introspects it through the exact production path
(:func:`pgrls.introspect.introspect`), and runs the full built-in rule
set at **default options** — no ``[lint] disable``, no per-rule
allowlists, no severity overrides. That is the rawest possible firing
signal: whatever a user gets from ``pgrls lint`` with an empty config.

A case's ``expect`` set is the COMPLETE set of rule IDs that *should*
fire on it. Anything fired that is not in ``expect`` (and not recorded
in ``known_fp``) is a **false positive**; anything in ``expect`` that
does not fire is a **false negative**.

What this measures — and what it does not
-----------------------------------------
This is a *construct-validity* corpus: it measures whether pgrls fires
correctly on hand-labeled schemas, including adversarial near-misses
built specifically to bait false positives (a ``coalesce()``-wrapped
auth check, an ``IS NULL`` buried in a subquery, a tenant predicate
wrapped in a ``SubLink``…). It is deliberately adversarial on the
negative side, because a clean schema that trivially fires nothing tells
you nothing about robustness.

It is NOT a random sample of real-world databases. The numbers are a
precision/recall characterization of *this labeled set*, not an estimate
of the false-positive rate over the wild population of all Postgres
schemas. Treat them as a regression gate and a robustness statement, not
a population parameter. See ``docs/PRECISION.md`` for the published run.

The two artifact-dependent rules (HYG004 — coverage; PERF005 — runtime
seq-scan stats) need data that does not exist for a static schema, so
they are out of scope here and excluded from the rule set.
"""
from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from dataclasses import dataclass, field

import psycopg

from corpus.cases import CASES, Case
from pgrls.introspect import introspect
from pgrls.rules import Rule, all_rules

# Rules that consume a runtime artifact (coverage / perf stats) rather
# than the schema alone. They cannot fire on a static corpus case, so
# they are excluded rather than counted as silent.
ARTIFACT_RULES: frozenset[str] = frozenset({"HYG004", "PERF005"})

# Auth stubs + roles, created once on the throwaway DB. Mirrors
# demo/cases/_shared.sql: Supabase-style GUC-reading functions so a
# policy that calls auth.uid()/auth.role()/auth.jwt() parse-analyzes at
# CREATE POLICY time without a real Supabase stack, plus the roles the
# gold-standard `pgrls generate` output and demo fixtures grant to.
_PRELUDE = """
CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claim.sub', true)::UUID $$;
CREATE OR REPLACE FUNCTION auth.role() RETURNS TEXT LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claim.role', true) $$;
CREATE OR REPLACE FUNCTION auth.jwt() RETURNS JSONB LANGUAGE SQL STABLE
    AS $$ SELECT current_setting('request.jwt.claims', true)::JSONB $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='app_authenticated')
    THEN CREATE ROLE app_authenticated NOLOGIN; END IF;
END $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated')
    THEN CREATE ROLE authenticated NOLOGIN; END IF;
END $$;
"""

# Fresh, isolated namespace per case. Dropping `public` clears every
# table/policy/index the previous case created so findings never leak
# across cases. `auth` (the prelude) is intentionally preserved.
_RESET = "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;"


def corpus_rules() -> list[Rule]:
    """The built-in rules in scope for the static corpus (all but the
    two artifact-dependent rules)."""
    return [r for r in all_rules() if r.id not in ARTIFACT_RULES]


@contextlib.contextmanager
def corpus_db() -> Iterator[str]:
    """Yield a connection URL to a *throwaway* Postgres the harness may
    DROP/CREATE schemas on.

    Prefers ``PGRLS_TEST_DATABASE_URL`` then ``DATABASE_URL`` (the CI
    service container), else spins a testcontainer pinned to
    ``PGRLS_TEST_PG_IMAGE`` (default ``postgres:16-alpine``). Mirrors the
    repo's existing test-DB resolution so ``corpus/`` behaves like the
    other suites.
    """
    url = os.environ.get("PGRLS_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if url:
        yield url
        return
    from testcontainers.postgres import PostgresContainer

    image = os.environ.get("PGRLS_TEST_PG_IMAGE", "postgres:16-alpine")
    with PostgresContainer(
        image, username="c", password="c", dbname="c"
    ) as pg:
        yield pg.get_connection_url(driver=None)


@dataclass(frozen=True)
class CaseResult:
    case: Case
    fired: frozenset[str]

    @property
    def false_positives(self) -> frozenset[str]:
        """Rules that fired but are neither expected nor a recorded
        known FP — i.e. *undocumented* false positives. The regression
        test fails if any case has these."""
        return self.fired - self.case.expect - self.case.known_fp

    @property
    def false_negatives(self) -> frozenset[str]:
        """Expected rules that did not fire."""
        return self.case.expect - self.fired

    @property
    def all_unexpected(self) -> frozenset[str]:
        """Every firing outside ``expect`` — undocumented *and* known
        FPs. This is what the published FP count uses: a known FP is
        still a false positive, it is just one we have already
        adjudicated (so it does not break CI)."""
        return self.fired - self.case.expect


def measure(conn_url: str, cases: list[Case] = CASES) -> list[CaseResult]:
    """Apply, introspect, and lint every case on the DB at ``conn_url``.

    The connection's role must be able to DROP/CREATE schemas and roles
    (the throwaway testcontainer superuser is fine).
    """
    rules = corpus_rules()
    results: list[CaseResult] = []
    with psycopg.connect(conn_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(_PRELUDE)
        for case in cases:
            with conn.cursor() as cur:
                cur.execute(_RESET)
                cur.execute(case.sql)
            schema = introspect(conn, ["public"])
            fired: set[str] = set()
            for rule in rules:
                for v in rule.check(schema, {}):
                    fired.add(v.rule_id)
            results.append(CaseResult(case=case, fired=frozenset(fired)))
    return results


@dataclass
class RuleStats:
    rule_id: str
    tp: int = 0   # expected and fired
    fp: int = 0   # fired but not expected (incl. known FPs)
    fn: int = 0   # expected but did not fire

    @property
    def fires(self) -> int:
        return self.tp + self.fp

    @property
    def precision(self) -> float | None:
        return self.tp / self.fires if self.fires else None

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def fp_rate(self) -> float | None:
        return self.fp / self.fires if self.fires else None


@dataclass
class Summary:
    per_rule: dict[str, RuleStats] = field(default_factory=dict)
    n_cases: int = 0
    n_positive: int = 0
    n_negative: int = 0
    tp_total: int = 0
    fp_total: int = 0
    fn_total: int = 0
    undocumented_fp: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    false_negatives: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    known_fp: list[tuple[str, frozenset[str]]] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        fires = self.tp_total + self.fp_total
        return self.tp_total / fires if fires else None

    @property
    def recall(self) -> float | None:
        denom = self.tp_total + self.fn_total
        return self.tp_total / denom if denom else None


def summarize(results: list[CaseResult]) -> Summary:
    s = Summary(n_cases=len(results))
    rule_ids = [r.id for r in corpus_rules()]
    s.per_rule = {rid: RuleStats(rule_id=rid) for rid in rule_ids}
    for res in results:
        if res.case.kind == "positive":
            s.n_positive += 1
        else:
            s.n_negative += 1
        expect = res.case.expect
        fired = res.fired
        for rid in s.per_rule:
            in_expect = rid in expect
            in_fired = rid in fired
            if in_expect and in_fired:
                s.per_rule[rid].tp += 1
            elif in_expect and not in_fired:
                s.per_rule[rid].fn += 1
            elif (not in_expect) and in_fired:
                s.per_rule[rid].fp += 1
        s.tp_total += len(fired & expect)
        s.fp_total += len(res.all_unexpected)
        s.fn_total += len(res.false_negatives)
        if res.false_positives:
            s.undocumented_fp.append((res.case.name, res.false_positives))
        if res.false_negatives:
            s.false_negatives.append((res.case.name, res.false_negatives))
        documented = res.fired & res.case.known_fp
        if documented:
            s.known_fp.append((res.case.name, documented))
    return s
