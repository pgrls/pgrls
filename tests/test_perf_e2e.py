"""Live-DB end-to-end for `pgrls perf` (runtime seq-scan analysis).

Two things only a real server can prove:

* the ``pg_stat_user_tables`` query in ``collect_table_stats`` runs and
  returns the expected columns on every supported Postgres major, and
* the full pipeline (introspect → PERF003 cross-reference → report)
  correctly classifies an observed sequential scan as *confirmed* (no
  index for the RLS predicate) vs *index-unused* (an index exists but the
  table still seq-scans).

Stats timing: ``pg_conn`` is autocommit, so each statement's stats commit
immediately. We create and ANALYZE the table *before* the workload (so
``n_live_tup`` is populated — ``pg_stat_reset`` would zero it), run enough
sequential scans to clear the threshold, then ``pg_stat_force_next_flush``
(PG15+) to push this backend's pending counters out before reading.
"""
from __future__ import annotations

import time

import psycopg

from pgrls.introspect import introspect
from pgrls.perf import (
    CONFIRMED,
    INDEX_UNUSED,
    PerfThresholds,
    build_perf_report,
    collect_statements,
    collect_table_stats,
)

# The CLI helper that turns PERF003's static verdict into a (schema, table)
# set — exercised here against real introspected ASTs.
from pgrls.cli import _perf003_flagged_tables

# Loose enough to fire on a modest test table, still above trivially-small.
_THRESHOLDS = PerfThresholds(min_live_tup=1_000, min_seq_scans=50, min_seq_pct=50.0)


def _seqscan_workload(conn: psycopg.Connection, n: int = 60) -> None:
    """Run `n` queries that must sequentially scan perf_posts.

    The predicate is on an unindexed column, so the planner has no choice
    but a sequential scan; the table owner bypasses the (non-forced) RLS
    policy, so all rows are scanned.
    """
    with conn.cursor() as cur:
        for i in range(n):
            cur.execute(
                "SELECT count(*) FROM public.perf_posts WHERE tenant_id = %s",
                (i % 50,),
            )


def _stats_after_flush(
    conn: psycopg.Connection, table: str, *, want_seq: int = 50
) -> dict:
    """Read table stats, forcing a stats flush and retrying briefly.

    Cumulative stats are flushed asynchronously; `pg_stat_force_next_flush`
    pushes this backend's pending counters out, but we still retry a few
    times to absorb any lag before asserting.
    """
    for _ in range(20):
        with conn.cursor() as cur:
            cur.execute("SELECT pg_stat_force_next_flush()")
            cur.execute("SELECT pg_stat_clear_snapshot()")
        stats = collect_table_stats(conn, ["public"])
        ts = stats.get(("public", table))
        if ts is not None and ts.seq_scan >= want_seq:
            return stats
        time.sleep(0.1)
    return collect_table_stats(conn, ["public"])


def test_collect_table_stats_reads_live_columns(apply_sql, pg_conn) -> None:
    # Minimal: the query parses and returns integer counters on this PG.
    apply_sql(
        """
        CREATE TABLE public.things (
            id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            tenant_id bigint NOT NULL
        );
        INSERT INTO public.things (tenant_id)
            SELECT g % 10 FROM generate_series(1, 2000) g;
        ANALYZE public.things
        """
    )
    stats = collect_table_stats(pg_conn, ["public"])
    ts = stats[("public", "things")]
    assert ts.schema == "public" and ts.table == "things"
    assert isinstance(ts.seq_scan, int)
    assert isinstance(ts.idx_scan, int)
    assert ts.n_live_tup >= 1_000  # populated by ANALYZE


def test_perf_confirms_seqscan_on_unindexed_rls_table(apply_sql, pg_conn) -> None:
    apply_sql(
        """
        CREATE TABLE public.perf_posts (
            id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            tenant_id bigint NOT NULL,
            body text
        );
        INSERT INTO public.perf_posts (tenant_id, body)
            SELECT g % 50, 'row ' || g FROM generate_series(1, 20000) g;
        ALTER TABLE public.perf_posts ENABLE ROW LEVEL SECURITY;
        CREATE POLICY perf_posts_iso ON public.perf_posts
            USING (tenant_id = current_setting('app.tenant_id', true)::bigint);
        ANALYZE public.perf_posts
        """
    )
    # No index on tenant_id → PERF003 flags the policy statically.
    schema = introspect(pg_conn, schemas=["public"])
    flagged = _perf003_flagged_tables(schema)
    assert ("public", "perf_posts") in flagged

    _seqscan_workload(pg_conn, n=60)
    stats = _stats_after_flush(pg_conn, "perf_posts")
    assert stats[("public", "perf_posts")].seq_scan >= 50

    report = build_perf_report(
        schema, stats, statically_flagged=flagged, thresholds=_THRESHOLDS
    )
    finding = next(
        (f for f in report.findings if f.stats.table == "perf_posts"), None
    )
    assert finding is not None, "expected perf_posts to be flagged"
    assert finding.classification == CONFIRMED
    assert finding.severity == "warning"


def test_perf_index_unused_when_predicate_is_indexed(apply_sql, pg_conn) -> None:
    # tenant_id IS indexed → PERF003 does NOT flag the table. But the table
    # is still sequentially scanned (by queries on an unindexed column), so
    # runtime surfaces it as index-unused: a real signal static analysis
    # can't produce.
    apply_sql(
        """
        CREATE TABLE public.perf_posts (
            id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            tenant_id bigint NOT NULL,
            body text
        );
        INSERT INTO public.perf_posts (tenant_id, body)
            SELECT g % 50, 'row ' || g FROM generate_series(1, 20000) g;
        CREATE INDEX ON public.perf_posts (tenant_id);
        ALTER TABLE public.perf_posts ENABLE ROW LEVEL SECURITY;
        CREATE POLICY perf_posts_iso ON public.perf_posts
            USING (tenant_id = current_setting('app.tenant_id', true)::bigint);
        ANALYZE public.perf_posts
        """
    )
    schema = introspect(pg_conn, schemas=["public"])
    flagged = _perf003_flagged_tables(schema)
    assert ("public", "perf_posts") not in flagged  # predicate column indexed

    # Force seq scans via an unindexed predicate (body LIKE).
    with pg_conn.cursor() as cur:
        for _ in range(60):
            cur.execute(
                "SELECT count(*) FROM public.perf_posts WHERE body LIKE 'row 1%'"
            )
    stats = _stats_after_flush(pg_conn, "perf_posts")
    assert stats[("public", "perf_posts")].seq_scan >= 50

    report = build_perf_report(
        schema, stats, statically_flagged=flagged, thresholds=_THRESHOLDS
    )
    finding = next(
        (f for f in report.findings if f.stats.table == "perf_posts"), None
    )
    assert finding is not None
    assert finding.classification == INDEX_UNUSED
    assert finding.severity == "info"


def test_collect_statements_none_without_extension(apply_sql, pg_conn) -> None:
    # The shared test container doesn't preload pg_stat_statements, so the
    # extension is absent — collect_statements must degrade to None (never
    # raise), which is what lets `pgrls perf --statements` fall back cleanly.
    apply_sql("CREATE TABLE public.x (id int)")
    assert collect_statements(pg_conn) is None


def test_collect_statements_live_with_extension() -> None:
    # Validate the pg_stat_statements SQL + relation parsing against a REAL
    # extension. Needs a throwaway container with the library preloaded
    # (it can't be enabled at runtime), so this boots its own — skipped when
    # an external DB is supplied (we can't reconfigure its preload libs).
    import os

    import pytest

    if os.environ.get("PGRLS_TEST_DATABASE_URL"):
        pytest.skip("needs a throwaway container to set shared_preload_libraries")
    from testcontainers.postgres import PostgresContainer

    image = os.environ.get("PGRLS_TEST_PG_IMAGE", "postgres:16-alpine")
    container = PostgresContainer(
        image, username="postgres", password="postgres", dbname="postgres"
    ).with_command("postgres -c shared_preload_libraries=pg_stat_statements")
    with container as pg:
        url = pg.get_connection_url(driver=None)
        with psycopg.connect(url, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
                cur.execute(
                    "CREATE TABLE public.s_posts (id int, tenant_id int)"
                )
                for _ in range(3):
                    cur.execute(
                        "SELECT * FROM public.s_posts WHERE tenant_id = 1"
                    )
            stmts = collect_statements(conn)
    assert stmts is not None
    # The SELECT was normalized + parsed; it references the qualified table.
    assert any(s.references("public", "s_posts") for s in stmts)
