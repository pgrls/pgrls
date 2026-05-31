"""Unit tests for PERF005 — RLS table observed to sequentially scan.

PERF005 is opt-in: it fires only when lint injects a parsed runtime-stats
snapshot under the private `_perf` option (from `pgrls lint --perf`). These
tests pass that dict directly. The CLI wiring (`lint --perf` loads the
artifact) is covered in tests/test_perf.py; the live pipeline in
tests/test_perf_e2e.py.
"""
from __future__ import annotations

from pgrls.model import Policy, Schema, Table
from pgrls.perf import TableStats
from pgrls.rules.perf005 import PERF005


def _table(name: str, *, rls: bool, schema: str = "public") -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=rls,
        policies=(
            Policy(
                name=f"{name}_p",
                command="ALL",
                permissive=True,
                roles=("authenticated",),
                using_sql="true",
                with_check_sql=None,
            ),
        ),
    )


def _pressured(schema: str, name: str) -> TableStats:
    # Over every default threshold.
    return TableStats(
        schema=schema,
        table=name,
        seq_scan=500,
        seq_tup_read=5_000_000,
        idx_scan=1,
        n_live_tup=500_000,
    )


def _schema(*tables: Table) -> Schema:
    return Schema(tables=tables)


def test_inert_without_artifact() -> None:
    # No `_perf` injected (normal lint run) → silent, not "flag everything".
    schema = _schema(_table("posts", rls=True))
    assert PERF005().check(schema, {}) == []
    assert PERF005().check(schema, {"_perf": "not-a-dict"}) == []


def test_fires_for_pressured_rls_table() -> None:
    schema = _schema(_table("posts", rls=True))
    perf = {("public", "posts"): _pressured("public", "posts")}
    out = PERF005().check(schema, {"_perf": perf})
    assert len(out) == 1
    v = out[0]
    assert v.rule_id == "PERF005"
    assert v.severity == "info"
    assert v.location == "public.posts"
    assert "sequentially scanned" in v.message


def test_non_rls_table_never_flagged() -> None:
    schema = _schema(_table("public_data", rls=False))
    perf = {("public", "public_data"): _pressured("public", "public_data")}
    assert PERF005().check(schema, {"_perf": perf}) == []


def test_table_without_stats_skipped() -> None:
    schema = _schema(_table("posts", rls=True))
    assert PERF005().check(schema, {"_perf": {}}) == []


def test_below_threshold_not_flagged() -> None:
    schema = _schema(_table("posts", rls=True))
    small = {
        ("public", "posts"): TableStats(
            schema="public",
            table="posts",
            seq_scan=2,
            seq_tup_read=10,
            idx_scan=0,
            n_live_tup=100,
        )
    }
    assert PERF005().check(schema, {"_perf": small}) == []


def test_thresholds_from_options_lower_the_bar() -> None:
    schema = _schema(_table("posts", rls=True))
    small = {
        ("public", "posts"): TableStats(
            schema="public",
            table="posts",
            seq_scan=2,
            seq_tup_read=10,
            idx_scan=0,
            n_live_tup=100,
        )
    }
    opts = {
        "_perf": small,
        "min_rows": 10,
        "min_seq_scans": 1,
        "min_seq_pct": 10.0,
    }
    assert len(PERF005().check(schema, opts)) == 1


def test_bad_threshold_option_falls_back_to_default() -> None:
    # A non-numeric config value must not crash the lint run.
    schema = _schema(_table("posts", rls=True))
    perf = {("public", "posts"): _pressured("public", "posts")}
    out = PERF005().check(
        schema, {"_perf": perf, "min_rows": "lots", "min_seq_pct": None}
    )
    assert len(out) == 1  # defaults applied, table still over them


def test_allowlist_suppresses_by_qualified_and_bare_name() -> None:
    schema = _schema(_table("posts", rls=True))
    perf = {("public", "posts"): _pressured("public", "posts")}
    assert PERF005().check(
        schema, {"_perf": perf, "allowlist": ["public.posts"]}
    ) == []
    assert PERF005().check(
        schema, {"_perf": perf, "allowlist": ["posts"]}
    ) == []
