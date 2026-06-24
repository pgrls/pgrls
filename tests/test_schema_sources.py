"""Unit tests for the shared offline schema-source helpers."""
from pgrls.schema_sources import (
    _CATALOG_ONLY_INERT,
    inert_rule_ids,
    schema_source_warnings,
)

ALL_INERT = frozenset(rid for rid, _ in _CATALOG_ONLY_INERT)


def test_inert_rule_ids_sql_is_catalog_only_set():
    assert inert_rule_ids("sql") == ALL_INERT


def test_inert_rule_ids_snapshot_is_conservative_same_as_sql():
    # R2.2: a snapshot may omit catalog fields; skip-and-report, never silently no-op.
    assert inert_rule_ids("snapshot") == ALL_INERT


def test_inert_rule_ids_live_is_empty():
    assert inert_rule_ids("database_url") == frozenset()


def test_warnings_none_command_matches_legacy_text():
    msgs = schema_source_warnings("sql", command=None)
    assert len(msgs) == 2
    assert "absence of findings is NOT a proof" in msgs[0]
    assert "Inert on sql= input" in msgs[1]


def test_warnings_generate_is_generation_scoped():
    msgs = schema_source_warnings("sql", command="generate")
    assert any("generation reflects only" in m.lower() for m in msgs)
    assert all("catalog-only" not in m for m in msgs)


def test_warnings_snapshot_source_is_nonempty():
    msgs = schema_source_warnings("snapshot", command="lint")
    assert msgs and any("snapshot" in m.lower() for m in msgs)


def test_warnings_live_source_is_empty():
    assert schema_source_warnings("database_url", command="lint") == []
