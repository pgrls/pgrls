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


def test_warnings_lint_command_uses_corrected_wording():
    """CLI lint/fix path gets corrected wording: --database-url, no snapshot recommendation."""
    msgs = schema_source_warnings("sql", command="lint")
    assert len(msgs) == 2
    # Must mention --database-url or $DATABASE_URL (not the internal arg name)
    assert "--database-url" in msgs[0] or "$DATABASE_URL" in msgs[0], (
        "CLI warning must name --database-url or $DATABASE_URL, not internal arg name"
    )
    # Must NOT recommend snapshot as "full coverage"
    assert "snapshot" not in msgs[0].lower(), (
        "CLI warning must not recommend a snapshot for full coverage"
    )
    # The "absence of findings" text must still be present
    assert "absence of findings is NOT a proof" in msgs[0]


def test_warnings_fix_command_uses_corrected_wording():
    """CLI fix path gets the same corrected wording as lint."""
    msgs = schema_source_warnings("sql", command="fix")
    assert "--database-url" in msgs[0] or "$DATABASE_URL" in msgs[0]
    assert "snapshot" not in msgs[0].lower()


def test_warnings_none_command_legacy_text_unchanged():
    """command=None (MCP) keeps exact legacy text — pinned for backward compat."""
    msgs = schema_source_warnings("sql", command=None)
    # The legacy text references database_url (the internal arg name) and snapshot
    assert "database_url" in msgs[0]
    assert "snapshot" in msgs[0].lower()
