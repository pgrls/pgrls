"""Unit tests for the shared offline schema-source helpers."""
from pgrls.model import SNAPSHOT_VERSION
from pgrls.schema_sources import (
    _CATALOG_DEPENDENT_RULES,
    inert_rule_ids,
    schema_source_warnings,
)

ALL_INERT = frozenset(_CATALOG_DEPENDENT_RULES)


def test_inert_rule_ids_sql_is_catalog_only_set():
    # A sql= schema carries no catalog field → every catalog rule is inert.
    assert inert_rule_ids("sql") == ALL_INERT


def test_inert_rule_ids_perf005_is_not_a_catalog_rule():
    # PERF005 reads the --perf runtime artifact, not a schema field, so it is
    # never treated as a coverage gap of the schema source (matches live).
    assert "PERF005" not in ALL_INERT
    assert "PERF005" not in inert_rule_ids("sql")


def test_inert_rule_ids_current_snapshot_skips_nothing():
    # A current snapshot meets every rule's field-version threshold → the full
    # rule set runs and an absence of findings is real coverage.
    assert inert_rule_ids("snapshot", snapshot_version=SNAPSHOT_VERSION) == frozenset()


def test_inert_rule_ids_snapshot_is_version_gated():
    # A v15 snapshot predates SEC042's fields (v16) and SEC047's (v20), so they
    # are inert — but runs the rules whose fields it does carry (e.g. SEC035 v13).
    inert = inert_rule_ids("snapshot", snapshot_version=15)
    assert "SEC042" in inert and "SEC047" in inert
    assert "SEC035" not in inert  # is_primary landed in v13


def test_sec052_is_gated_on_view_grants_v23():
    # SEC052's firing decision reads `View.grants` (v23). It must be inert on a
    # pre-v23 snapshot (and a view-less SQL source) so a stale-snapshot lint
    # doesn't silently false-clean an auth.users-exposing view past
    # --require-full-coverage.
    assert _CATALOG_DEPENDENT_RULES["SEC052"][1] == 23
    assert "SEC052" in inert_rule_ids("snapshot", snapshot_version=22)
    assert "SEC052" not in inert_rule_ids("snapshot", snapshot_version=23)
    assert "SEC052" in inert_rule_ids("sql")


def test_reachability_gated_rules_threshold_covers_column_grants():
    # SEC041/SEC043 reach `Table.column_grants` (snapshot v8) through the shared
    # `sec041._is_directly_reachable` gate, so a threshold below 8 would let a
    # v3-v7 snapshot run them against empty column_grants and silently miss a
    # column-grant-only partition/inheritance RLS bypass (a false-clean).
    for rule in ("SEC041", "SEC043"):
        assert _CATALOG_DEPENDENT_RULES[rule][1] >= 8, (
            f"{rule} reads column_grants (v8) via _is_directly_reachable; "
            "its inert threshold must be >= 8 or it false-cleans on v3-v7 "
            "snapshots."
        )
    assert "SEC041" in inert_rule_ids("snapshot", snapshot_version=7)
    assert "SEC041" not in inert_rule_ids("snapshot", snapshot_version=8)


def test_inert_rule_ids_unknown_snapshot_version_fails_closed():
    # An unknown version is conservative: every catalog rule is treated as inert.
    assert inert_rule_ids("snapshot", snapshot_version=None) == ALL_INERT


def test_inert_rule_ids_thresholds_are_reachable():
    # Every threshold must be serializable by the current snapshot format, else
    # that rule would be permanently inert on snapshots (a silent coverage gap).
    assert all(v <= SNAPSHOT_VERSION for _, v in _CATALOG_DEPENDENT_RULES.values())


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
    msgs = schema_source_warnings("snapshot", command="lint", snapshot_version=8)
    assert msgs and any("snapshot" in m.lower() for m in msgs)


def test_warnings_current_snapshot_reports_nothing_skipped():
    # A current snapshot leaves no rule inert, so no "Skipped" line is emitted.
    msgs = schema_source_warnings(
        "snapshot", command="lint", snapshot_version=SNAPSHOT_VERSION
    )
    assert msgs  # the point-in-time caveat still fires
    assert all("Skipped" not in m for m in msgs)


def test_warnings_old_snapshot_lists_skipped_rules():
    msgs = schema_source_warnings("snapshot", command="lint", snapshot_version=8)
    assert any("Skipped" in m and "SEC042" in m for m in msgs)


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
