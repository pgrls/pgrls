"""Use case 33: Classic INHERITS (non-declarative) — partition_of."""
from __future__ import annotations


def test_uc33_classic_inherits_does_not_set_partition_of(
    lint_output: str,
) -> None:
    # Pre-declarative INHERITS still goes through pg_inherits,
    # but `relispartition` is false on classic-inherits
    # children. The introspector filters on relispartition, so
    # neither parent nor child gets a `partition_of`. SEC001
    # fires on both with the standalone classic message —
    # NOT the "is a partition of" variant.
    assert "SEC001  app.legacy_parent\n" in lint_output
    assert "SEC001  app.legacy_child\n" in lint_output
    # The child's message must NOT name the parent (which
    # would be the visible-root variant from uc15 — wrong here).
    legacy_child_section = lint_output.split(
        "SEC001  app.legacy_child"
    )[1].split("\n\n")[0]
    assert (
        "is a partition of app.legacy_parent" not in legacy_child_section
    )


