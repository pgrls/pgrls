"""Unit tests for VIEW003 — materialized view over RLS-protected table."""
from __future__ import annotations

import pytest

from pgrls.model import Schema, Table, View
from pgrls.rules.view003 import VIEW003


def _table(
    schema: str,
    name: str,
    *,
    rls: bool,
    force: bool = True,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=(),
    )


def _view(
    schema: str = "public",
    name: str = "v",
    *,
    is_materialized: bool = True,
    security_invoker: bool = False,
    security_barrier: bool = False,
    references: tuple[tuple[str, str], ...] = (),
    security_definer_calls: tuple[str, ...] = (),
    definition: str = "SELECT 1",
) -> View:
    # Note: default `is_materialized=True` here so the positive
    # VIEW003 cases don't have to spell it out — the negative
    # "regular view" case overrides it explicitly.
    return View(
        schema=schema,
        name=name,
        is_materialized=is_materialized,
        security_invoker=security_invoker,
        security_barrier=security_barrier,
        definition=definition,
        references=references,
        security_definer_calls=security_definer_calls,
    )


def test_view003_fires_on_matview_over_rls_table() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_snapshot",
                references=(("public", "users"),),
            ),
        ),
    )
    violations = VIEW003().check(schema, options={})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "VIEW003"
    assert v.severity == "warning"
    assert v.location == "public.user_snapshot"
    assert "public.user_snapshot" in v.message
    assert "public.users" in v.message
    assert "REFRESH" in v.message


def test_view003_does_not_fire_on_matview_over_non_rls_table() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=False),),
        views=(
            _view(
                schema="public",
                name="user_snapshot",
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW003().check(schema, options={}) == []


def test_view003_does_not_fire_on_regular_view_over_rls_table() -> None:
    # Regular views (non-materialized) are VIEW001/VIEW002 territory —
    # VIEW003 must skip them.
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                is_materialized=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW003().check(schema, options={}) == []


def test_view003_allowlist_exempts_qualified_matview_name() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_snapshot",
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW003().check(
        schema, options={"allowlist": ["public.user_snapshot"]}
    ) == []


def test_view003_message_joins_multiple_leaked_refs_sorted() -> None:
    # Pin the comma-join shape so it doesn't quietly drift —
    # multiple leaked refs render as a sorted, comma-separated
    # list of qualified names.
    schema = Schema(
        tables=(
            _table("public", "users", rls=True),
            _table("public", "invoices", rls=True),
        ),
        views=(
            _view(
                schema="public",
                name="user_snapshot",
                references=(
                    ("public", "users"),
                    ("public", "invoices"),
                ),
            ),
        ),
    )
    violations = VIEW003().check(schema, options={})
    assert len(violations) == 1
    assert "public.invoices, public.users" in violations[0].message


def test_view003_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_snapshot",
                references=(("public", "users"),),
            ),
        ),
    )
    with pytest.raises(TypeError, match="allowlist"):
        VIEW003().check(
            schema, options={"allowlist": "public.user_snapshot"}  # type: ignore[arg-type]
        )


def test_view003_bare_name_allowlist_entry_raises_clearly() -> None:
    # Allowlist is qualified-only — a bare `user_snapshot` (no `.`)
    # is rejected with a TypeError that names the rule.
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_snapshot",
                references=(("public", "users"),),
            ),
        ),
    )
    with pytest.raises(TypeError, match="VIEW003"):
        VIEW003().check(
            schema, options={"allowlist": ["user_snapshot"]}
        )


def test_view003_fires_independently_per_offending_matview() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="bad_a",
                references=(("public", "users"),),
            ),
            _view(
                schema="public",
                name="bad_b",
                references=(("public", "users"),),
            ),
            # A regular view over the same RLS table — VIEW003
            # must skip it (that's VIEW001's domain).
            _view(
                schema="public",
                name="not_a_matview",
                is_materialized=False,
                references=(("public", "users"),),
            ),
        ),
    )
    locations = sorted(v.location for v in VIEW003().check(schema, {}))
    assert locations == ["public.bad_a", "public.bad_b"]


def test_view003_does_not_fire_on_matview_with_no_references() -> None:
    # A matview constructed without view→table dependencies (e.g. a
    # `SELECT 1` matview) has nothing to leak — no fire.
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="constant_matview",
                references=(),
            ),
        ),
    )
    assert VIEW003().check(schema, options={}) == []


def test_view003_leaked_list_only_contains_rls_protected_refs() -> None:
    # A matview that references both an RLS-protected table and an
    # unprotected one should mention only the RLS-protected one.
    schema = Schema(
        tables=(
            _table("public", "users", rls=True),
            _table("public", "audit_log", rls=False),
        ),
        views=(
            _view(
                schema="public",
                name="user_snapshot",
                references=(
                    ("public", "audit_log"),
                    ("public", "users"),
                ),
            ),
        ),
    )
    violations = VIEW003().check(schema, options={})
    assert len(violations) == 1
    msg = violations[0].message
    assert "public.users" in msg
    # Crucially, the unprotected table must NOT appear in the
    # leaked-references portion of the message.
    assert "public.audit_log" not in msg


def test_view003_does_not_fire_on_schema_with_no_views() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(),
    )
    assert VIEW003().check(schema, options={}) == []


def test_view003_does_not_fire_when_only_non_rls_refs_present() -> None:
    # A matview that references only unprotected tables — no RLS
    # leak surface, so VIEW003 stays silent.
    schema = Schema(
        tables=(
            _table("public", "audit_log", rls=False),
            _table("public", "metadata", rls=False),
        ),
        views=(
            _view(
                schema="public",
                name="audit_snapshot",
                references=(
                    ("public", "audit_log"),
                    ("public", "metadata"),
                ),
            ),
        ),
    )
    assert VIEW003().check(schema, options={}) == []
