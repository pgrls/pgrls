"""Unit tests for VIEW002 — non-`security_barrier` view over RLS-protected table."""
from __future__ import annotations

import pytest

from pgrls.model import Schema, Table, View
from pgrls.rules.view001 import VIEW001
from pgrls.rules.view002 import VIEW002


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
    is_materialized: bool = False,
    security_invoker: bool = True,
    security_barrier: bool = False,
    references: tuple[tuple[str, str], ...] = (),
    security_definer_calls: tuple[str, ...] = (),
    definition: str = "SELECT 1",
) -> View:
    # Note: default `security_invoker=True` here so VIEW002 tests
    # don't accidentally also exercise VIEW001 — the rules are
    # orthogonal and we want each test to pin one axis.
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


def test_view002_fires_on_non_barrier_view_over_rls_table() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    violations = VIEW002().check(schema, options={})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "VIEW002"
    assert v.severity == "warning"
    assert v.location == "public.user_summary"
    assert "public.user_summary" in v.message
    assert "public.users" in v.message
    assert "security_barrier" in v.message


def test_view002_does_not_fire_when_security_barrier_true() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                security_barrier=True,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002().check(schema, options={}) == []


def test_view002_does_not_fire_on_view_over_non_rls_table() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=False),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002().check(schema, options={}) == []


def test_view002_does_not_fire_on_materialized_view() -> None:
    # Matviews are VIEW003's domain — VIEW002 must skip them.
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                is_materialized=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002().check(schema, options={}) == []


def test_view002_allowlist_exempts_qualified_view_name() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002().check(
        schema, options={"allowlist": ["public.user_summary"]}
    ) == []


def test_view002_does_not_fire_on_view_with_no_references() -> None:
    # A view constructed without view→table dependencies has nothing
    # to leak — no fire.
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="constant_view",
                security_barrier=False,
                references=(),
            ),
        ),
    )
    assert VIEW002().check(schema, options={}) == []


def test_view002_leaked_list_only_contains_rls_protected_refs() -> None:
    # A view that references both an RLS-protected table and an
    # unprotected one should mention only the RLS-protected one.
    schema = Schema(
        tables=(
            _table("public", "users", rls=True),
            _table("public", "audit_log", rls=False),
        ),
        views=(
            _view(
                schema="public",
                name="user_summary",
                security_barrier=False,
                references=(
                    ("public", "audit_log"),
                    ("public", "users"),
                ),
            ),
        ),
    )
    violations = VIEW002().check(schema, options={})
    assert len(violations) == 1
    msg = violations[0].message
    assert "public.users" in msg
    # Crucially, the unprotected table must NOT appear in the
    # leaked-references portion of the message.
    assert "public.audit_log" not in msg


def test_view002_message_joins_multiple_leaked_refs_sorted() -> None:
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
                name="user_summary",
                security_barrier=False,
                references=(
                    ("public", "users"),
                    ("public", "invoices"),
                ),
            ),
        ),
    )
    violations = VIEW002().check(schema, options={})
    assert len(violations) == 1
    assert "public.invoices, public.users" in violations[0].message


def test_view002_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    with pytest.raises(TypeError, match="allowlist"):
        VIEW002().check(
            schema, options={"allowlist": "public.user_summary"}  # type: ignore[arg-type]
        )


def test_view002_bare_name_allowlist_entry_raises_clearly() -> None:
    # Allowlist is qualified-only — a bare `user_summary` (no `.`)
    # is rejected with a TypeError that names the rule.
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="user_summary",
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    with pytest.raises(TypeError, match="VIEW002"):
        VIEW002().check(
            schema, options={"allowlist": ["user_summary"]}
        )


def test_view002_does_not_fire_on_schema_with_no_views() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(),
    )
    assert VIEW002().check(schema, options={}) == []


def test_view002_fires_independently_per_offending_view() -> None:
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            _view(
                schema="public",
                name="bad_a",
                security_barrier=False,
                references=(("public", "users"),),
            ),
            _view(
                schema="public",
                name="bad_b",
                security_barrier=False,
                references=(("public", "users"),),
            ),
            _view(
                schema="public",
                name="good",
                security_barrier=True,
                references=(("public", "users"),),
            ),
        ),
    )
    locations = sorted(v.location for v in VIEW002().check(schema, {}))
    assert locations == ["public.bad_a", "public.bad_b"]


# ---------- Independence: VIEW001 and VIEW002 fire on the same view ----------


def test_view001_and_view002_fire_independently_on_same_view() -> None:
    # A view that's BOTH non-invoker AND non-barrier over an RLS
    # table should trigger BOTH rules — the two flags defend against
    # different leak vectors and a future refactor that consolidates
    # them must not silently collapse one into the other.
    schema = Schema(
        tables=(_table("public", "users", rls=True),),
        views=(
            View(
                schema="public",
                name="bad_view",
                is_materialized=False,
                security_invoker=False,
                security_barrier=False,
                definition="SELECT * FROM public.users",
                references=(("public", "users"),),
                security_definer_calls=(),
            ),
        ),
    )

    view001_violations = VIEW001().check(schema, options={})
    view002_violations = VIEW002().check(schema, options={})

    assert len(view001_violations) == 1
    assert len(view002_violations) == 1
    assert view001_violations[0].rule_id == "VIEW001"
    assert view002_violations[0].rule_id == "VIEW002"
    # Both fire on the SAME view location — confirming they're
    # independent axes, not mutually exclusive.
    assert view001_violations[0].location == view002_violations[0].location
    # And the two violations carry distinct rule IDs.
    assert (
        view001_violations[0].rule_id != view002_violations[0].rule_id
    )
