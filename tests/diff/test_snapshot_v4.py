"""Unit tests for snapshot v4 round-trip and view metadata."""
from __future__ import annotations

import pytest

from pgrls.model import (
    SNAPSHOT_VERSION,
    Schema,
    SecdefFunction,
    View,
)


def test_snapshot_version_is_4() -> None:
    assert SNAPSHOT_VERSION == 4


def test_to_snapshot_emits_views_field() -> None:
    schema = Schema(
        tables=(),
        views=(
            View(
                schema="public",
                name="invoices_v",
                is_materialized=False,
                security_invoker=True,
                security_barrier=False,
                definition="SELECT * FROM public.invoices",
                references=(("public", "invoices"),),
                security_definer_calls=(),
            ),
        ),
    )
    snap = schema.to_snapshot()
    assert snap["version"] == 4
    assert "views" in snap
    assert snap["views"][0]["name"] == "invoices_v"
    assert snap["views"][0]["security_invoker"] is True
    assert snap["views"][0]["references"] == [["public", "invoices"]]


def test_from_snapshot_round_trips_v4_with_views() -> None:
    original = Schema(
        tables=(),
        views=(
            View(
                schema="public",
                name="orders_mv",
                is_materialized=True,
                security_invoker=False,
                security_barrier=True,
                definition="SELECT * FROM public.orders",
                references=(("public", "orders"),),
                security_definer_calls=("public.audit_lookup",),
            ),
        ),
    )
    loaded = Schema.from_snapshot(original.to_snapshot())
    assert loaded.views == original.views


def test_from_snapshot_v3_yields_empty_views() -> None:
    # v3 snapshots load fine but have no view data — `Schema.views`
    # is `()`. Confirms the v3 → v4 boundary is non-breaking on
    # the load side; the missing data is just absent.
    v3 = {
        "version": 3,
        "tables": [],
        "policies": [],
    }
    loaded = Schema.from_snapshot(v3)
    assert loaded.views == ()


def test_from_snapshot_rejects_v2_with_clear_message() -> None:
    # v2 was supported in v0.2.x; v0.3.0 drops it. Test pins
    # the rejection so a future "let's add v2 back for legacy
    # users" change makes the deliberate cut visible.
    v2 = {
        "version": 2,
        "tables": [],
    }
    with pytest.raises(Exception, match="version 2"):
        Schema.from_snapshot(v2)


def test_from_snapshot_rejects_unknown_version() -> None:
    with pytest.raises(Exception, match="version 999"):
        Schema.from_snapshot({"version": 999, "tables": []})


def test_to_snapshot_emits_security_definer_functions_field() -> None:
    schema = Schema(
        tables=(),
        views=(),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.read_secret",
                body="SELECT * FROM public.secret",
                language="sql",
            ),
        ),
    )
    snap = schema.to_snapshot()
    assert "security_definer_functions" in snap
    assert snap["security_definer_functions"] == [
        {
            "qualified_name": "public.read_secret",
            "body": "SELECT * FROM public.secret",
            "language": "sql",
        }
    ]


def test_from_snapshot_round_trips_v4_with_security_definer_functions() -> None:
    original = Schema(
        tables=(),
        views=(),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.read_secret",
                body="SELECT * FROM public.secret",
                language="sql",
            ),
            SecdefFunction(
                qualified_name="public.audit_lookup",
                body="DECLARE r RECORD; BEGIN ... END;",
                language="plpgsql",
            ),
        ),
    )
    loaded = Schema.from_snapshot(original.to_snapshot())
    assert loaded.security_definer_functions == original.security_definer_functions


def test_from_snapshot_v4_without_security_definer_functions_loads_clean() -> None:
    # An older v4 snapshot written before the additive
    # `security_definer_functions` extension shipped — the field is
    # absent from the JSON. Loading must succeed and yield `()`.
    legacy_v4 = {
        "version": 4,
        "tables": [],
        "policies": [],
        "views": [],
    }
    loaded = Schema.from_snapshot(legacy_v4)
    assert loaded.security_definer_functions == ()


def test_from_snapshot_v3_yields_empty_security_definer_functions() -> None:
    # v3 has no `security_definer_functions`; load must succeed and
    # the field defaults to an empty tuple.
    v3 = {
        "version": 3,
        "tables": [],
        "policies": [],
    }
    loaded = Schema.from_snapshot(v3)
    assert loaded.security_definer_functions == ()
