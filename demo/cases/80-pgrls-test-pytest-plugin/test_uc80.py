"""Use case 80: pgrls.testing pytest plugin — end-to-end smoke."""
from __future__ import annotations

import pytest

from pgrls.testing import PgrlsTestClient


@pytest.fixture
def demo_pgrls_db(demo_db: str):
    # The demo conftest exposes `demo_db` as the connection
    # string. Wrap it with PgrlsTestClient + per-test transaction
    # the same way the pytest plugin does — without depending on
    # the user's conftest having a `pgrls_db` fixture set up.
    with PgrlsTestClient.connect(demo_db) as client:
        with client.transaction():
            yield client


def test_uc80_pgrls_testing_smoke(
    demo_pgrls_db: PgrlsTestClient,
) -> None:
    # Seed in admin context, then verify the seed inserted both rows.
    # Role switching against the demo's connecting user (which has
    # bypass) won't exercise RLS filtering — the protocol fixture
    # at tests/protocol/ is the authoritative end-to-end check.
    # This case is here to verify the pytest-plugin wiring works
    # against the demo's connection.
    demo_pgrls_db.seed(
        "app.demo_invoices",
        [
            {"tenant_id": "tenant-a", "amount": 100},
            {"tenant_id": "tenant-b", "amount": 200},
        ],
    )
    rows = demo_pgrls_db.fetchall(
        "SELECT count(*) AS n FROM app.demo_invoices"
    )
    assert rows[0]["n"] == 2
