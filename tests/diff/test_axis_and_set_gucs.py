"""Two vacuous-proof shapes the cross-tenant / anon provers used to accept."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.diff._z3_compare import (
    Z3_AVAILABLE,
    prove_anon_isolation,
    prove_cross_tenant_isolation,
)

pytestmark = pytest.mark.skipif(not Z3_AVAILABLE, reason="z3 not installed")


@pytest.mark.parametrize(
    "sql",
    [
        "status = current_setting('app.status', true)",
        "region = (SELECT current_setting('app.region', true))",
        "is_public = current_setting('app.show_public', true)::bool",
    ],
)
def test_cross_tenant_refuses_a_non_identity_axis(sql: str) -> None:
    """`status != session.status` is UNSAT, but that proves nothing about
    tenants — the policy has no tenant scoping at all. Honest answer:
    unverified, not PROVEN."""
    assert prove_cross_tenant_isolation(parse_expr(sql))[0] == "unverified"


@pytest.mark.parametrize(
    "sql",
    [
        "tenant_id = current_setting('app.tenant_id', true)",
        "org_id = (SELECT current_setting('app.org_id', true))::uuid",
        "user_id = (SELECT auth.uid())",
    ],
)
def test_cross_tenant_still_proves_on_an_identity_axis(sql: str) -> None:
    assert prove_cross_tenant_isolation(parse_expr(sql))[0] == "isolated"


def test_cross_tenant_identity_columns_override() -> None:
    sql = "region = current_setting('app.region', true)"
    assert prove_cross_tenant_isolation(parse_expr(sql))[0] == "unverified"
    assert (
        prove_cross_tenant_isolation(
            parse_expr(sql), identity_columns=frozenset({"region"})
        )[0]
        == "isolated"
    )


def test_anon_db_level_guc_defeats_the_unset_assumption() -> None:
    """`ALTER DATABASE … SET app.tenant_id = 'shared'` makes the read succeed
    for a fresh anon session (measured live: 1 row). With the name captured
    in `set_gucs` the prover must not claim PROVEN."""
    sql = "tenant_id = current_setting('app.tenant_id')"
    assert prove_anon_isolation(parse_expr(sql))[0] == "isolated"
    assert (
        prove_anon_isolation(parse_expr(sql), set_gucs=frozenset({"app.tenant_id"}))[0]
        != "isolated"
    )
