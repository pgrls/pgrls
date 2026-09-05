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
    verdict, witness = prove_anon_isolation(
        parse_expr(sql), set_gucs={"app.tenant_id": "shared"}
    )
    assert verdict == "leak"
    # The configured value is carried through, so the counterexample is a real
    # row rather than "a conditional leak" — that is what --emit-repro seeds
    # and what --probe replays.
    assert witness == {"tenant_id": "shared"}


def test_anon_guc_value_that_cannot_satisfy_the_policy_stays_isolated() -> None:
    """A set GUC is not automatically a leak: `ALTER DATABASE … SET app.flag =
    'off'` against `current_setting('app.flag') = 'on'` admits nothing
    (measured live: 0 rows). Treating any set GUC as an opaque non-null value
    reported a LEAK here."""
    sql = "current_setting('app.flag', true) = 'on'"
    assert prove_anon_isolation(parse_expr(sql), set_gucs={"app.flag": "off"})[0] == "isolated"
    assert prove_anon_isolation(parse_expr(sql), set_gucs={"app.flag": "on"})[0] == "leak"


def test_anon_guc_set_with_an_uncaptured_value_stays_opaque() -> None:
    """A `None` value means "set, but the value was not captured" (a
    non-superuser introspection cannot read pg_file_settings). The prover must
    not prove isolation from a value it does not have — it declines instead."""
    sql = "tenant_id = current_setting('app.tenant_id')"
    verdict, witness = prove_anon_isolation(parse_expr(sql), set_gucs={"app.tenant_id": None})
    assert verdict == "leak"
    assert witness is None  # no value to pin the row with


def test_anon_guc_states_are_checked_per_login_path() -> None:
    """Role-level settings bind to the LOGIN role, so an anonymous session has
    one GUC state per login path (a direct `anon` login, or `authenticator`
    then `SET ROLE anon`). A leak in ANY state is a leak — both paths are real
    sessions."""
    sql = "tenant_id = current_setting('app.tenant_id')"
    assert prove_anon_isolation(parse_expr(sql), set_gucs=[{}, {}])[0] == "isolated"
    assert (
        prove_anon_isolation(parse_expr(sql), set_gucs=[{}, {"app.tenant_id": "shared"}])[0]
        == "leak"
    )


def test_cast_fold_refuses_values_postgres_would_reject() -> None:
    """The fold must not invent a row Postgres cannot hold. `'999…'::int`
    RAISES, so a witness naming it is a leak the tool cannot exhibit — and the
    emitted reproduction's INSERT failed with "integer out of range".
    `Infinity` / `NaN` are valid PG floats that z3.RealVal cannot parse; the
    resulting Z3Exception crashed the whole command."""
    from pgrls.diff._z3_compare import prove_anon_isolation

    in_range = prove_anon_isolation(
        parse_expr("id = current_setting('app.n')::int"), set_gucs={"app.n": "1"}
    )
    assert in_range == ("leak", {"id": 1})
    for value, sql in [
        ("99999999999999999999", "id = current_setting('app.n')::int"),
        ("40000", "id = current_setting('app.n')::smallint"),
    ]:
        verdict, witness = prove_anon_isolation(parse_expr(sql), set_gucs={"app.n": value})
        assert (verdict, witness) == ("leak", None), (sql, value)
    # No crash, and no fabricated constant.
    assert prove_anon_isolation(parse_expr("score < 'Infinity'::float8"))[0] == "leak"
    assert prove_anon_isolation(
        parse_expr("score > current_setting('app.t')::numeric"), set_gucs={"app.t": "NaN"}
    )[0] == "leak"


def test_a_guc_we_cannot_attribute_to_the_server_stays_undecided() -> None:
    """A GUC the introspecting session can read may be its own connection's
    option (`PGOPTIONS`), which an anonymous caller would not have. Recording
    it as definitely set proved `current_setting(x, true) IS NULL` dead — the
    SEC004 inverted-gate shape — and flipped a real LEAK to PROVEN."""
    from pgrls.diff._z3_compare import prove_anon_isolation
    from pgrls.model import MAYBE_SET

    gate = parse_expr("current_setting('app.gate', true) IS NULL")
    assert prove_anon_isolation(gate)[0] == "leak"                       # unset
    assert prove_anon_isolation(gate, set_gucs={"app.gate": "v"})[0] == "isolated"
    assert prove_anon_isolation(gate, set_gucs={"app.gate": MAYBE_SET})[0] == "leak"
    # The safe direction is preserved for the scoping shape too.
    scoped = parse_expr("tenant = current_setting('app.t')")
    assert prove_anon_isolation(scoped)[0] == "isolated"
    assert prove_anon_isolation(scoped, set_gucs={"app.t": MAYBE_SET})[0] == "leak"
