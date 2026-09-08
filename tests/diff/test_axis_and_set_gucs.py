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


def test_anon_leak_is_total_asks_the_all_sessions_question() -> None:
    """`prove_anon_isolation` is the EXISTS question and returns the first
    leaking session's witness, so a `{}` witness cannot be read as "every
    session reads everything". `anon_leak_is_total` is the FORALL question the
    reachability and escalation cedes need."""
    from pgrls.diff._z3_compare import anon_leak_is_total, prove_anon_isolation

    # Total for the anon-key caller, admits nothing to a JWT-less one.
    anon_key = parse_expr("auth.role() = 'anon'")
    assert prove_anon_isolation(anon_key) == ("leak", {})
    assert anon_leak_is_total(anon_key) is False

    # Total in both sessions.
    assert anon_leak_is_total(parse_expr("true")) is True

    # Not a leak at all.
    assert anon_leak_is_total(parse_expr("tenant_id = auth.uid()")) is False


def test_maybe_set_carries_the_observed_value_and_avoids_nul() -> None:
    """The sentinel is a prefix so `--emit-repro` can offer the value the
    introspecting session saw, and it must stay storable in a `jsonb` column —
    Postgres rejects a literal NUL there, and snapshots do land in one."""
    from pgrls.model import MAYBE_SET, is_maybe_set, maybe_set_value

    assert "\x00" not in MAYBE_SET
    assert is_maybe_set(MAYBE_SET + "fromconn")
    assert maybe_set_value(MAYBE_SET + "fromconn") == "fromconn"
    assert not is_maybe_set("fromconn")
    assert not is_maybe_set(None)


# --- review pass 10: the cross-tenant prover minted EVERY auth call non-NULL,
# i.e. assumed a JWT is always present. Measured on PG16 with tenancy carried by
# `SET app.tenant` and no JWT: a tenant-b session read tenant a's row through
# `... OR auth.role() IS NULL`, while both --mode cross-tenant and --mode anon
# reported PROVEN — nothing caught it.


@pytest.mark.parametrize(
    "sql",
    [
        "tenant_id = current_setting('app.tenant_id', true) OR auth.role() IS NULL",
        "tenant_id = current_setting('app.tenant_id', true) "
        "OR current_setting('request.jwt.claim.role', true) IS NULL",
        "tenant_id = current_setting('app.tenant_id', true) "
        "AND auth.role() IS NOT NULL",
    ],
)
def test_cross_tenant_declines_when_an_offaxis_auth_value_is_null_tested(
    sql: str,
) -> None:
    assert prove_cross_tenant_isolation(parse_expr(sql))[0] == "unverified"


def test_cross_tenant_still_proves_when_the_axis_itself_is_null_tested() -> None:
    """The AXIS being non-NULL is the mode's own premise — a session
    authenticated as tenant A has an identity. Only a DIFFERENT auth call is an
    unfounded assumption."""
    sql = (
        "tenant_id = current_setting('app.tenant_id', true) "
        "AND current_setting('app.tenant_id', true) IS NOT NULL"
    )
    assert prove_cross_tenant_isolation(parse_expr(sql))[0] == "isolated"


# --- review pass 11: the round-10 recorder only fired on a BARE minted session
# symbol, so any wrapper that keeps `is_null` but replaces the value slipped past it.
# Measured on PG16: with tenancy in `SET app.tenant_id` and no JWT, a tenant-b session
# READ and UPDATE'd tenant a's row through
# `... OR (current_setting('request.jwt.claims', true)::jsonb IS NULL AND ...)`,
# while --mode anon, --mode cross-tenant and --mode write all reported PROVEN with
# --strict clean. An encoder sweep found 402 of 576 off-axis cells falsely PROVEN.

_AXIS = "tenant_id = current_setting('app.tenant_id', true)"


@pytest.mark.parametrize(
    "offaxis",
    [
        # a cast whose target has no Z3 sort -> the value went opaque, the
        # null-flag survived, and the symbol identity was lost
        "current_setting('request.jwt.claims', true)::jsonb IS NULL",
        "auth.jwt()::json IS NULL",
        "current_setting('request.jwt.claim.sub', true)::timestamptz IS NULL",
        "auth.uid()::date IS NULL",
        # COALESCE builds a fresh value whose null-flag is the AND of its args'
        "coalesce(auth.role(), current_setting('request.jwt.claim.role', true)) IS NULL",
        "coalesce(auth.uid()::text, 'x') IS NULL",
        # and the bare form round 10 already covered, as a guard against regression
        "auth.role() IS NULL",
    ],
)
def test_cross_tenant_declines_through_a_wrapped_offaxis_null_test(
    offaxis: str,
) -> None:
    assert prove_cross_tenant_isolation(parse_expr(f"{_AXIS} OR {offaxis}"))[0] == (
        "unverified"
    )


@pytest.mark.parametrize(
    "sql",
    [
        # the axis identity's own non-nullness IS the mode's premise
        _AXIS + " AND current_setting('app.tenant_id', true) IS NOT NULL",
        # a sort-changing cast mints the axis symbol; recording the OUTERMOST
        # minted term is what keeps this provable
        "tenant_id = current_setting('app.tenant_id', true)::bigint "
        "AND current_setting('app.tenant_id', true)::bigint IS NOT NULL",
        "user_id = auth.uid() AND auth.uid() IS NOT NULL",
        "user_id = auth.uid() OR auth.uid() IS NULL",
    ],
)
def test_cross_tenant_still_proves_on_axis_null_tests(sql: str) -> None:
    assert prove_cross_tenant_isolation(parse_expr(sql))[0] == "isolated"


# --- review pass 12: `_is_anon_null_leaf` pinned is_null=TRUE for ANY
# `current_setting(<name>, true)`. That is true only of a CUSTOM (dotted) placeholder
# GUC, which a stock server ships unset. A non-dotted name is a BUILT-IN GUC: always
# set, and mostly USERSET. Measured on PG16 with RLS active and FORCE on, a policy
# `... OR current_setting('role', true) <> 'anon'` let a live anon session read every
# row (the value is 'none' in a fresh session) while --mode anon --strict said PROVEN.


@pytest.mark.parametrize(
    "builtin", ["role", "search_path", "application_name", "TimeZone"]
)
def test_anon_does_not_assume_a_builtin_guc_is_null(builtin: str) -> None:
    sql = (
        "tenant_id = current_setting('app.tenant_id', true) "
        f"OR current_setting('{builtin}', true) <> 'anon'"
    )
    assert prove_anon_isolation(parse_expr(sql))[0] == "leak"


def test_anon_builtin_guc_is_null_disjunct_is_dead() -> None:
    """The mirror: a built-in is never NULL, so the disjunct cannot fire and the
    predicate really is isolated. The old model proved the opposite of both."""
    sql = (
        "tenant_id = current_setting('app.tenant_id', true) "
        "OR current_setting('role', true) IS NULL"
    )
    assert prove_anon_isolation(parse_expr(sql))[0] == "isolated"


def test_anon_still_treats_a_custom_guc_as_unset() -> None:
    sql = (
        "tenant_id = current_setting('app.tenant_id', true) "
        "OR current_setting('app.gate', true) IS NULL"
    )
    assert prove_anon_isolation(parse_expr(sql))[0] == "leak"
