"""Unit tests for SEC046 — a policy calls an IMMUTABLE function that reads
session/identity state (constant-folded → cross-user wrong-row leak).

SEC046 (error) fires when a table policy's USING / WITH CHECK calls a
**user-defined** function declared ``IMMUTABLE`` (``Schema.immutable_functions``)
whose body reads session/identity state (``current_setting`` / ``auth.*`` /
``current_user`` / ``session_user``) or a table. Because IMMUTABLE lets Postgres
constant-fold the call into a reused/cached plan, the value frozen for one
caller is served to the next.

The FP boundary (all live-validated against Postgres 16 before this rule
shipped): an inline ``current_setting`` used directly in a policy is SAFE (a
STABLE built-in that does not fold) — only user-defined IMMUTABLE *wrappers* are
flagged; a pure IMMUTABLE function (no session/table read) is legitimate; and a
STABLE / VOLATILE function is never captured here at all (only ``provolatile='i'``
reaches the rule). The rule abstains (fail-closed) on an unparseable / empty /
non-SQL body and on a pre-v19 snapshot with no captured IMMUTABLE functions.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import (
    ImmutableFunction,
    Policy,
    Schema,
    Table,
)
from pgrls.rules.sec046 import SEC046

# --- body fixtures: the volatility-vs-body matrix the rule keys on ----------

# A user-defined IMMUTABLE function whose body reads the per-request GUC — the
# dangerous case (proven live to serve the wrong user's rows under plan reuse).
_DANGER = ImmutableFunction(
    qualified_name="app.cur_tenant",
    body="SELECT current_setting('app.tenant', true)",
    language="sql",
)
# Reads auth.uid() — the Supabase request context.
_DANGER_AUTH = ImmutableFunction(
    qualified_name="app.uid_wrapper",
    body="SELECT (auth.jwt() ->> 'sub')",
    language="sql",
)
# Reads current_user (a SQLValueFunction node).
_DANGER_CURUSER = ImmutableFunction(
    qualified_name="app.who",
    body="SELECT current_user::text",
    language="sql",
)
# Reads a table — likewise non-immutable in truth.
_DANGER_TABLE = ImmutableFunction(
    qualified_name="app.lookup",
    body="SELECT t.tenant FROM tenants t WHERE t.uid = 1",
    language="sql",
)
# A genuinely pure IMMUTABLE function — deterministic on args, no session/table
# read. Legitimate; must NOT fire.
_PURE = ImmutableFunction(
    qualified_name="app.is_even",
    body="SELECT $1 % 2 = 0",
    language="sql",
)
# A PL/pgSQL body that DOES read a GUC but is not pglast-parseable → abstain.
_PLPGSQL = ImmutableFunction(
    qualified_name="app.plfn",
    body="BEGIN RETURN current_setting('app.tenant'); END",
    language="plpgsql",
)
# An empty body → abstain.
_EMPTY = ImmutableFunction(
    qualified_name="app.emptyfn", body="", language="sql"
)


def _policy(
    *,
    name: str = "p",
    using: str | None = None,
    with_check: str | None = None,
    command: str = "ALL",
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("app_user",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _schema(
    *policies: Policy,
    immutable_functions: tuple[ImmutableFunction, ...] = (),
    table: str = "docs",
) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name=table,
                rls_enabled=True,
                force_rls=True,
                policies=policies,
                columns=("id", "tenant"),
            ),
        ),
        immutable_functions=immutable_functions,
    )


# --- positives -------------------------------------------------------------


def test_immutable_session_wrapper_qualified_call_fires() -> None:
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.cur_tenant()"),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    assert len(out) == 1
    assert out[0].rule_id == "SEC046"
    assert out[0].severity == "error"
    assert out[0].location == "public.docs.p"
    assert "app.cur_tenant" in out[0].message
    assert "STABLE" in out[0].message


def test_immutable_session_wrapper_bare_call_fires() -> None:
    # `pg_get_expr` may render the call without a schema prefix; the rule
    # resolves a bare name to its captured qualified function.
    out = SEC046().check(
        _schema(
            _policy(using="tenant = cur_tenant()"),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    assert [v.location for v in out] == ["public.docs.p"]


def test_immutable_auth_wrapper_fires() -> None:
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.uid_wrapper()"),
            immutable_functions=(_DANGER_AUTH,),
        ),
        options={},
    )
    assert len(out) == 1


def test_immutable_current_user_wrapper_fires() -> None:
    out = SEC046().check(
        _schema(
            _policy(using="owner = app.who()"),
            immutable_functions=(_DANGER_CURUSER,),
        ),
        options={},
    )
    assert len(out) == 1


def test_immutable_table_reading_wrapper_fires() -> None:
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.lookup()"),
            immutable_functions=(_DANGER_TABLE,),
        ),
        options={},
    )
    assert len(out) == 1


def test_with_check_call_fires() -> None:
    # WITH CHECK governs writes and is also walked.
    out = SEC046().check(
        _schema(
            _policy(
                command="INSERT",
                with_check="tenant = app.cur_tenant()",
            ),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    assert [v.location for v in out] == ["public.docs.p"]


def test_call_in_both_clauses_fires_once() -> None:
    # A policy that calls the wrapper in USING and WITH CHECK reports once.
    out = SEC046().check(
        _schema(
            _policy(
                command="ALL",
                using="tenant = app.cur_tenant()",
                with_check="tenant = app.cur_tenant()",
            ),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    assert len(out) == 1


def test_message_names_policy_table_and_remedy() -> None:
    out = SEC046().check(
        _schema(
            _policy(name="tenant_iso", using="tenant = app.cur_tenant()"),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    msg = out[0].message
    assert "tenant_iso" in msg
    assert "public.docs" in msg
    assert "ALTER FUNCTION app.cur_tenant(...) STABLE" in msg


# --- negatives / FP boundary ----------------------------------------------


def test_inline_current_setting_does_not_fire() -> None:
    # Inline current_setting is a STABLE built-in (does NOT fold) and is not a
    # captured user function — the rule must NOT flag it (the key FP boundary).
    out = SEC046().check(
        _schema(
            _policy(using="tenant = current_setting('app.tenant', true)"),
            immutable_functions=(),
        ),
        options={},
    )
    assert out == []


def test_inline_current_setting_with_unrelated_immutable_present() -> None:
    # Even when an (unrelated, pure) IMMUTABLE function is captured, an inline
    # current_setting policy that calls no wrapper does not fire.
    out = SEC046().check(
        _schema(
            _policy(using="tenant = current_setting('app.tenant', true)"),
            immutable_functions=(_PURE,),
        ),
        options={},
    )
    assert out == []


def test_pure_immutable_function_does_not_fire() -> None:
    # A pure IMMUTABLE function (no session/table read) is legitimate.
    out = SEC046().check(
        _schema(
            _policy(using="app.is_even(id)"),
            immutable_functions=(_PURE,),
        ),
        options={},
    )
    assert out == []


def test_plpgsql_body_abstains() -> None:
    # A PL/pgSQL body is not pglast-parseable as a statement → abstain
    # (fail-closed) even though the body textually reads a GUC.
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.plfn()"),
            immutable_functions=(_PLPGSQL,),
        ),
        options={},
    )
    assert out == []


def test_empty_body_abstains() -> None:
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.emptyfn()"),
            immutable_functions=(_EMPTY,),
        ),
        options={},
    )
    assert out == []


def test_dangerous_function_not_called_does_not_fire() -> None:
    # The dangerous IMMUTABLE wrapper exists but no policy calls it.
    out = SEC046().check(
        _schema(
            _policy(using="tenant = 'x'"),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    assert out == []


def test_pre_v19_snapshot_abstains() -> None:
    # No captured immutable_functions (a pre-v19 snapshot) → nothing to match.
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.cur_tenant()"),
            immutable_functions=(),
        ),
        options={},
    )
    assert out == []


def test_policy_without_ast_abstains() -> None:
    # A policy with no parsed AST (e.g. loaded from snapshot) is skipped.
    pol = Policy(
        name="p",
        command="ALL",
        permissive=True,
        roles=("app_user",),
        using_sql="tenant = app.cur_tenant()",
        with_check_sql=None,
        using_ast=None,
        with_check_ast=None,
    )
    out = SEC046().check(
        _schema(pol, immutable_functions=(_DANGER,)), options={}
    )
    assert out == []


# --- false-positive regressions (adversarial review) -----------------------


def test_pure_cte_bodied_immutable_does_not_fire() -> None:
    # A CTE name referenced in FROM parses as an unqualified RangeVar, but
    # reading a same-body CTE is NOT a table read. A genuinely pure IMMUTABLE
    # function whose body only reads its own CTE must NOT fire (review MED-1).
    pure_cte = ImmutableFunction(
        qualified_name="app.cte_pure",
        body=(
            "WITH t AS (SELECT generate_series(1, n) AS x) SELECT count(*) FROM t"
        ),
        language="sql",
    )
    out = SEC046().check(
        _schema(
            _policy(using="id <= app.cte_pure(10)"),
            immutable_functions=(pure_cte,),
        ),
        options={},
    )
    assert out == []


def test_qualified_call_to_pure_function_does_not_misattribute() -> None:
    # A dangerous `app.foo` and a pure `other.foo` share a bare name. A policy
    # call QUALIFIED to the pure `other.foo` must NOT fire — the bare-name
    # fallback applies only to genuinely unqualified calls (review MED-2).
    danger = ImmutableFunction(
        qualified_name="app.foo",
        body="SELECT current_setting('app.tenant', true)",
        language="sql",
    )
    pure = ImmutableFunction(
        qualified_name="other.foo", body="SELECT 'static'", language="sql"
    )
    out = SEC046().check(
        _schema(
            _policy(using="tenant = other.foo()"),
            immutable_functions=(danger, pure),
        ),
        options={},
    )
    assert out == []


def test_unqualified_call_still_resolves_via_bare_name() -> None:
    # Control: a genuinely UNqualified call must still resolve to the dangerous
    # function via the bare-name fallback (the MED-2 fix must not break this).
    out = SEC046().check(
        _schema(
            _policy(using="tenant = cur_tenant()"),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    assert len(out) == 1
    assert out[0].rule_id == "SEC046"


# --- allowlist -------------------------------------------------------------


def test_allowlist_suppresses_by_qualified_name() -> None:
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.cur_tenant()"),
            immutable_functions=(_DANGER,),
        ),
        options={"allowlist": ["app.cur_tenant"]},
    )
    assert out == []


def test_allowlist_other_function_does_not_suppress() -> None:
    out = SEC046().check(
        _schema(
            _policy(using="tenant = app.cur_tenant()"),
            immutable_functions=(_DANGER,),
        ),
        options={"allowlist": ["app.other"]},
    )
    assert len(out) == 1


def test_allowlist_bare_name_rejected() -> None:
    # The allowlist requires schema.function (mirrors SEC014/SEC017).
    with pytest.raises(TypeError):
        SEC046().check(
            _schema(
                _policy(using="tenant = app.cur_tenant()"),
                immutable_functions=(_DANGER,),
            ),
            options={"allowlist": ["cur_tenant"]},
        )


# --- multiple findings -----------------------------------------------------


def test_two_policies_each_call_dangerous_each_fire() -> None:
    out = SEC046().check(
        _schema(
            _policy(name="a", using="tenant = app.cur_tenant()"),
            _policy(name="b", using="tenant = app.cur_tenant()"),
            immutable_functions=(_DANGER,),
        ),
        options={},
    )
    assert sorted(v.location for v in out) == [
        "public.docs.a",
        "public.docs.b",
    ]


# --- model round-trip (snapshot v19) --------------------------------------


def test_immutable_functions_snapshot_round_trip() -> None:
    schema = Schema(
        immutable_functions=(
            ImmutableFunction(
                qualified_name="app.cur_tenant",
                body="SELECT current_setting('app.tenant', true)",
                language="sql",
            ),
            ImmutableFunction(
                qualified_name="app.is_even",
                body="SELECT $1 % 2 = 0",
                language="sql",
            ),
        )
    )
    snap = schema.to_snapshot()
    assert snap["version"] == 26
    assert snap["immutable_functions"] == [
        {
            "qualified_name": "app.cur_tenant",
            "body": "SELECT current_setting('app.tenant', true)",
            "language": "sql",
        },
        {
            "qualified_name": "app.is_even",
            "body": "SELECT $1 % 2 = 0",
            "language": "sql",
        },
    ]
    back = Schema.from_snapshot(snap)
    assert back.immutable_functions == schema.immutable_functions


def test_pre_v19_snapshot_loads_with_empty_immutable_functions() -> None:
    # A v18 snapshot has no immutable_functions key → loads as () so SEC046
    # finds nothing (fail-closed) until re-captured.
    schema = Schema(
        immutable_functions=(
            ImmutableFunction(
                qualified_name="app.cur_tenant",
                body="SELECT current_setting('app.tenant', true)",
                language="sql",
            ),
        )
    )
    snap = schema.to_snapshot()
    snap["version"] = 18
    del snap["immutable_functions"]
    back = Schema.from_snapshot(snap)
    assert back.immutable_functions == ()
