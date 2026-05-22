"""Unit tests for SEC024 — policy calls current_setting() with an
unqualified parameter name.

SEC024 (info) fires when a policy's USING / WITH CHECK expression
calls current_setting() with a string-literal parameter name that
contains no `.`. A customized run-time parameter must be qualified
(`app.tenant_id`), so an unqualified name is a dropped prefix or a
built-in server setting.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec024 import SEC024


def _policy(
    *,
    name: str = "p",
    using: str | None = None,
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command="ALL",
        permissive=True,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _schema(*policies: Policy, name: str = "docs") -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name=name,
                rls_enabled=True,
                force_rls=True,
                policies=policies,
                columns=("id", "tenant_id"),
            ),
        )
    )


# --- firing --------------------------------------------------------------


def test_sec024_fires_on_unqualified_name() -> None:
    schema = _schema(
        _policy(using="tenant_id = current_setting('tenant_id', true)")
    )
    [v] = SEC024().check(schema, options={})
    assert v.rule_id == "SEC024"
    assert v.severity == "info"
    assert v.location == "public.docs.p"
    assert "'tenant_id'" in v.message


def test_sec024_silent_on_qualified_name() -> None:
    schema = _schema(
        _policy(
            using="tenant_id = current_setting('app.tenant_id', true)"
        )
    )
    assert SEC024().check(schema, options={}) == []


def test_sec024_fires_on_cast_wrapped_literal() -> None:
    # Postgres deparses a string-literal argument with an explicit
    # cast — `current_setting('tenant'::text, true)` — which is the
    # form an introspected policy carries. The literal name must
    # still be read through the TypeCast wrapper.
    schema = _schema(
        _policy(using="tenant_id = current_setting('tenant'::text, true)")
    )
    assert len(SEC024().check(schema, options={})) == 1


def test_sec024_silent_on_cast_wrapped_qualified_literal() -> None:
    # The TypeCast unwrap must not change the verdict for a
    # qualified name — `app.tenant` still has a period.
    schema = _schema(
        _policy(
            using="tenant_id = current_setting('app.tenant'::text, true)"
        )
    )
    assert SEC024().check(schema, options={}) == []


def test_sec024_fires_on_one_argument_form() -> None:
    # The arity is SEC019's concern; SEC024 fires on the name shape
    # regardless of whether the missing_ok argument was passed.
    schema = _schema(
        _policy(using="tenant_id = current_setting('tenant')")
    )
    assert len(SEC024().check(schema, options={})) == 1


def test_sec024_fires_on_call_in_with_check() -> None:
    schema = _schema(
        _policy(
            using="tenant_id = 1",
            with_check="tenant_id = current_setting('tenant', true)",
        )
    )
    assert len(SEC024().check(schema, options={})) == 1


def test_sec024_fires_on_call_wrapped_in_subselect() -> None:
    schema = _schema(
        _policy(
            using="tenant_id = (SELECT current_setting('tenant', true))"
        )
    )
    assert len(SEC024().check(schema, options={})) == 1


def test_sec024_silent_when_no_current_setting() -> None:
    assert SEC024().check(
        _schema(_policy(using="tenant_id = 1")), options={}
    ) == []


def test_sec024_silent_on_empty_parameter_name() -> None:
    # current_setting('') is a malformed call — Postgres errors at
    # query time. That is a different class of bug from "dropped
    # prefix", so SEC024 stays silent rather than reporting an
    # `unqualified parameter name ''` finding.
    schema = _schema(_policy(using="tenant_id = current_setting('')"))
    assert SEC024().check(schema, options={}) == []


def test_sec024_silent_on_dynamic_parameter_name() -> None:
    # A name assembled from an expression rather than a string
    # literal — SEC024 cannot know what it resolves to, so it does
    # not fire (the first argument is an A_Expr, not an A_Const).
    schema = _schema(
        _policy(using="tenant_id = current_setting('ten' || 'ant')")
    )
    assert SEC024().check(schema, options={}) == []


def test_sec024_silent_on_non_string_literal_argument() -> None:
    # `current_setting(42)` — the first argument is an A_Const whose
    # `.val` is an Integer, not a String. SEC024 only inspects
    # string-literal names (a real parameter name is a string), so a
    # numeric literal is left alone rather than flagged. The call is
    # itself nonsensical (Postgres would error on it), but the rule
    # must not crash trying to read `.sval` off a non-String.
    schema = _schema(_policy(using="tenant_id = current_setting(42)"))
    assert SEC024().check(schema, options={}) == []


def test_sec024_silent_on_zero_argument_call() -> None:
    # `current_setting()` with no arguments at all — `find_func_calls`
    # still matches the name, but there is no first argument to read.
    # SEC024 skips it (the `args` list is empty) rather than indexing
    # into nothing.
    schema = _schema(_policy(using="tenant_id::text = current_setting()"))
    assert SEC024().check(schema, options={}) == []


# --- message / multiple --------------------------------------------------


def test_sec024_message_lists_multiple_unqualified_names_sorted() -> None:
    schema = _schema(
        _policy(
            using=(
                "tenant_id = current_setting('zeta', true) "
                "OR tenant_id = current_setting('alpha', true)"
            )
        )
    )
    [v] = SEC024().check(schema, options={})
    msg = v.message
    assert msg.index("'alpha'") < msg.index("'zeta'")
    assert "[lint.rules.SEC024]" in msg


def test_sec024_message_names_only_the_unqualified_call() -> None:
    # A policy mixing a qualified and an unqualified call fires,
    # and the message names only the offending unqualified one.
    # `app.region` is chosen because it appears nowhere in the
    # rule's message text — `app.tenant_id` does, as the example.
    schema = _schema(
        _policy(
            using=(
                "tenant_id = current_setting('app.region', true) "
                "OR tenant_id = current_setting('legacy', true)"
            )
        )
    )
    [v] = SEC024().check(schema, options={})
    assert "'legacy'" in v.message
    assert "'app.region'" not in v.message


def test_sec024_fires_once_per_policy() -> None:
    schema = _schema(
        _policy(name="a", using="tenant_id = current_setting('t', true)"),
        _policy(name="b", using="tenant_id = current_setting('t', true)"),
    )
    locations = {v.location for v in SEC024().check(schema, options={})}
    assert locations == {"public.docs.a", "public.docs.b"}


# --- allowlist -----------------------------------------------------------


def test_sec024_allowlist_skips_named_policy() -> None:
    def _tbl(table: str, policy_name: str) -> Table:
        return Table(
            schema="public",
            name=table,
            rls_enabled=True,
            force_rls=True,
            columns=("id", "tenant_id"),
            policies=(
                _policy(
                    name=policy_name,
                    using="tenant_id = current_setting('t', true)",
                ),
            ),
        )

    schema = Schema(tables=(_tbl("t1", "exempt"), _tbl("t2", "active")))
    violations = SEC024().check(
        schema, options={"allowlist": ["public.t1.exempt"]}
    )
    assert [v.location for v in violations] == ["public.t2.active"]


def test_sec024_allowlist_rejects_non_list() -> None:
    schema = _schema(
        _policy(using="tenant_id = current_setting('t', true)")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC024().check(schema, options={"allowlist": "public.docs.p"})


def test_sec024_allowlist_rejects_whitespace_padded_entry() -> None:
    schema = _schema(
        _policy(using="tenant_id = current_setting('t', true)")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC024().check(
            schema, options={"allowlist": [" public.docs.p "]}
        )
