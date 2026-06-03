"""Unit tests for SEC021 — identity column compared to a hardcoded literal.

SEC021 (info) fires when a policy's USING / WITH CHECK expression
has an `=` comparison between an identity-named column (`tenant_id`,
`org_id`, …) and a literal constant — `tenant_id = 1` — the
scaffolding-value anti-pattern. It deliberately stays silent on a
legitimate `column = literal` policy whose column is NOT
identity-named (`is_public = true`, `status = 'published'`) and on
an identity column keyed off session context
(`tenant_id = current_setting('app.tenant')`).
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec021 import SEC021


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _wrap(policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=(
                    "id",
                    "tenant_id",
                    "org_id",
                    "owner_id",
                    "is_public",
                    "status",
                ),
            ),
        )
    )


# --- fires: identity column compared to a literal ------------------------


def test_sec021_fires_on_tenant_id_eq_integer() -> None:
    schema = _wrap(_policy("tenant_id = 1"))
    [v] = SEC021().check(schema, {})
    assert v.rule_id == "SEC021"
    assert v.severity == "info"
    assert v.location == "public.t.p"
    assert "identity column" in v.message
    assert "[lint.rules.SEC021]" in v.message


def test_sec021_fires_on_org_id_eq_string() -> None:
    assert len(SEC021().check(_wrap(_policy("org_id = 'acme'")), {})) == 1


def test_sec021_fires_with_literal_on_the_left() -> None:
    # The comparison is symmetric — literal on either operand.
    assert len(SEC021().check(_wrap(_policy("1 = tenant_id")), {})) == 1


def test_sec021_fires_on_typecast_wrapped_literal() -> None:
    # A literal of a non-default type is spelled `'…'::type`; the
    # operand is a TypeCast wrapping the A_Const.
    schema = _wrap(_policy("owner_id = 'acme'::text"))
    assert len(SEC021().check(schema, {})) == 1


def test_sec021_fires_on_typecast_wrapped_identity_column() -> None:
    # A cast of the identity column is still the DIRECT operand —
    # `tenant_id::text = 'acme'` pins to one tenant and must fire.
    schema = _wrap(_policy("tenant_id::text = 'acme'"))
    assert len(SEC021().check(schema, {})) == 1


def test_sec021_silent_on_derived_expression_of_identity_column() -> None:
    # R11 #7: the identity column must be the DIRECT operand. A derived
    # expression (substring / arithmetic / concat) of the column does
    # NOT pin the policy to a single tenant, so it must not fire against
    # the documented `tenant_id = 1` shape.
    for using in (
        "substring(tenant_id::text, 1, 2) = 'ab'",
        "tenant_id + 1 = 5",
        "tenant_id || 'x' = 'foo'",
    ):
        assert SEC021().check(_wrap(_policy(using)), {}) == [], using


def test_sec021_fires_when_only_in_with_check() -> None:
    p = _policy(with_check="tenant_id = 1", command="INSERT")
    assert len(SEC021().check(_wrap(p), {})) == 1


def test_sec021_fires_when_a_conjunct_of_a_larger_predicate() -> None:
    # `tenant_id = 1` buried in an AND still fires — the literal
    # comparison is the smell wherever it sits.
    schema = _wrap(_policy("id > 0 AND tenant_id = 1"))
    assert len(SEC021().check(schema, {})) == 1


def test_sec021_fires_on_hardcoded_literal_inside_subquery() -> None:
    # A hardcoded identity comparison inside a sub-select membership
    # check is still surfaced — the walk recurses into sub-selects.
    schema = _wrap(
        _policy("id IN (SELECT doc_id FROM acl WHERE acl.tenant_id = 5)")
    )
    assert len(SEC021().check(schema, {})) == 1


def test_sec021_fires_on_each_offending_policy_independently() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "tenant_id"),
                policies=(
                    _policy("tenant_id = 1", name="bad_a"),
                    _policy("id > 0", name="ok"),
                    _policy("tenant_id = 2", name="bad_b"),
                ),
            ),
        )
    )
    locations = sorted(v.location for v in SEC021().check(schema, {}))
    assert locations == ["public.t.bad_a", "public.t.bad_b"]


# --- silent: legitimate column = literal / correct patterns --------------


def test_sec021_silent_on_attribute_column_eq_boolean() -> None:
    # `is_public` is not an identity column — a public-content
    # policy comparing it to `true` is legitimate. SEC021 must NOT
    # fire (this is the headline false-positive it avoids).
    assert SEC021().check(_wrap(_policy("is_public = true")), {}) == []


def test_sec021_silent_on_attribute_column_eq_string() -> None:
    assert SEC021().check(_wrap(_policy("status = 'published'")), {}) == []


def test_sec021_silent_on_identity_column_eq_session_value() -> None:
    # The recommended pattern — the identity column keyed off a
    # per-request GUC — must NOT fire. The right operand is a
    # function call, not a literal.
    schema = _wrap(
        _policy("tenant_id = current_setting('app.tenant', true)")
    )
    assert SEC021().check(schema, {}) == []


def test_sec021_silent_on_identity_column_eq_other_column() -> None:
    # Column-to-column comparison — no literal operand.
    assert SEC021().check(_wrap(_policy("tenant_id = owner_id")), {}) == []


def test_sec021_silent_on_non_equality_operator() -> None:
    # SEC021 is equality-only — `<>` / `>` are not the pin pattern.
    assert SEC021().check(_wrap(_policy("tenant_id <> 1")), {}) == []
    assert SEC021().check(_wrap(_policy("tenant_id > 1")), {}) == []


def test_sec021_silent_on_plain_id_column() -> None:
    # `id` is not in the identity-column set — `id = 1` is silent.
    assert SEC021().check(_wrap(_policy("id = 1")), {}) == []


def test_sec021_silent_when_policy_has_no_clauses() -> None:
    schema = _wrap(_policy(using=None, with_check=None))
    assert SEC021().check(schema, {}) == []


# --- identity_columns option ---------------------------------------------


def test_sec021_custom_identity_columns_replaces_default() -> None:
    # The configured list replaces the default set: `tenant_id` is
    # no longer identity-ish, `site_id` now is.
    options = {"identity_columns": ["site_id"]}
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "tenant_id", "site_id"),
                policies=(
                    _policy("tenant_id = 1", name="default_only"),
                    _policy("site_id = 1", name="custom"),
                ),
            ),
        )
    )
    locations = [v.location for v in SEC021().check(schema, options)]
    assert locations == ["public.t.custom"]


def test_sec021_custom_identity_columns_is_case_insensitive() -> None:
    # Postgres lowercases unquoted identifiers; the option is
    # case-folded to match.
    options = {"identity_columns": ["Site_ID"]}
    schema = _wrap(_policy("id = 1"))  # no 'site_id' here -> silent
    assert SEC021().check(schema, options) == []
    schema2 = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "site_id"),
                policies=(_policy("site_id = 1"),),
            ),
        )
    )
    assert len(SEC021().check(schema2, options)) == 1


def test_sec021_bad_identity_columns_type_raises_clearly() -> None:
    schema = _wrap(_policy("tenant_id = 1"))
    with pytest.raises(TypeError, match="identity_columns"):
        SEC021().check(schema, {"identity_columns": "tenant_id"})  # type: ignore[dict-item]


# --- allowlist / metadata ------------------------------------------------


def test_sec021_allowlist_exempts_qualified_policy_id() -> None:
    schema = _wrap(_policy("tenant_id = 1"))
    assert SEC021().check(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec021_bad_allowlist_type_raises_clearly() -> None:
    schema = _wrap(_policy("tenant_id = 1"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC021().check(schema, {"allowlist": "public.t.p"})  # type: ignore[dict-item]


def test_sec021_message_recommends_session_context() -> None:
    schema = _wrap(_policy("tenant_id = 1"))
    [v] = SEC021().check(schema, {})
    assert "current_setting" in v.message
    assert "allowlist" in v.message


def test_sec021_metadata_present() -> None:
    rule = SEC021()
    assert rule.id == "SEC021"
    assert rule.severity == "info"
    assert rule.title
