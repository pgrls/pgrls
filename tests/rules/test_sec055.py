"""Unit tests for SEC055 — silent binding form after the schema adopted the
raising one.

SEC055 (warning) fires on a policy still comparing against a two-argument
``current_setting(name, true)`` in a schema where some *other* policy already
uses a ``…require_…``-shaped binding helper. The silent form returns NULL when
nothing is bound, so an unbound query is filtered to zero rows and cannot be
told apart from "no such row" — the application 404s instead of failing, and a
test suite connected as the table owner cannot see the difference at all.

Adoption is detected from the SCHEMA, not from ``pgrls.toml``: a config-gated
rule is silent exactly when CI lints a database without the repo's config
beside it.
"""
from __future__ import annotations

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec055 import SEC055

_SILENT = "tenant_id = (SELECT current_setting('app.tenant_id', true))"
_RAISING = "tenant_id = (SELECT pgrls_require_tenant('app.tenant_id'))"


def _table(name: str, using: str) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=True,
        force_rls=True,
        columns=("id", "tenant_id"),
        policies=(
            Policy(
                name="p",
                command="ALL",
                permissive=True,
                roles=("authenticated",),
                using_sql=using,
                with_check_sql=None,
                using_ast=parse_expr(using),
                with_check_ast=None,
            ),
        ),
    )


def _fire(*tables: Table) -> list[str]:
    schema = Schema(tables=tuple(tables))
    return [v.location for v in SEC055().check(schema, {})]


def test_fires_on_the_unconverted_policy_only() -> None:
    """The half-converted schema — the whole point of the rule."""
    assert _fire(_table("converted", _RAISING), _table("drifted", _SILENT)) == [
        "public.drifted.p"
    ]


def test_silent_when_the_schema_never_adopted() -> None:
    """No flood. A project on the silent form everywhere never opted in, so
    there is no drift to report — this is the overwhelmingly common schema and
    it must stay quiet."""
    assert _fire(_table("a", _SILENT), _table("b", _SILENT)) == []


def test_silent_when_fully_converted() -> None:
    assert _fire(_table("a", _RAISING), _table("b", _RAISING)) == []


def test_catalog_rendered_form_is_matched() -> None:
    """`pg_get_expr` normalizes a policy: the literal picks up a `::text` cast
    and the whole predicate is wrapped `( SELECT … AS current_setting )`. A
    first cut of this rule matched hand-typed SQL with a regex and found
    nothing against a live database, so pin the catalog spelling."""
    rendered_silent = (
        "(tenant_id = ( SELECT current_setting('app.tenant_id'::text, true) "
        "AS current_setting))"
    )
    rendered_raising = (
        "(tenant_id = ( SELECT pgrls_require_tenant('app.tenant_id'::text) "
        "AS pgrls_require_tenant))"
    )
    assert _fire(
        _table("converted", rendered_raising), _table("drifted", rendered_silent)
    ) == ["public.drifted.p"]


def test_hand_rolled_helper_counts_as_adoption() -> None:
    """The pattern predates the flag, so a project's own `require_tenant()`
    is the population most likely to have half-converted."""
    assert _fire(
        _table("converted", "tenant_id = (SELECT require_tenant())"),
        _table("drifted", _SILENT),
    ) == ["public.drifted.p"]


def test_one_arg_current_setting_is_not_flagged() -> None:
    """The one-argument form RAISES on an unset GUC — already loud, and
    SEC019's subject for a different reason."""
    assert _fire(
        _table("converted", _RAISING),
        _table("one_arg", "tenant_id = (SELECT current_setting('app.tenant_id'))"),
    ) == []


def test_allowlist_suppresses_a_platform_table() -> None:
    """A table read before a tenant is chosen — `users`, `memberships` — is
    legitimately unbound-readable."""
    schema = Schema(
        tables=(_table("converted", _RAISING), _table("users", _SILENT))
    )
    opts = {"allowlist": ["public.users.p"]}
    assert SEC055().check(schema, opts) == []
