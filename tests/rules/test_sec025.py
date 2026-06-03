"""Unit tests for SEC025 — policy predicate references a table that
has RLS disabled.

SEC025 (warning) fires when a policy's USING / WITH CHECK
references — in a sub-select, a JOIN, anywhere `RangeVar` reaches
— another table whose `rls_enabled` is false. The row-level
isolation on the policy's own table is only as strong as the
referenced table's isolation; an attacker who can write to the
referenced table can grant themselves access.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table, View
from pgrls.rules.sec025 import SEC025


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


def _docs(
    *policies: Policy,
    schema: str = "public",
    name: str = "documents",
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=True,
        force_rls=True,
        policies=policies,
        columns=("id", "tenant_id"),
    )


def _members(
    *,
    schema: str = "public",
    name: str = "members",
    rls_enabled: bool = False,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls_enabled,
        force_rls=False,
        policies=(),
        columns=("user_id", "tenant_id"),
    )


# --- firing --------------------------------------------------------------


def test_sec025_fires_on_subquery_to_rls_disabled_table() -> None:
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN (SELECT tenant_id FROM public.members)"
                    )
                )
            ),
            _members(rls_enabled=False),
        )
    )
    [v] = SEC025().check(schema, options={})
    assert v.rule_id == "SEC025"
    assert v.severity == "warning"
    assert v.location == "public.documents.p"
    assert "public.members" in v.message
    assert "RLS disabled" in v.message


def test_sec025_silent_when_referenced_table_is_rls_protected() -> None:
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN (SELECT tenant_id FROM public.members)"
                    )
                )
            ),
            _members(rls_enabled=True),
        )
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_silent_on_cte_shadowing_rls_disabled_table() -> None:
    # The policy references a CTE *named* `members`, not the base
    # table. In Postgres a CTE name shadows a same-named table within
    # its scope, so the unqualified `members` ref is the CTE — SEC025
    # must not resolve it to the RLS-disabled `members` table (a false
    # positive). The CTE body here touches no base table at all.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN ("
                        "WITH members AS (SELECT 1 AS tenant_id) "
                        "SELECT tenant_id FROM members)"
                    )
                )
            ),
            _members(rls_enabled=False),
        )
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_fires_when_cte_shadow_is_in_the_other_clause() -> None:
    # R10 #2: a CTE named `members` in USING must NOT suppress a bare
    # `members` reference in WITH CHECK — USING and WITH CHECK are
    # independent Postgres scopes, so the WITH CHECK ref genuinely reads
    # the RLS-disabled `public.members`. The earlier code unioned CTE
    # names across both clauses and silently swallowed this real leak.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN ("
                        "WITH members AS (SELECT 1 AS tenant_id) "
                        "SELECT tenant_id FROM members)"
                    ),
                    with_check=(
                        "tenant_id IN (SELECT tenant_id FROM public.members)"
                    ),
                )
            ),
            _members(rls_enabled=False),
        )
    )
    [v] = SEC025().check(schema, options={})
    assert v.location == "public.documents.p"
    assert "public.members" in v.message


def test_sec025_same_clause_cte_shadow_still_suppressed_with_two_clauses() -> None:
    # Guard against over-firing from the per-clause refactor: when the
    # CTE shadow and the bare ref are in the SAME clause, suppression
    # must still hold even though the OTHER clause is also present.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN ("
                        "WITH members AS (SELECT 1 AS tenant_id) "
                        "SELECT tenant_id FROM members)"
                    ),
                    with_check="tenant_id = 1",
                )
            ),
            _members(rls_enabled=False),
        )
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_silent_on_self_reference() -> None:
    # A policy on `documents` referencing `documents` itself in a
    # sub-select inherits the same RLS gate (its own policies apply
    # transitively), so SEC025 stays quiet.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN ("
                        "SELECT tenant_id FROM public.documents"
                        ")"
                    )
                )
            ),
        )
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_silent_on_view_reference() -> None:
    # A view is a different surface — VIEW001 / VIEW002 cover
    # view-mediated bypass. SEC025 stops at the table boundary so
    # the two rules do not double-fire on the same reference.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN (SELECT tenant_id FROM public.members_v)"
                    )
                )
            ),
        ),
        views=(
            View(
                schema="public",
                name="members_v",
                is_materialized=False,
                security_invoker=True,
                security_barrier=True,
                definition="SELECT 1",
                references=(),
                security_definer_calls=(),
            ),
        ),
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_silent_on_out_of_scope_reference() -> None:
    # `private.acl` is not in the introspected schema set, so
    # pgrls can't see its RLS state. The conservative call is
    # silence — widen `--schemas` to include it for SEC025 to
    # surface a finding there.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN (SELECT tenant_id FROM private.acl)"
                    )
                )
            ),
        )
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_silent_on_pg_catalog_reference() -> None:
    # System catalogs are never introspected; an admin-style
    # `pg_catalog.pg_roles` lookup must not trip SEC025.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "owner IN ("
                        "SELECT rolname FROM pg_catalog.pg_roles"
                        ")"
                    )
                )
            ),
        )
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_resolves_unqualified_name_against_own_schema() -> None:
    # `members` (no schema) resolves to `public.members` because
    # the policy is on `public.documents`. The reference is
    # RLS-disabled there, so SEC025 fires.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using="tenant_id IN (SELECT tenant_id FROM members)"
                )
            ),
            _members(rls_enabled=False),
        )
    )
    [v] = SEC025().check(schema, options={})
    assert "public.members" in v.message


def test_sec025_silent_on_unqualified_name_not_in_own_schema() -> None:
    # `ledger` (no schema) does NOT resolve to any table in the
    # policy's own schema (`public`) — it might live in another schema
    # not passed to `--schemas`. SEC025 can't see its RLS state, so it
    # stays silent rather than guessing. Pins the bare-name "not found
    # in own schema → skip" branch.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using="tenant_id IN (SELECT tenant_id FROM ledger)"
                )
            ),
        )
    )
    assert SEC025().check(schema, options={}) == []


def test_sec025_fires_on_cross_schema_reference() -> None:
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN ("
                        "SELECT tenant_id FROM private.acl"
                        ")"
                    )
                ),
                schema="public",
            ),
            Table(
                schema="private",
                name="acl",
                rls_enabled=False,
                force_rls=False,
                policies=(),
                columns=("user_id", "tenant_id"),
            ),
        )
    )
    [v] = SEC025().check(schema, options={})
    assert "private.acl" in v.message


def test_sec025_lists_multiple_unprotected_tables_sorted() -> None:
    # Two unprotected tables in the same predicate — one finding,
    # message lists both in sorted order.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN ("
                        "SELECT m.tenant_id FROM public.members m "
                        "JOIN public.audit a ON a.tenant_id = m.tenant_id"
                        ")"
                    )
                )
            ),
            _members(rls_enabled=False),
            Table(
                schema="public",
                name="audit",
                rls_enabled=False,
                force_rls=False,
                policies=(),
                columns=("tenant_id",),
            ),
        )
    )
    [v] = SEC025().check(schema, options={})
    msg = v.message
    assert "public.audit" in msg
    assert "public.members" in msg
    assert msg.index("public.audit") < msg.index("public.members")


def test_sec025_fires_on_with_check_reference() -> None:
    # The cross-table read can be in WITH CHECK too — same risk.
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using="tenant_id IS NOT NULL",
                    with_check=(
                        "tenant_id IN (SELECT tenant_id FROM public.members)"
                    ),
                )
            ),
            _members(rls_enabled=False),
        )
    )
    assert len(SEC025().check(schema, options={})) == 1


# --- allowlist -----------------------------------------------------------


def test_sec025_allowlist_skips_named_policy() -> None:
    # Two policies on the same table, both reading the unprotected
    # `members`. Allowlisting `ok` silences only that one; `fire`
    # still trips.
    using = "tenant_id IN (SELECT tenant_id FROM public.members)"
    schema = Schema(
        tables=(
            _docs(
                _policy(name="ok", using=using),
                _policy(name="fire", using=using),
            ),
            _members(rls_enabled=False),
        )
    )
    violations = SEC025().check(
        schema, options={"allowlist": ["public.documents.ok"]}
    )
    assert [v.location for v in violations] == ["public.documents.fire"]


def test_sec025_allowlist_rejects_non_list() -> None:
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN (SELECT tenant_id FROM public.members)"
                    )
                )
            ),
            _members(rls_enabled=False),
        )
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC025().check(
            schema, options={"allowlist": "public.documents.p"}
        )


def test_sec025_allowlist_rejects_whitespace_padded_entry() -> None:
    schema = Schema(
        tables=(
            _docs(
                _policy(
                    using=(
                        "tenant_id IN (SELECT tenant_id FROM public.members)"
                    )
                )
            ),
            _members(rls_enabled=False),
        )
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC025().check(
            schema, options={"allowlist": [" public.documents.p "]}
        )
