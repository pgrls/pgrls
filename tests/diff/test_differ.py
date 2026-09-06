"""Unit tests for pgrls.diff.differ scaffolding."""
from __future__ import annotations

import dataclasses
from typing import get_args

import pytest

from pgrls.diff import (
    Change,
    ChangeKind,
    Classification,
    diff_schemas,
)
from pgrls.model import ColumnGrant, Grant, Policy, Schema, Table


def _t(
    name: str = "t",
    *,
    rls=False,
    force=False,
    partition_of=None,
    policies: tuple[Policy, ...] = (),
    columns: tuple[str, ...] = ("id",),
    grants: tuple[Grant, ...] = (),
    column_grants: tuple[ColumnGrant, ...] = (),
) -> Table:
    return Table(
        schema="public",
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
        columns=columns,
        partition_of=partition_of,
        grants=grants,
        column_grants=column_grants,
    )


def _p(
    name: str,
    *,
    permissive: bool = False,
    command: str = "ALL",
    roles: tuple[str, ...] = ("PUBLIC",),
    using_sql: str | None = None,
    with_check_sql: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=roles,
        using_sql=using_sql,
        with_check_sql=with_check_sql,
    )


def test_diff_two_empty_schemas_yields_no_changes() -> None:
    assert diff_schemas(Schema(tables=()), Schema(tables=())) == []


def test_semantically_equivalent_policy_predicate_is_no_change() -> None:
    # A policy whose USING predicate is rewritten to a logically
    # equivalent but syntactically different form (De Morgan) must diff
    # as NO change when the diff-z3 extra is installed: Z3 returns
    # "semantic_equivalent", which _diff_policy_shapes must treat like
    # "unchanged". Regression — "semantic_equivalent" was absent from
    # the result->Change mapping tables, so diff_schemas raised
    # KeyError('semantic_equivalent') on this valid input.
    pytest.importorskip("z3")
    base = Schema(
        tables=(_t("t", rls=True, policies=(_p("p", using_sql="NOT (a AND b)"),)),)
    )
    head = Schema(
        tables=(
            _t("t", rls=True, policies=(_p("p", using_sql="(NOT a) OR (NOT b)"),)),
        )
    )
    assert diff_schemas(base, head) == []


def test_change_dataclass_is_frozen() -> None:
    c = Change(
        kind=ChangeKind.RLS_FLIPPED,
        classification="dangerous",
        location="public.t",
        message="RLS disabled",
        before_sql=None,
        after_sql=None,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.kind = ChangeKind.POLICY_ADDED_PERMISSIVE  # type: ignore[misc]


def test_classification_literal_values() -> None:
    # Pin the Literal contract at runtime so any drift surfaces
    # here, not at the formatter (where 'unknown classification'
    # would be a silent bug).
    assert set(get_args(Classification)) == {
        "safe",
        "breaking",
        "requires_review",
        "dangerous",
    }


def test_rls_off_to_on_is_safe() -> None:
    base = Schema(tables=(_t(rls=False),))
    head = Schema(tables=(_t(rls=True),))
    changes = diff_schemas(base, head)
    # Pin total count so a later task that adds a spurious rule
    # firing on this fixture surfaces here, not at integration.
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.RLS_FLIPPED and c.classification == "safe"
        for c in changes
    )


def test_rls_on_to_off_is_dangerous() -> None:
    base = Schema(tables=(_t(rls=True),))
    head = Schema(tables=(_t(rls=False),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.RLS_FLIPPED and c.classification == "dangerous"
        for c in changes
    )


def test_force_off_to_on_is_safe() -> None:
    base = Schema(tables=(_t(rls=True, force=False),))
    head = Schema(tables=(_t(rls=True, force=True),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.FORCE_RLS_FLIPPED
        and c.classification == "safe"
        for c in changes
    )


def test_force_on_to_off_is_dangerous() -> None:
    base = Schema(tables=(_t(rls=True, force=True),))
    head = Schema(tables=(_t(rls=True, force=False),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.FORCE_RLS_FLIPPED
        and c.classification == "dangerous"
        for c in changes
    )


def test_table_added_with_rls_is_safe() -> None:
    base = Schema(tables=())
    head = Schema(tables=(_t(rls=True, force=True),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.TABLE_ADDED_WITH_RLS
        and c.classification == "safe"
        for c in changes
    )


def test_table_added_without_rls_is_dangerous() -> None:
    base = Schema(tables=())
    head = Schema(tables=(_t(rls=False),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.TABLE_ADDED_WITHOUT_RLS
        and c.classification == "dangerous"
        for c in changes
    )


def test_table_dropped_is_breaking() -> None:
    base = Schema(tables=(_t(rls=True),))
    head = Schema(tables=())
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.TABLE_DROPPED
        and c.classification == "breaking"
        for c in changes
    )


# ---------------------------------------------------------------------------
# Policy add / drop classification
# ---------------------------------------------------------------------------


def test_policy_added_restrictive_is_safe() -> None:
    # Restrictive policies AND together — adding one tightens access (safe).
    pol = _p("isolate", permissive=False)
    base = Schema(tables=(_t(rls=True, policies=()),))
    head = Schema(tables=(_t(rls=True, policies=(pol,)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.POLICY_ADDED_RESTRICTIVE
        and c.classification == "safe"
        for c in changes
    )


def test_policy_added_permissive_is_dangerous() -> None:
    # Permissive policies OR together — adding one loosens access (dangerous).
    pol = _p("allow_all", permissive=True)
    base = Schema(tables=(_t(rls=True, policies=()),))
    head = Schema(tables=(_t(rls=True, policies=(pol,)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.POLICY_ADDED_PERMISSIVE
        and c.classification == "dangerous"
        for c in changes
    )


def test_policy_dropped_restrictive_is_dangerous() -> None:
    # Restrictive policies AND together — dropping one loosens access (dangerous).
    pol = _p("isolate", permissive=False)
    base = Schema(tables=(_t(rls=True, policies=(pol,)),))
    head = Schema(tables=(_t(rls=True, policies=()),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.POLICY_DROPPED_RESTRICTIVE
        and c.classification == "dangerous"
        for c in changes
    )


def test_policy_dropped_permissive_is_breaking() -> None:
    # Permissive policies OR together — dropping one tightens access (breaking).
    pol = _p("allow_all", permissive=True)
    base = Schema(tables=(_t(rls=True, policies=(pol,)),))
    head = Schema(tables=(_t(rls=True, policies=()),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.POLICY_DROPPED_PERMISSIVE
        and c.classification == "breaking"
        for c in changes
    )


# ---------------------------------------------------------------------------
# Policy shape changes (Task 7): permissive flag
# ---------------------------------------------------------------------------


def test_permissive_flag_tightened_is_safe() -> None:
    # permissive=True → False: restrictive AND-combines, row set narrows (safe).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", permissive=True),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", permissive=False),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.PERMISSIVE_FLAG_TIGHTENED
        and c.classification == "safe"
        for c in changes
    )


def test_permissive_flag_loosened_is_dangerous() -> None:
    # permissive=False → True: permissive OR-combines, row set broadens (dangerous).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", permissive=False),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", permissive=True),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.PERMISSIVE_FLAG_LOOSENED
        and c.classification == "dangerous"
        for c in changes
    )


# ---------------------------------------------------------------------------
# Policy shape changes (Task 7): command field
# ---------------------------------------------------------------------------


def test_command_broadened_to_all_is_dangerous() -> None:
    # narrow → ALL: policy now covers more operations (dangerous).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", command="SELECT"),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", command="ALL"),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.COMMAND_BROADENED
        and c.classification == "dangerous"
        for c in changes
    )


def test_command_narrowed_from_all_is_breaking() -> None:
    # ALL → narrow: policy no longer covers all operations (breaking).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", command="ALL"),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", command="DELETE"),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.COMMAND_NARROWED
        and c.classification == "breaking"
        for c in changes
    )


def test_command_sidegrade_is_narrowed_breaking() -> None:
    # narrow → different narrow: downstream consumer loses their covered command (breaking).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", command="SELECT"),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", command="INSERT"),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.COMMAND_NARROWED
        and c.classification == "breaking"
        for c in changes
    )


# ---------------------------------------------------------------------------
# Policy shape changes (Task 7): roles set
# ---------------------------------------------------------------------------


def test_roles_widened_is_dangerous() -> None:
    # head roles ⊋ base roles: policy now applies to more roles (dangerous).
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("app_user",)),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("app_user", "admin")),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.ROLES_WIDENED
        and c.classification == "dangerous"
        for c in changes
    )


def test_roles_narrowed_is_safe() -> None:
    # head roles ⊊ base roles: policy now applies to fewer roles (safe).
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("app_user", "admin")),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("app_user",)),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.ROLES_NARROWED
        and c.classification == "safe"
        for c in changes
    )


def test_roles_disjoint_replaced_requires_review() -> None:
    # Roles replaced with a different set — automated judgment is unreliable (requires_review).
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("app_user",)),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("reporting_role",)),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.ROLES_DISJOINT_REPLACED
        and c.classification == "requires_review"
        for c in changes
    )


def test_roles_gaining_public_is_a_widening_not_a_review() -> None:
    """`TO authenticated` → `TO PUBLIC` is disjoint as SETS, but PUBLIC is a
    superset of every role set (it covers anon too) — a widening, dangerous,
    and it must fail the default `--fail-on dangerous` gate rather than pass
    as requires_review."""
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("authenticated",)),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("PUBLIC",)),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert changes[0].kind == ChangeKind.ROLES_WIDENED
    assert changes[0].classification == "dangerous"
    assert "PUBLIC covers every role" in changes[0].message


def test_roles_mixed_overlap_requires_review() -> None:
    # Same ChangeKind as fully-disjoint but a distinct shape: head and
    # base share at least one role yet each carries a unique member.
    # Pin separately so a future refactor that tightens the else-branch
    # to "fully disjoint only" surfaces here.
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("a", "b")),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", roles=("b", "c")),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.ROLES_DISJOINT_REPLACED
        and c.classification == "requires_review"
        for c in changes
    )


def test_policy_shape_sub_checks_compose() -> None:
    # Multiple sub-checks fire on a single policy: permissive flips
    # AND roles widen → 2 Changes, not one. Pins the "one Change per
    # sub-check" composition contract so a future refactor that
    # short-circuits on the first match would surface here.
    base = Schema(
        tables=(
            _t(rls=True, policies=(_p("p", permissive=False, roles=("a",)),)),
        )
    )
    head = Schema(
        tables=(
            _t(rls=True, policies=(_p("p", permissive=True, roles=("a", "b")),)),
        )
    )
    changes = diff_schemas(base, head)
    # permissive False → True: PERMISSIVE_FLAG_LOOSENED (dangerous)
    # roles {"a"} → {"a", "b"} (strict superset): ROLES_WIDENED (dangerous)
    assert len(changes) == 2
    kinds = {c.kind for c in changes}
    assert kinds == {
        ChangeKind.PERMISSIVE_FLAG_LOOSENED,
        ChangeKind.ROLES_WIDENED,
    }


def test_policy_shape_no_change_when_fields_identical() -> None:
    # Explicit pin: when both sides have a policy with identical
    # permissive/command/roles, _diff_policy_shapes emits zero
    # Changes. Implicitly covered by the empty-schema test, but
    # this version exercises the "policy present on both sides
    # with all three fields equal" code path explicitly so any
    # spurious emission surfaces here.
    pol = _p("p", permissive=False, command="SELECT", roles=("a", "b"))
    base = Schema(tables=(_t(rls=True, policies=(pol,)),))
    head = Schema(tables=(_t(rls=True, policies=(pol,)),))
    assert diff_schemas(base, head) == []


# ---------------------------------------------------------------------------
# Policy predicate changes (Task 9): USING clause
# ---------------------------------------------------------------------------


def test_using_tightened_and_is_safe() -> None:
    # P → P AND Q: head adds a conjunct — fewer rows pass (safe).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1"),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1 AND b = 2"),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.USING_TIGHTENED and c.classification == "safe"
        for c in changes
    )


def test_using_loosened_and_drop_is_dangerous() -> None:
    # P AND Q → P: head drops a conjunct — more rows pass (dangerous).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1 AND b = 2"),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1"),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.USING_LOOSENED and c.classification == "dangerous"
        for c in changes
    )


def test_using_loosened_or_is_dangerous() -> None:
    # P → P OR Q: head adds a disjunct — more rows pass (dangerous).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1"),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1 OR b = 2"),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.USING_LOOSENED and c.classification == "dangerous"
        for c in changes
    )


def test_using_requires_review_for_unrelated() -> None:
    # Operator change — classifier cannot determine direction (requires_review).
    base = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1"),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql="a > 1"),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.USING_REQUIRES_REVIEW
        and c.classification == "requires_review"
        for c in changes
    )


# ---------------------------------------------------------------------------
# Policy predicate changes (Task 9): WITH CHECK clause
# ---------------------------------------------------------------------------


def test_with_check_tightened_or_drop_is_safe() -> None:
    # P OR Q → P: head drops a disjunct — fewer rows pass WITH CHECK (safe).
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="a = 1 OR b = 2"),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="a = 1"),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.WITH_CHECK_TIGHTENED and c.classification == "safe"
        for c in changes
    )


def test_with_check_loosened_and_drop_is_dangerous() -> None:
    # P AND Q → P: head drops a conjunct — more rows pass WITH CHECK (dangerous).
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="a = 1 AND b = 2"),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="a = 1"),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.WITH_CHECK_LOOSENED and c.classification == "dangerous"
        for c in changes
    )


def test_with_check_requires_review_for_unrelated() -> None:
    # Operator change — classifier cannot determine direction (requires_review).
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="tenant_id = current_setting('app.tenant_id')"),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="tenant_id = 99"),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert any(
        c.kind == ChangeKind.WITH_CHECK_REQUIRES_REVIEW
        and c.classification == "requires_review"
        for c in changes
    )


def test_with_check_unchanged_emits_zero_changes() -> None:
    # Whitespace-only diff in WITH CHECK — normalized to same; no change emitted.
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="a = 1"),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", with_check_sql="a   =   1"),)),)
    )
    changes = diff_schemas(base, head)
    assert changes == []


# ---------------------------------------------------------------------------
# SQL fragments carried through to before_sql / after_sql (Task 9)
# ---------------------------------------------------------------------------


def test_using_change_carries_before_after_sql() -> None:
    # The Change emitted for a USING predicate diff must carry the original
    # SQL strings so the text formatter can render a git-diff style block.
    base_sql = "a = 1"
    head_sql = "a = 1 AND b = 2"
    base = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql=base_sql),)),))
    head = Schema(tables=(_t(rls=True, policies=(_p("p", using_sql=head_sql),)),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    c = changes[0]
    assert c.kind == ChangeKind.USING_TIGHTENED
    assert c.before_sql == base_sql
    assert c.after_sql == head_sql


def test_using_added_to_existing_policy_carries_none_before_sql() -> None:
    # A USING predicate added where there was none — base_sql is None
    # and head_sql is the new SQL. compare_predicates returns
    # "requires_review" for one-side-None, but the formatter still
    # needs the asymmetric pair so it can render an addition block.
    # Pin: before_sql is None, after_sql is the new SQL.
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", using_sql=None),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1"),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    c = changes[0]
    assert c.kind == ChangeKind.USING_REQUIRES_REVIEW
    assert c.classification == "requires_review"
    assert c.before_sql is None
    assert c.after_sql == "a = 1"


def test_using_removed_from_policy_carries_none_after_sql() -> None:
    # Mirror of the previous test: removing a predicate gives the
    # formatter a non-None before_sql with a None after_sql so it
    # can render a deletion block.
    base = Schema(
        tables=(_t(rls=True, policies=(_p("p", using_sql="a = 1"),)),)
    )
    head = Schema(
        tables=(_t(rls=True, policies=(_p("p", using_sql=None),)),)
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    c = changes[0]
    assert c.kind == ChangeKind.USING_REQUIRES_REVIEW
    assert c.before_sql == "a = 1"
    assert c.after_sql is None


# ---------------------------------------------------------------------------
# Column-reference detection (Task 10)
# ---------------------------------------------------------------------------


def test_column_dropped_referenced_is_requires_review() -> None:
    # base has columns (id, tenant_id); head drops tenant_id.
    # head's policy references tenant_id in its USING clause.
    # Expect one COLUMN_DROPPED_REFERENCED (requires_review).
    from pgrls.ast_utils import parse_expr

    using_ast = parse_expr("tenant_id = current_setting('app.tenant_id')")
    pol = Policy(
        name="isolate",
        command="ALL",
        permissive=True,
        roles=("PUBLIC",),
        using_sql="tenant_id = current_setting('app.tenant_id')",
        with_check_sql=None,
        using_ast=using_ast,
        with_check_ast=None,
    )
    base = Schema(tables=(_t(rls=True, columns=("id", "tenant_id"), policies=()),))
    head = Schema(tables=(_t(rls=True, columns=("id",), policies=(pol,)),))
    changes = diff_schemas(base, head)
    column_changes = [c for c in changes if c.kind == ChangeKind.COLUMN_DROPPED_REFERENCED]
    assert len(column_changes) == 1
    assert column_changes[0].classification == "requires_review"


def test_column_dropped_unreferenced_emits_no_change() -> None:
    # base has columns (id, tenant_id); head drops tenant_id.
    # head's policy only references id in its USING clause — no mention of tenant_id.
    # Expect zero COLUMN_DROPPED_REFERENCED changes.
    from pgrls.ast_utils import parse_expr

    using_ast = parse_expr("id = 42")
    pol = Policy(
        name="isolate",
        command="ALL",
        permissive=True,
        roles=("PUBLIC",),
        using_sql="id = 42",
        with_check_sql=None,
        using_ast=using_ast,
        with_check_ast=None,
    )
    base = Schema(tables=(_t(rls=True, columns=("id", "tenant_id"), policies=()),))
    head = Schema(tables=(_t(rls=True, columns=("id",), policies=(pol,)),))
    changes = diff_schemas(base, head)
    column_changes = [c for c in changes if c.kind == ChangeKind.COLUMN_DROPPED_REFERENCED]
    assert column_changes == []


def test_column_added_emits_no_change() -> None:
    # base has columns (id,); head gains tenant_id.
    # Column-added is intentionally not reported (see AGENTS.md
    # classification table — only column-DROPPED-while-referenced
    # fires; column-added is a benign forward change).
    base = Schema(tables=(_t(rls=True, columns=("id",)),))
    head = Schema(tables=(_t(rls=True, columns=("id", "tenant_id")),))
    changes = diff_schemas(base, head)
    column_changes = [c for c in changes if c.kind == ChangeKind.COLUMN_DROPPED_REFERENCED]
    assert column_changes == []


def test_column_dropped_referenced_by_second_policy_in_iteration_order() -> None:
    # _diff_columns walks all head policies into a single
    # `referenced_names` set rather than short-circuiting on the
    # first matching policy. This test pins the contract: when the
    # FIRST policy doesn't reference the dropped column but a LATER
    # policy does, the column drop is still flagged.
    #
    # Without the upfront set, a regression that re-introduced
    # break-after-first-policy (matching only the first listed
    # policy's predicate) would silently miss this case.
    from pgrls.ast_utils import parse_expr

    # First policy references `id` only — does NOT mention tenant_id.
    pol_1 = Policy(
        name="first",
        command="SELECT",
        permissive=True,
        roles=("PUBLIC",),
        using_sql="id > 0",
        with_check_sql=None,
        using_ast=parse_expr("id > 0"),
        with_check_ast=None,
    )
    # Second policy DOES reference tenant_id — this is the one that
    # makes the column drop a REQUIRES_REVIEW.
    pol_2 = Policy(
        name="second",
        command="ALL",
        permissive=False,
        roles=("PUBLIC",),
        using_sql="tenant_id = 'x'",
        with_check_sql=None,
        using_ast=parse_expr("tenant_id = 'x'"),
        with_check_ast=None,
    )
    base = Schema(
        tables=(
            _t(
                rls=True,
                columns=("id", "tenant_id"),
                policies=(pol_1, pol_2),
            ),
        )
    )
    head = Schema(
        tables=(
            _t(
                rls=True,
                columns=("id",),
                policies=(pol_1, pol_2),
            ),
        )
    )
    changes = diff_schemas(base, head)
    column_changes = [
        c for c in changes if c.kind == ChangeKind.COLUMN_DROPPED_REFERENCED
    ]
    assert len(column_changes) == 1
    assert column_changes[0].location == "public.t.tenant_id"
    assert column_changes[0].classification == "requires_review"


# ---------------------------------------------------------------------------
# Grant diff detection (Task 10)
# ---------------------------------------------------------------------------


def test_grant_revoked_is_safe() -> None:
    # base: app has SELECT+INSERT; head: app has SELECT only → INSERT revoked.
    # Expect one GRANT_REVOKED (safe).
    base = Schema(
        tables=(_t(rls=True, grants=(Grant(role="app", privileges=("SELECT", "INSERT")),)),)
    )
    head = Schema(
        tables=(_t(rls=True, grants=(Grant(role="app", privileges=("SELECT",)),)),)
    )
    changes = diff_schemas(base, head)
    grant_changes = [c for c in changes if c.kind == ChangeKind.GRANT_REVOKED]
    assert len(grant_changes) == 1
    assert grant_changes[0].classification == "safe"


def test_grant_added_is_requires_review() -> None:
    # base: app has SELECT; head: app has SELECT+INSERT → INSERT added.
    # Expect one GRANT_ADDED (requires_review).
    base = Schema(
        tables=(_t(rls=True, grants=(Grant(role="app", privileges=("SELECT",)),)),)
    )
    head = Schema(
        tables=(_t(rls=True, grants=(Grant(role="app", privileges=("SELECT", "INSERT")),)),)
    )
    changes = diff_schemas(base, head)
    grant_changes = [c for c in changes if c.kind == ChangeKind.GRANT_ADDED]
    assert len(grant_changes) == 1
    assert grant_changes[0].classification == "requires_review"


def test_grant_public_no_rls_is_dangerous() -> None:
    # head: rls_enabled=False, no policies, PUBLIC gains SELECT.
    # Expect one GRANT_PUBLIC_NO_RLS (dangerous), NOT GRANT_ADDED.
    base = Schema(tables=(_t(rls=False, grants=()),))
    head = Schema(
        tables=(
            _t(
                rls=False,
                policies=(),
                grants=(Grant(role="PUBLIC", privileges=("SELECT",)),),
            ),
        )
    )
    changes = diff_schemas(base, head)
    kinds = {c.kind for c in changes}
    assert ChangeKind.GRANT_PUBLIC_NO_RLS in kinds
    assert ChangeKind.GRANT_ADDED not in kinds
    public_no_rls = [c for c in changes if c.kind == ChangeKind.GRANT_PUBLIC_NO_RLS]
    assert len(public_no_rls) == 1
    assert public_no_rls[0].classification == "dangerous"


def test_column_grant_public_no_rls_is_dangerous() -> None:
    # R15 #2: a column-level PUBLIC grant added on a no-RLS table exposes
    # that column to every connected role — the same data-exposure as a
    # table-level PUBLIC grant, at column granularity. Must route to the
    # dangerous GRANT_PUBLIC_NO_RLS path (not be silently no-change), and
    # name the exposed column.
    base = Schema(tables=(_t(rls=False),))
    head = Schema(
        tables=(
            _t(
                rls=False,
                column_grants=(
                    ColumnGrant(
                        role="PUBLIC", column="ssn", privileges=("SELECT",)
                    ),
                ),
            ),
        )
    )
    changes = diff_schemas(base, head)
    public_no_rls = [
        c for c in changes if c.kind == ChangeKind.GRANT_PUBLIC_NO_RLS
    ]
    assert len(public_no_rls) == 1
    assert public_no_rls[0].classification == "dangerous"
    assert "ssn" in public_no_rls[0].message
    # With RLS enabled the same column grant is only requires_review.
    head_rls = Schema(
        tables=(
            _t(
                rls=True,
                force=True,
                column_grants=(
                    ColumnGrant(
                        role="PUBLIC", column="ssn", privileges=("SELECT",)
                    ),
                ),
            ),
        )
    )
    changes_rls = diff_schemas(Schema(tables=(_t(rls=True, force=True),)), head_rls)
    assert ChangeKind.GRANT_PUBLIC_NO_RLS not in {c.kind for c in changes_rls}
    added = [c for c in changes_rls if c.kind == ChangeKind.GRANT_ADDED]
    assert len(added) == 1 and added[0].classification == "requires_review"


def test_column_grant_revoked_is_safe() -> None:
    # R16 #7 (coverage): when a column grant's privilege set strictly
    # shrinks between base and head, the diff must emit a single
    # GRANT_REVOKED change classified "safe" (a revoke only narrows
    # access — never a security regression) that names the column. This
    # is the only _diff_column_grants branch the suite did not exercise.
    base = Schema(
        tables=(
            _t(
                rls=True,
                force=True,
                column_grants=(
                    ColumnGrant(
                        role="reporter",
                        column="ssn",
                        privileges=("SELECT", "UPDATE"),
                    ),
                ),
            ),
        )
    )
    head = Schema(
        tables=(
            _t(
                rls=True,
                force=True,
                column_grants=(
                    ColumnGrant(
                        role="reporter", column="ssn", privileges=("SELECT",)
                    ),
                ),
            ),
        )
    )
    changes = diff_schemas(base, head)
    revoked = [c for c in changes if c.kind == ChangeKind.GRANT_REVOKED]
    assert len(revoked) == 1
    assert revoked[0].classification == "safe"
    assert "ssn" in revoked[0].message
    assert "UPDATE" in revoked[0].message  # the lost privilege is named
    # The unchanged SELECT privilege produces no added/dangerous churn.
    assert ChangeKind.GRANT_PUBLIC_NO_RLS not in {c.kind for c in changes}
    assert ChangeKind.GRANT_ADDED not in {c.kind for c in changes}


def test_grant_public_no_rls_fires_even_when_stale_policies_present() -> None:
    # Postgres only enforces policies when RLS is on; with RLS off,
    # any policies on the table are dormant. A new PUBLIC grant on
    # an RLS-off table is therefore wide-open whether or not policies
    # exist — pin the dangerous classification so a future
    # "tightening" of the rule can't silently reintroduce the
    # false-negative.
    pol = _p("allow_read", permissive=True, using_sql="true")
    base = Schema(tables=(_t(rls=False, policies=(pol,), grants=()),))
    head = Schema(
        tables=(
            _t(
                rls=False,
                policies=(pol,),
                grants=(Grant(role="PUBLIC", privileges=("SELECT",)),),
            ),
        )
    )
    changes = diff_schemas(base, head)
    kinds = {c.kind for c in changes}
    assert ChangeKind.GRANT_PUBLIC_NO_RLS in kinds
    assert ChangeKind.GRANT_ADDED not in kinds
    public_no_rls = [c for c in changes if c.kind == ChangeKind.GRANT_PUBLIC_NO_RLS]
    assert len(public_no_rls) == 1
    assert public_no_rls[0].classification == "dangerous"


def test_grant_public_added_with_rls_enabled_is_just_requires_review() -> None:
    # head: rls_enabled=True with a policy, PUBLIC gains SELECT.
    # Expect GRANT_ADDED (requires_review), NOT GRANT_PUBLIC_NO_RLS.
    pol = _p("allow_read", permissive=True, using_sql="true")
    base = Schema(tables=(_t(rls=True, grants=()),))
    head = Schema(
        tables=(
            _t(
                rls=True,
                policies=(pol,),
                grants=(Grant(role="PUBLIC", privileges=("SELECT",)),),
            ),
        )
    )
    changes = diff_schemas(base, head)
    kinds = {c.kind for c in changes}
    assert ChangeKind.GRANT_ADDED in kinds
    assert ChangeKind.GRANT_PUBLIC_NO_RLS not in kinds
    grant_added = [c for c in changes if c.kind == ChangeKind.GRANT_ADDED]
    assert len(grant_added) == 1
    assert grant_added[0].classification == "requires_review"


def test_grant_mixed_per_role_emits_both_revoke_and_add() -> None:
    # base: app has SELECT+INSERT; head: app has SELECT+DELETE.
    # INSERT was revoked (safe), DELETE was added (requires_review).
    # Pins the "one change per direction per role" composition contract.
    base = Schema(
        tables=(
            _t(rls=True, grants=(Grant(role="app", privileges=("SELECT", "INSERT")),)),
        )
    )
    head = Schema(
        tables=(
            _t(rls=True, grants=(Grant(role="app", privileges=("SELECT", "DELETE")),)),
        )
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 2
    revoked = [c for c in changes if c.kind == ChangeKind.GRANT_REVOKED]
    added = [c for c in changes if c.kind == ChangeKind.GRANT_ADDED]
    assert len(revoked) == 1
    assert revoked[0].classification == "safe"
    assert revoked[0].location == "public.t.app"
    assert len(added) == 1
    assert added[0].classification == "requires_review"
    assert added[0].location == "public.t.app"


def test_grants_iterate_sorted_by_role_name() -> None:
    # head adds privileges to roles "zeta" AND "alpha"; base has no grants.
    # Pins that the resulting Changes list orders alpha's Change before zeta's
    # (sorted iteration over the role-name union).
    base = Schema(tables=(_t(rls=True, grants=()),))
    head = Schema(
        tables=(
            _t(
                rls=True,
                grants=(
                    Grant(role="zeta", privileges=("SELECT",)),
                    Grant(role="alpha", privileges=("SELECT",)),
                ),
            ),
        )
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 2
    assert changes[0].location == "public.t.alpha"
    assert changes[1].location == "public.t.zeta"


def test_rls_and_force_both_flip_emits_two_changes() -> None:
    # base: rls=True, force=True; head: rls=False, force=False.
    # Both flag flips fire independently → exactly 2 Changes.
    base = Schema(tables=(_t(rls=True, force=True),))
    head = Schema(tables=(_t(rls=False, force=False),))
    changes = diff_schemas(base, head)
    assert len(changes) == 2
    rls_changes = [c for c in changes if c.kind == ChangeKind.RLS_FLIPPED]
    force_changes = [c for c in changes if c.kind == ChangeKind.FORCE_RLS_FLIPPED]
    assert len(rls_changes) == 1
    assert rls_changes[0].classification == "dangerous"
    assert len(force_changes) == 1
    assert force_changes[0].classification == "dangerous"


# ---------------------------------------------------------------------------
# Composite changes — multi-category integration
# ---------------------------------------------------------------------------


def test_composite_change_emits_one_per_category_independently() -> None:
    # Real-world migration shape: a single table flips RLS off,
    # drops a RESTRICTIVE policy, and revokes a grant — all at
    # once. Each unit test pins one change kind in isolation; this
    # test pins that the differ composes them correctly when they
    # co-occur on the same table. Without this, a refactor that
    # accidentally short-circuited the per-table sub-rule loop on
    # the first match would not be caught by the per-rule tests.
    base_pol = _p("isolate", permissive=False, roles=("PUBLIC",))
    base = Schema(
        tables=(
            _t(
                rls=True,
                policies=(base_pol,),
                grants=(
                    Grant(role="app", privileges=("SELECT", "INSERT")),
                ),
            ),
        )
    )
    head = Schema(
        tables=(
            _t(
                rls=False,                                # RLS flipped off
                policies=(),                              # policy dropped
                grants=(
                    Grant(role="app", privileges=("SELECT",)),  # INSERT revoked
                ),
            ),
        )
    )
    changes = diff_schemas(base, head)

    # Exactly three Changes — one per independent rule firing.
    assert len(changes) == 3, [c.kind.name for c in changes]

    kinds_by_classification: dict[str, set[ChangeKind]] = {}
    for c in changes:
        kinds_by_classification.setdefault(c.classification, set()).add(c.kind)

    # RLS_FLIPPED on the rls=True→False side is dangerous.
    # POLICY_DROPPED_RESTRICTIVE is dangerous.
    # GRANT_REVOKED (INSERT) is safe.
    assert kinds_by_classification.get("dangerous") == {
        ChangeKind.RLS_FLIPPED,
        ChangeKind.POLICY_DROPPED_RESTRICTIVE,
    }
    assert kinds_by_classification.get("safe") == {
        ChangeKind.GRANT_REVOKED,
    }


def test_composite_change_within_table_ordering_is_deterministic() -> None:
    # Same fixture-shape concern as above, but pin the within-table
    # sub-rule order documented in `diff_schemas`'s docstring:
    # RLS state → policies (presence) → policy shape → predicates →
    # columns → grants. Multi-category changes on one table emit in
    # that order so formatter output stays stable across runs.
    base_pol = _p("isolate", permissive=False)
    base = Schema(
        tables=(
            _t(
                rls=True,
                policies=(base_pol,),
                grants=(Grant(role="app", privileges=("SELECT",)),),
            ),
        )
    )
    head = Schema(
        tables=(
            _t(
                rls=False,
                policies=(),
                grants=(),  # role dropped entirely → GRANT_REVOKED
            ),
        )
    )
    changes = diff_schemas(base, head)
    kinds_in_order = [c.kind for c in changes]
    # Item 1 in the within-table sub-rule list (RLS state) before
    # item 3 (_diff_policies presence) before item 6 (_diff_grants).
    assert kinds_in_order.index(ChangeKind.RLS_FLIPPED) < kinds_in_order.index(
        ChangeKind.POLICY_DROPPED_RESTRICTIVE
    )
    assert kinds_in_order.index(
        ChangeKind.POLICY_DROPPED_RESTRICTIVE
    ) < kinds_in_order.index(ChangeKind.GRANT_REVOKED)


def test_composite_change_six_step_ordering_is_deterministic() -> None:
    # Cover all six steps from `diff_schemas`'s within-table
    # docstring on a single table: (1) RLS state flip, (2) skipped
    # — no policies presence change, (3) policy-shape role
    # widening, (4) predicate change, (5) column drop referenced by
    # head policy, (6) grant change. Without this test, a future
    # reorder of the `changes.extend(...)` calls in
    # `pgrls/diff/differ.py:diff_schemas` would silently flip the
    # CLI/JSON/SARIF output without breaking
    # `test_composite_change_within_table_ordering_is_deterministic`
    # (which only pins steps 1, 3, 6 — three of the six).
    base_pol = _p(
        "isolate",
        permissive=False,
        command="SELECT",
        roles=("app",),
        using_sql="tenant_id = 'a'",
    )
    head_pol = _p(
        "isolate",
        permissive=False,
        command="SELECT",
        roles=("app", "admin"),  # role widened → POLICY_ROLES_WIDENED
        using_sql="tenant_id = 'a' OR tenant_id = 'b'",  # OR added → loosened
    )
    base = Schema(
        tables=(
            _t(
                rls=True,
                policies=(base_pol,),
                columns=("id", "tenant_id"),
                grants=(Grant(role="app", privileges=("SELECT",)),),
            ),
        )
    )
    head = Schema(
        tables=(
            _t(
                rls=False,  # RLS toggled off → step 1
                policies=(head_pol,),  # shape change → step 3
                columns=("id",),  # tenant_id dropped (still ref'd) → step 5
                grants=(),  # GRANT_REVOKED → step 6
            ),
        )
    )
    changes = diff_schemas(base, head)
    kinds_in_order = [c.kind for c in changes]
    # Step 1 (RLS) < step 3 (policy shape — roles) < step 4
    # (predicate) < step 5 (column dropped) < step 6 (grant). Step 2
    # (policy presence) doesn't fire because both sides have the
    # same policy by name; that's deliberately omitted to keep the
    # fixture realistic.
    rls_idx = kinds_in_order.index(ChangeKind.RLS_FLIPPED)
    roles_idx = kinds_in_order.index(ChangeKind.ROLES_WIDENED)
    pred_idx = kinds_in_order.index(ChangeKind.USING_LOOSENED)
    col_idx = kinds_in_order.index(
        ChangeKind.COLUMN_DROPPED_REFERENCED
    )
    grant_idx = kinds_in_order.index(ChangeKind.GRANT_REVOKED)
    assert rls_idx < roles_idx < pred_idx < col_idx < grant_idx


# ---------------------------------------------------------------------------
# Partition handling — partition_of differences are not detected as Changes
# ---------------------------------------------------------------------------


def test_partition_of_only_diff_emits_no_changes() -> None:
    # v0.2 has no partition-aware diff logic — Table.partition_of is
    # captured in snapshots and survives round-trip but isn't compared
    # by any detection rule. A diff where the ONLY difference between
    # base and head is partition_of should emit zero Changes. This
    # test future-proofs against accidentally adding a partition_of
    # comparison: if v0.3+ wants partition-family diffs, removing
    # this test in the same change makes the intent visible in the
    # diff.
    base = Schema(
        tables=(
            _t(rls=True, partition_of=None),
        )
    )
    head = Schema(
        tables=(
            _t(rls=True, partition_of=("public", "parent_table")),
        )
    )
    assert diff_schemas(base, head) == []

    # And the inverse direction (head removes partition_of).
    base2 = Schema(
        tables=(
            _t(rls=True, partition_of=("public", "parent_table")),
        )
    )
    head2 = Schema(
        tables=(
            _t(rls=True, partition_of=None),
        )
    )
    assert diff_schemas(base2, head2) == []


# ---------------------------------------------------------------------------
# H1 — leaking-row counterexample surfacing.
#
# The serialization tests below build a Change with a hand-supplied
# counterexample directly, so they exercise the Change → Violation →
# JSON / text projection deterministically WITHOUT invoking the solver
# (Z3-agnostic, never flaky). The end-to-end population test is gated on
# z3 because only the verifier path produces a non-None counterexample.
# ---------------------------------------------------------------------------


def _loosened_change_with_cx() -> Change:
    return Change(
        kind=ChangeKind.USING_LOOSENED,
        classification="dangerous",
        location="public.t",
        message="Policy public.t USING predicate loosened.",
        before_sql="tenant_id = 1",
        after_sql="tenant_id = 1 OR tenant_id = 2",
        counterexample={"tenant_id": 2},
    )


def test_json_includes_counterexample() -> None:
    import json

    from pgrls.diff.formatters import format_diff_json

    payload = json.loads(format_diff_json([_loosened_change_with_cx()]))
    assert payload["violations"][0]["counterexample"] == {"tenant_id": 2}


def test_json_omits_counterexample_when_absent() -> None:
    import json

    from pgrls.diff.formatters import format_diff_json

    c = Change(
        kind=ChangeKind.RLS_FLIPPED,
        classification="dangerous",
        location="public.t",
        message="RLS disabled",
        before_sql=None,
        after_sql=None,
    )
    payload = json.loads(format_diff_json([c]))
    assert "counterexample" not in payload["violations"][0]


def test_text_includes_leaking_row() -> None:
    from pgrls.diff.formatters import format_diff_text

    out = format_diff_text([_loosened_change_with_cx()])
    assert "example leaking row" in out
    assert "tenant_id=2" in out


def test_text_omits_leaking_row_when_absent() -> None:
    from pgrls.diff.formatters import format_diff_text

    c = Change(
        kind=ChangeKind.USING_LOOSENED,
        classification="dangerous",
        location="public.t",
        message="Policy public.t USING predicate loosened.",
        before_sql="tenant_id = 1",
        after_sql="tenant_id = 1 OR tenant_id = 2",
        counterexample=None,
    )
    out = format_diff_text([c])
    assert "example leaking row" not in out


def test_diff_schemas_populates_counterexample_on_semantic_loosen() -> None:
    # End-to-end through diff_schemas: a Z3-only semantic loosen (the
    # syntactic OR-add pattern is dodged by spreading the disjunction
    # so compare_predicates must reach classify_via_z3) yields a
    # USING_LOOSENED Change carrying a sound leaking row.
    pytest.importorskip("z3")
    base = Schema(
        tables=(_t("t", rls=True, policies=(_p("p", using_sql="tenant_id = 1"),)),)
    )
    head = Schema(
        tables=(
            _t(
                "t",
                rls=True,
                policies=(
                    _p("p", using_sql="tenant_id = 1 OR tenant_id = 2 OR tenant_id = 3"),
                ),
            ),
        )
    )
    changes = diff_schemas(base, head)
    loosened = [c for c in changes if c.kind == ChangeKind.USING_LOOSENED]
    assert len(loosened) == 1
    cx = loosened[0].counterexample
    assert cx is not None
    # Only real columns, and the row is a member of head ∖ base.
    assert all(not k.startswith(("_isnull__", "_opaque__")) for k in cx)
    assert cx.get("tenant_id") in (2, 3)


def test_diff_schemas_no_counterexample_on_syntactic_loosen() -> None:
    # A SINGLE OR-disjunct add is caught by the syntactic `loosened_or`
    # pattern BEFORE Z3 runs — also DANGEROUS, but H1 deliberately does
    # not attach a counterexample to the non-verifier path, so the
    # field stays None.
    base = Schema(
        tables=(_t("t", rls=True, policies=(_p("p", using_sql="tenant_id = 1"),)),)
    )
    head = Schema(
        tables=(
            _t(
                "t",
                rls=True,
                policies=(_p("p", using_sql="tenant_id = 1 OR tenant_id = 2"),),
            ),
        )
    )
    changes = diff_schemas(base, head)
    loosened = [c for c in changes if c.kind == ChangeKind.USING_LOOSENED]
    assert len(loosened) == 1
    assert loosened[0].counterexample is None


# ---------------------------------------------------------------------------
# Policy rename detection (Task 3)
# ---------------------------------------------------------------------------


def _table_with(*policies):
    return _t(rls=True, policies=tuple(policies))


def test_pure_rename_is_single_safe_change_strict_default():
    base = Schema(tables=(_table_with(_p("old", using_sql="tenant_id = 1")),))
    head = Schema(tables=(_table_with(_p("new", using_sql="tenant_id = 1")),))
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    assert changes[0].kind is ChangeKind.POLICY_RENAMED
    assert changes[0].classification == "safe"
    assert "old" in changes[0].message and "new" in changes[0].message


def test_pure_rename_normalization_still_safe():
    # Whitespace-only diff in USING; compare_predicates normalizes to "unchanged".
    base = Schema(tables=(_table_with(_p("old", using_sql="tenant_id = 1")),))
    head = Schema(tables=(_table_with(_p("new", using_sql="tenant_id   =   1")),))
    changes = diff_schemas(base, head)
    assert [c.kind for c in changes] == [ChangeKind.POLICY_RENAMED]
    assert changes[0].classification == "safe"


def test_pure_rename_semantic_equivalent_still_safe() -> None:
    # Z3 returns "semantic_equivalent" for logically-equivalent but syntactically
    # reordered predicates (e.g. "a AND b" vs "b AND a").  A rename whose predicate
    # pair compares as semantic_equivalent must still be a single SAFE POLICY_RENAMED.
    pytest.importorskip("z3")
    base = Schema(tables=(_table_with(_p("old", using_sql="a AND b")),))
    head = Schema(tables=(_table_with(_p("new", using_sql="b AND a")),))
    changes = diff_schemas(base, head)
    assert [c.kind for c in changes] == [ChangeKind.POLICY_RENAMED]
    assert changes[0].classification == "safe"


def test_rename_plus_loosen_is_drop_add_under_strict():
    base = Schema(tables=(_table_with(_p("old", using_sql="tenant_id = 1")),))
    head = Schema(tables=(_table_with(
        _p("new", using_sql="tenant_id = 1 OR is_admin()")),))
    changes = diff_schemas(base, head)  # strict default
    kinds = {c.kind for c in changes}
    assert ChangeKind.POLICY_RENAMED not in kinds
    assert ChangeKind.POLICY_DROPPED_RESTRICTIVE in kinds
    assert ChangeKind.POLICY_ADDED_RESTRICTIVE in kinds


def test_rename_plus_loosen_is_dangerous_under_relaxed():
    base = Schema(tables=(_table_with(_p("old", using_sql="tenant_id = 1")),))
    head = Schema(tables=(_table_with(
        _p("new", using_sql="tenant_id = 1 OR is_admin()")),))
    changes = diff_schemas(base, head, rename_detection="relaxed")
    assert [c.kind for c in changes] == [ChangeKind.POLICY_RENAMED]
    assert changes[0].classification == "dangerous"


def test_rename_with_z3_incompatible_predicate_degrades_to_requires_review() -> None:
    # Regression for the crash surfaced by this feature (PR #229) and guarded
    # upstream in #230: a renamed policy whose predicate edit OR/AND-combines an
    # Int comparison with a bare boolean function call reaches Z3 with mismatched
    # sorts. Unlike the `tenant_id = 1` -> `tenant_id = 1 OR is_admin()` loosen
    # fixtures (a clean syntactic subset that never reaches Z3), `tenant_id = 2`
    # is NOT a subset of the head disjuncts, so the comparator falls through to
    # Z3 and must DEGRADE to `requires_review` (the safe direction), not raise
    # `z3.Z3Exception`. Guarded with importorskip so the crash path is actually
    # exercised when z3 is present.
    pytest.importorskip("z3")
    base = Schema(tables=(_table_with(_p("old", using_sql="tenant_id = 2")),))
    head = Schema(tables=(_table_with(
        _p("new", using_sql="tenant_id = 1 OR is_admin()")),))

    # strict (default): not a pure rename -> clean drop+add, no crash.
    strict = diff_schemas(base, head)
    strict_kinds = {c.kind for c in strict}
    assert ChangeKind.POLICY_RENAMED not in strict_kinds
    assert ChangeKind.POLICY_DROPPED_RESTRICTIVE in strict_kinds
    assert ChangeKind.POLICY_ADDED_RESTRICTIVE in strict_kinds

    # relaxed: the rename path collapses the pair and the degraded predicate
    # verdict grades to requires_review (never crashes, never safe/dangerous).
    relaxed = diff_schemas(base, head, rename_detection="relaxed")
    assert [c.kind for c in relaxed] == [ChangeKind.POLICY_RENAMED]
    assert relaxed[0].classification == "requires_review"


def test_rename_plus_tighten_is_safe_under_relaxed():
    base = Schema(tables=(_table_with(_p("old", using_sql="tenant_id = 1")),))
    head = Schema(tables=(_table_with(
        _p("new", using_sql="tenant_id = 1 AND active")),))
    changes = diff_schemas(base, head, rename_detection="relaxed")
    assert [c.kind for c in changes] == [ChangeKind.POLICY_RENAMED]
    assert changes[0].classification == "safe"


def test_rename_classification_requires_review_for_pure_rename():
    base = Schema(tables=(_table_with(_p("old", using_sql="tenant_id = 1")),))
    head = Schema(tables=(_table_with(_p("new", using_sql="tenant_id = 1")),))
    changes = diff_schemas(base, head, rename_classification="requires_review")
    assert [c.kind for c in changes] == [ChangeKind.POLICY_RENAMED]
    assert changes[0].classification == "requires_review"


def test_two_policies_swapping_names_no_rename():
    # Both names present on both sides -> never one-sided -> no rename.
    base = Schema(tables=(_table_with(
        _p("a", using_sql="x = 1"), _p("b", using_sql="y = 2")),))
    head = Schema(tables=(_table_with(
        _p("a", using_sql="y = 2"), _p("b", using_sql="x = 1")),))
    changes = diff_schemas(base, head)
    assert all(c.kind is not ChangeKind.POLICY_RENAMED for c in changes)


def test_ambiguous_bucket_falls_back_to_drop_add():
    # 2 base-only + 1 head-only, identical shape -> cannot pair uniquely.
    base = Schema(tables=(_table_with(
        _p("old1", using_sql="x = 1"), _p("old2", using_sql="x = 1")),))
    head = Schema(tables=(_table_with(_p("new", using_sql="x = 1")),))
    changes = diff_schemas(base, head)
    assert all(c.kind is not ChangeKind.POLICY_RENAMED for c in changes)
    assert sum(c.kind is ChangeKind.POLICY_DROPPED_RESTRICTIVE
               for c in changes) == 2


def test_off_mode_keeps_drop_add_for_identical_rename():
    base = Schema(tables=(_table_with(_p("old", using_sql="x = 1")),))
    head = Schema(tables=(_table_with(_p("new", using_sql="x = 1")),))
    changes = diff_schemas(base, head, rename_detection="off")
    kinds = {c.kind for c in changes}
    assert ChangeKind.POLICY_RENAMED not in kinds
    assert ChangeKind.POLICY_DROPPED_RESTRICTIVE in kinds
    assert ChangeKind.POLICY_ADDED_RESTRICTIVE in kinds


def test_rename_with_role_change_not_paired():
    base = Schema(tables=(_table_with(
        _p("old", roles=("alice",), using_sql="x = 1")),))
    head = Schema(tables=(_table_with(
        _p("new", roles=("bob",), using_sql="x = 1")),))
    changes = diff_schemas(base, head)  # different bucket -> no rename
    assert all(c.kind is not ChangeKind.POLICY_RENAMED for c in changes)


def test_clause_added_is_not_pure_rename():
    # USING equal but WITH CHECK added (None -> non-empty): not pure.
    base = Schema(tables=(_table_with(
        _p("old", using_sql="x = 1", with_check_sql=None)),))
    head = Schema(tables=(_table_with(
        _p("new", using_sql="x = 1", with_check_sql="x = 1")),))
    strict = diff_schemas(base, head)
    assert all(c.kind is not ChangeKind.POLICY_RENAMED for c in strict)
    relaxed = diff_schemas(base, head, rename_detection="relaxed")
    assert [c.kind for c in relaxed] == [ChangeKind.POLICY_RENAMED]
    assert relaxed[0].classification == "requires_review"


def test_text_and_json_render_empty_counterexample_as_any_row() -> None:
    # An empty-dict counterexample is the H1 verifier's "every row leaks"
    # witness (the old predicate rejected everything). Pin both renderings.
    import json as _json

    from pgrls.diff.formatters import format_diff_json, format_diff_text

    c = Change(
        kind=ChangeKind.USING_LOOSENED,
        classification="dangerous",
        location="public.t",
        message="Policy public.t USING predicate loosened.",
        before_sql="false",
        after_sql="true",
        counterexample={},
    )
    assert "example leaking row: (any row" in format_diff_text([c])
    payload = _json.loads(format_diff_json([c]))
    assert payload["violations"][0]["counterexample"] == {}


# ---------------------------------------------------------------------------
# Fix 9 — Determinism: POLICY_RENAMED appears before add/drop in output list
# ---------------------------------------------------------------------------


def test_renamed_policy_appears_before_add_drop_in_output() -> None:
    # A table with BOTH a renamed policy AND a genuinely added policy:
    # the POLICY_RENAMED change must appear before the POLICY_ADDED_*
    # change in the output list (rename pass runs first, sorted by
    # location; add/drop loop follows).
    base = Schema(
        tables=(
            _t(
                rls=True,
                policies=(
                    _p("old_name", using_sql="tenant_id = 1"),
                    _p("stays", using_sql="x = 2"),
                ),
            ),
        )
    )
    head = Schema(
        tables=(
            _t(
                rls=True,
                policies=(
                    _p("new_name", using_sql="tenant_id = 1"),
                    _p("stays", using_sql="x = 2"),
                    _p("brand_new", permissive=True, using_sql="true"),
                ),
            ),
        )
    )
    changes = diff_schemas(base, head)
    renamed = [c for c in changes if c.kind is ChangeKind.POLICY_RENAMED]
    added = [c for c in changes if c.kind is ChangeKind.POLICY_ADDED_PERMISSIVE]
    assert len(renamed) == 1
    assert len(added) == 1
    # POLICY_RENAMED must come before POLICY_ADDED_PERMISSIVE.
    assert changes.index(renamed[0]) < changes.index(added[0])


# ---------------------------------------------------------------------------
# Fix 11 — Pure rename with both USING and WITH CHECK set (name-only, safe)
# ---------------------------------------------------------------------------


def test_pure_rename_with_both_clauses_is_single_safe_change() -> None:
    # A policy with command="ALL" and BOTH using_sql and with_check_sql set
    # identically on both sides except for the name — must produce a single
    # POLICY_RENAMED SAFE change, not a drop+add.
    base = Schema(
        tables=(
            _t(
                rls=True,
                policies=(
                    _p(
                        "old",
                        command="ALL",
                        using_sql="tenant_id = current_setting('app.tenant')",
                        with_check_sql="tenant_id = current_setting('app.tenant')",
                    ),
                ),
            ),
        )
    )
    head = Schema(
        tables=(
            _t(
                rls=True,
                policies=(
                    _p(
                        "new",
                        command="ALL",
                        using_sql="tenant_id = current_setting('app.tenant')",
                        with_check_sql="tenant_id = current_setting('app.tenant')",
                    ),
                ),
            ),
        )
    )
    changes = diff_schemas(base, head)
    assert len(changes) == 1
    c = changes[0]
    assert c.kind is ChangeKind.POLICY_RENAMED
    assert c.classification == "safe"
    # Pure rename: no predicate block.
    assert c.before_sql is None
    assert c.after_sql is None


# --- multiple Grant rows per role (MF7) ------------------------------------


def test_offline_model_merges_repeated_grants_to_one_role() -> None:
    # `GRANT SELECT ...; GRANT INSERT ...;` to the same role appears live as ONE
    # Grant with both privileges (introspection groups the ACL per role). The
    # offline sql= path appended one Grant per statement, so every consumer
    # keying on role kept only the LAST. Column grants were already merged; the
    # table-level twin was missing.
    from pgrls.schema_sources import schema_from_sql

    schema = schema_from_sql(
        "CREATE TABLE public.t (id int);"
        "GRANT SELECT ON public.t TO PUBLIC;"
        "GRANT INSERT ON public.t TO PUBLIC;"
    )
    grants = schema.tables[0].grants
    assert len(grants) == 1
    assert grants[0].role == "PUBLIC"
    assert set(grants[0].privileges) == {"SELECT", "INSERT"}


def test_diff_reports_a_grant_added_alongside_an_existing_one() -> None:
    # The bite: head adds `GRANT SELECT ... TO PUBLIC` — opening reads to
    # everyone — beside an INSERT grant that both sides share. The overwrite
    # made base and head compare EQUAL, so `pgrls diff` reported no change and
    # the PR gate passed a migration that had just exposed the table.
    from pgrls.diff.grants import _diff_grants
    from pgrls.schema_sources import schema_from_sql

    rls = (
        "CREATE TABLE public.t (id int);"
        "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;"
    )
    base = schema_from_sql(rls + "GRANT INSERT ON public.t TO PUBLIC;").tables[0]
    head = schema_from_sql(
        rls
        + "GRANT SELECT ON public.t TO PUBLIC;"
        + "GRANT INSERT ON public.t TO PUBLIC;"
    ).tables[0]
    kinds = [c.kind.value for c in _diff_grants(base, head)]
    assert "DIFF_GRANT_ADDED" in kinds


def test_diff_unions_duplicate_grant_rows_it_is_handed() -> None:
    # Defense in depth at the consumer: a Schema from an older snapshot or a
    # hand-built one may still carry unmerged duplicate rows, and the diff must
    # not silently drop the earlier ones.
    from pgrls.diff.grants import _diff_grants
    from pgrls.model import Grant, Table

    def tbl(*grants: Grant) -> Table:
        return Table(
            schema="public", name="t", rls_enabled=True,
            force_rls=True, policies=(), grants=grants,
        )

    base = tbl(Grant(role="PUBLIC", privileges=("INSERT",)))
    head = tbl(
        Grant(role="PUBLIC", privileges=("SELECT",)),
        Grant(role="PUBLIC", privileges=("INSERT",)),
    )
    assert [c.kind.value for c in _diff_grants(base, head)] == ["DIFF_GRANT_ADDED"]
