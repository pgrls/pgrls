"""Column-reference diff helper.

`_diff_columns(base, head)` detects columns dropped between two
table snapshots that are still referenced by a head policy's
USING / WITH CHECK predicate. Such drops are classified
REQUIRES_REVIEW: the policy's runtime behavior depends on the
dropped column, so a human needs to confirm whether the policy
should be updated, dropped, or kept (with the column re-added).
"""
from __future__ import annotations

from pgrls.ast_utils import extract_column_refs, parse_expr
from pgrls.diff.differ import Change, ChangeKind
from pgrls.model import Table


def _diff_columns(base_table: Table, head_table: Table) -> list[Change]:
    """Detect dropped columns still referenced by head policies.

    For each column present in base but absent in head, walk every head
    policy's using_ast and with_check_ast via extract_column_refs. A
    column is considered referenced if any tuple in the refs set has it
    as its last element — this covers both unqualified refs like
    `("tenant_id",)` and qualified refs like `("t", "tenant_id")`.

    Trade-off: the lenient match accepts ANY qualifier, which means a
    head policy that references `other_table.tenant_id` (a tenant_id
    column on a JOINed table) registers as a reference to `tenant_id`
    on the table being diffed. This produces false positives, but the
    classification is `requires_review` — humans handle the trade-off
    correctly. A stricter match that verified the qualifier matches
    the diffed table would miss real `t.tenant_id` and unqualified
    `tenant_id` references that motivated the rule. v0.3 may revisit
    if false-positive volume warrants it.

    Emits one COLUMN_DROPPED_REFERENCED (requires_review) per dropped
    column that is still referenced. Columns added in head or unchanged
    are not reported.
    """
    dropped_cols = set(base_table.columns) - set(head_table.columns)
    if not dropped_cols:
        return []

    changes: list[Change] = []
    qname = head_table.qualified_name

    # Walk every head policy AST once and collect the set of
    # last-component column names referenced anywhere. Then per
    # dropped column, check membership in O(1). This drops the
    # nested loop from O(dropped × policies × ast-walk) to
    # O(policies × ast-walk + dropped).
    #
    # AST may not be populated when the head Schema came from
    # `Schema.from_snapshot` — v0.2.1 stops eagerly parsing on
    # snapshot load (see `from_snapshot` docstring). Fall back to
    # parsing the SQL on demand so this rule still fires for
    # snapshot-vs-anything diffs. parse_expr returns None for
    # empty/None input and on parse failure; either path produces
    # zero refs from this policy and the loop continues.
    #
    # On parse failure, parse_expr emits a stderr warning. Pass
    # location and a diff-context tail so the user sees the
    # offending policy named instead of a generic lint-context
    # message about SEC/PERF/HYG rules that don't run during diff.
    fail_tail = (
        "Snapshot policy AST will be unavailable for "
        "column-reference checks."
    )

    referenced_names: set[str] = set()
    for policy in head_table.policies:
        policy_loc = f"{qname}.{policy.name}"
        for ast_node, sql, clause in (
            (policy.using_ast, policy.using_sql, "USING"),
            (policy.with_check_ast, policy.with_check_sql, "WITH CHECK"),
        ):
            node = (
                ast_node
                if ast_node is not None
                else parse_expr(
                    sql,
                    location=policy_loc,
                    clause=clause,
                    fail_message_tail=fail_tail,
                )
            )
            if node is None:
                continue
            for ref in extract_column_refs(node):
                if ref:  # tuple is non-empty
                    referenced_names.add(ref[-1])

    for col_name in sorted(dropped_cols):
        if col_name in referenced_names:
            changes.append(
                Change(
                    kind=ChangeKind.COLUMN_DROPPED_REFERENCED,
                    classification="requires_review",
                    location=f"{qname}.{col_name}",
                    message=(
                        f"Column {qname}.{col_name} was dropped but is still"
                        " referenced by at least one head policy predicate"
                        " — review required."
                    ),
                    before_sql=None,
                    after_sql=None,
                )
            )

    return changes
