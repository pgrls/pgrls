"""Top-level pgrls.diff implementation.

Defines the public diff result types — `Change`, `ChangeKind`,
`Classification` — and the orchestrator function
`diff_schemas(base, head)`. Per-table sub-rule helpers live in
sibling modules:

  * `pgrls.diff.policies` — `_diff_policies` (add / drop) and
    `_diff_policy_shapes` (permissive flag, command, roles,
    USING / WITH CHECK predicate diff via
    `pgrls.diff.ast_compare.compare_predicates`).
  * `pgrls.diff.columns` — `_diff_columns` (dropped columns
    referenced by head policies).
  * `pgrls.diff.grants` — `_diff_grants` (per-role privilege
    revoke / add, with the PUBLIC + no-RLS DANGEROUS escape).

`diff_schemas` walks tables by qualified_name and dispatches to
those helpers in fixed order — see its docstring for the within-
table sub-rule sequence the formatters rely on.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from pgrls.model import Schema

Classification = Literal["safe", "breaking", "requires_review", "dangerous"]


class ChangeKind(str, Enum):
    """Categorization of detected changes.

    Mirrored as `rule_id` in the JSON / SARIF output. Stable
    across releases — additions allowed, removals/renames are
    breaking changes.
    """

    # RLS table-level state
    RLS_FLIPPED = "DIFF_RLS_FLIPPED"
    FORCE_RLS_FLIPPED = "DIFF_FORCE_RLS_FLIPPED"

    # Table presence
    TABLE_ADDED_WITH_RLS = "DIFF_TABLE_ADDED_WITH_RLS"
    TABLE_ADDED_WITHOUT_RLS = "DIFF_TABLE_ADDED_WITHOUT_RLS"
    TABLE_DROPPED = "DIFF_TABLE_DROPPED"

    # Policy add / drop / rename
    POLICY_ADDED_RESTRICTIVE = "DIFF_POLICY_ADDED_RESTRICTIVE"
    POLICY_ADDED_PERMISSIVE = "DIFF_POLICY_ADDED_PERMISSIVE"
    POLICY_DROPPED_RESTRICTIVE = "DIFF_POLICY_DROPPED_RESTRICTIVE"
    POLICY_DROPPED_PERMISSIVE = "DIFF_POLICY_DROPPED_PERMISSIVE"
    POLICY_RENAMED = "DIFF_POLICY_RENAMED"

    # Policy shape
    PERMISSIVE_FLAG_TIGHTENED = "DIFF_PERMISSIVE_FLAG_TIGHTENED"
    PERMISSIVE_FLAG_LOOSENED = "DIFF_PERMISSIVE_FLAG_LOOSENED"
    COMMAND_BROADENED = "DIFF_COMMAND_BROADENED"
    COMMAND_NARROWED = "DIFF_COMMAND_NARROWED"
    ROLES_WIDENED = "DIFF_ROLES_WIDENED"
    ROLES_NARROWED = "DIFF_ROLES_NARROWED"
    ROLES_DISJOINT_REPLACED = "DIFF_ROLES_DISJOINT_REPLACED"

    # Predicate changes (USING / WITH CHECK)
    USING_TIGHTENED = "DIFF_USING_TIGHTENED"
    USING_LOOSENED = "DIFF_USING_LOOSENED"
    USING_REQUIRES_REVIEW = "DIFF_USING_REQUIRES_REVIEW"
    WITH_CHECK_TIGHTENED = "DIFF_WITH_CHECK_TIGHTENED"
    WITH_CHECK_LOOSENED = "DIFF_WITH_CHECK_LOOSENED"
    WITH_CHECK_REQUIRES_REVIEW = "DIFF_WITH_CHECK_REQUIRES_REVIEW"

    # Columns
    COLUMN_DROPPED_REFERENCED = "DIFF_COLUMN_DROPPED_REFERENCED"

    # Grants
    GRANT_REVOKED = "DIFF_GRANT_REVOKED"
    GRANT_ADDED = "DIFF_GRANT_ADDED"
    GRANT_PUBLIC_NO_RLS = "DIFF_GRANT_PUBLIC_NO_RLS"


@dataclass(frozen=True)
class Change:
    """One detected change between two Schemas.

    All five fields are required; `before_sql` / `after_sql` may
    be None for changes that don't have a meaningful SQL pair
    (e.g., RLS_FLIPPED, ROLES_WIDENED).

    For predicate Changes (`USING_*` / `WITH_CHECK_*`),
    `before_sql` and `after_sql` carry the **original** SQL strings
    from the base and head snapshots — not pglast-canonicalized
    output. The text formatter renders them as-is so the user sees
    their own source formatting (parens, casing, whitespace) rather
    than a RawStream-normalized rewrite. Either side may be None
    when a predicate is added or removed.

    For loosened predicate Changes, `counterexample` may carry a
    `{column: value}` row that HEAD admits but BASE rejects (Z3 path
    only; None otherwise). It is excluded from `__eq__` / `__hash__`
    (`compare=False`) so the frozen dataclass stays hashable even
    with a dict payload — its presence is fully derived from the
    other fields, so dropping it from equality changes nothing.
    """

    kind: ChangeKind
    classification: Classification
    location: str
    message: str
    before_sql: str | None
    after_sql: str | None
    counterexample: dict[str, object] | None = field(
        default=None, compare=False, hash=False
    )


def diff_schemas(base: Schema, head: Schema) -> list[Change]:
    """Compute the list of changes from base to head.

    Output ordering is deterministic:

    * Outer order: by `qualified_name` (sorted).
    * Within a table, sub-rules emit in this fixed order:

        1. `RLS_FLIPPED`
        2. `FORCE_RLS_FLIPPED`
        3. `_diff_policies`         (sorted policy names; add/drop)
        4. `_diff_policy_shapes`    (sorted policy names; per policy:
                                     permissive → command → roles →
                                     predicate diff: USING then WITH CHECK)
        5. `_diff_columns`          (dropped columns referenced by head policies)
        6. `_diff_grants`           (sorted role names; revoked, added,
                                     PUBLIC-no-RLS)

    Reordering branches silently breaks the contract the text and
    JSON formatters rely on — prefer a docstring update + new
    branch over reshuffling.

    The text and JSON formatters rely on this ordering being
    stable across runs against the same inputs — reorder the
    branches and the formatter output reorders too.
    """
    # Local imports break the import cycle: policies.py / columns.py /
    # grants.py all import `Change` and `ChangeKind` from this module.
    # Pulling them in at module top would create a circular import at
    # package load. Imported once per call (cheap; cached in
    # sys.modules after the first call).
    from pgrls.diff.columns import _diff_columns
    from pgrls.diff.grants import _diff_grants
    from pgrls.diff.policies import _diff_policies, _diff_policy_shapes

    changes: list[Change] = []
    base_by_qname = {t.qualified_name: t for t in base.tables}
    head_by_qname = {t.qualified_name: t for t in head.tables}

    for qname in sorted(set(base_by_qname) | set(head_by_qname)):
        b = base_by_qname.get(qname)
        h = head_by_qname.get(qname)
        if b is None and h is not None:
            # Table added.
            if h.rls_enabled:
                changes.append(
                    Change(
                        kind=ChangeKind.TABLE_ADDED_WITH_RLS,
                        classification="safe",
                        location=qname,
                        message=f"Table {qname} added with RLS enabled.",
                        before_sql=None,
                        after_sql=None,
                    )
                )
            else:
                changes.append(
                    Change(
                        kind=ChangeKind.TABLE_ADDED_WITHOUT_RLS,
                        classification="dangerous",
                        location=qname,
                        message=(
                            f"Table {qname} added without RLS enabled "
                            "— every connected role can read every row."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
            continue
        if h is None and b is not None:
            # Table dropped.
            changes.append(
                Change(
                    kind=ChangeKind.TABLE_DROPPED,
                    classification="breaking",
                    location=qname,
                    message=(
                        f"Table {qname} dropped; its policies are "
                        "gone with it. Verify the drop is intentional."
                    ),
                    before_sql=None,
                    after_sql=None,
                )
            )
            continue
        # Both sides present; compare RLS state.
        assert b is not None and h is not None
        if b.rls_enabled != h.rls_enabled:
            changes.append(
                Change(
                    kind=ChangeKind.RLS_FLIPPED,
                    classification=(
                        "safe" if h.rls_enabled else "dangerous"
                    ),
                    location=qname,
                    message=(
                        f"Table {qname} RLS "
                        f"{'enabled' if h.rls_enabled else 'disabled'}."
                    ),
                    before_sql=None,
                    after_sql=None,
                )
            )
        if b.force_rls != h.force_rls:
            changes.append(
                Change(
                    kind=ChangeKind.FORCE_RLS_FLIPPED,
                    classification=(
                        "safe" if h.force_rls else "dangerous"
                    ),
                    location=qname,
                    message=(
                        f"Table {qname} FORCE ROW LEVEL SECURITY "
                        f"{'enabled' if h.force_rls else 'disabled'}."
                    ),
                    before_sql=None,
                    after_sql=None,
                )
            )
        changes.extend(_diff_policies(b, h))
        changes.extend(_diff_policy_shapes(b, h))
        changes.extend(_diff_columns(b, h))
        changes.extend(_diff_grants(b, h))
    return changes
