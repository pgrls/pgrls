"""Top-level pgrls.diff implementation.

`diff_schemas(base, head)` is the main entry point. It walks both
Schema instances, emits a list of `Change` records classified per
the table in the v0.2 design spec.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from pgrls.ast_utils import extract_column_refs
from pgrls.diff.ast_compare import compare_predicates
from pgrls.model import Policy, Schema, Table

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
    """

    kind: ChangeKind
    classification: Classification
    location: str
    message: str
    before_sql: str | None
    after_sql: str | None


# `compare_predicates` result → (USING ChangeKind, Classification).
# Lives here (after ChangeKind is declared) so the dict can store
# enum values directly. "unchanged" is not in the table — callers
# skip it before looking up. The two dicts must stay in lockstep:
# same keys, same Classification, only the kind enum differs.
_USING_RESULT_TO_CHANGE: dict[str, tuple[ChangeKind, Classification]] = {
    "tightened_and":     (ChangeKind.USING_TIGHTENED,       "safe"),
    "loosened_and_drop": (ChangeKind.USING_LOOSENED,        "dangerous"),
    "loosened_or":       (ChangeKind.USING_LOOSENED,        "dangerous"),
    "tightened_or_drop": (ChangeKind.USING_TIGHTENED,       "safe"),
    "requires_review":   (ChangeKind.USING_REQUIRES_REVIEW, "requires_review"),
}
_WITH_CHECK_RESULT_TO_CHANGE: dict[str, tuple[ChangeKind, Classification]] = {
    "tightened_and":     (ChangeKind.WITH_CHECK_TIGHTENED,       "safe"),
    "loosened_and_drop": (ChangeKind.WITH_CHECK_LOOSENED,        "dangerous"),
    "loosened_or":       (ChangeKind.WITH_CHECK_LOOSENED,        "dangerous"),
    "tightened_or_drop": (ChangeKind.WITH_CHECK_TIGHTENED,       "safe"),
    "requires_review":   (ChangeKind.WITH_CHECK_REQUIRES_REVIEW, "requires_review"),
}

# Per-result message fragment, keyed off compare_predicates's result.
# Joined with the clause label and policy location at the call site
# to produce the user-facing Change.message string. Keyed off
# `result` (not the kind) so the text describes the actual transform
# detected — `tightened_and` says "clause added" while
# `tightened_or_drop` says "disjunct removed", whereas the prior
# substring-on-kind branching collapsed both into one message.
_PREDICATE_RESULT_MESSAGES: dict[str, str] = {
    "tightened_and":     "tightened (clause added)",
    "loosened_and_drop": "loosened (clause removed) — broader row set",
    "loosened_or":       "loosened (disjunct added) — broader row set",
    "tightened_or_drop": "tightened (disjunct removed)",
    "requires_review":   (
        "changed in a way the auto-classifier can't analyze "
        "— manual review required"
    ),
}


def _diff_policies(base_table: Table, head_table: Table) -> list[Change]:
    """Return Changes for policies added or dropped between two table snapshots.

    Classification rationale:
    - Restrictive policies AND together: adding one tightens the allowed row
      set (safe); dropping one loosens it (dangerous).
    - Permissive policies OR together: adding one broadens the allowed row set
      (dangerous — previously-blocked rows become visible); dropping one
      narrows it (breaking — previously-visible rows may disappear).

    Rename detection is deferred to v0.3; each rename appears here as one drop
    + one add.
    """
    base_by_name: dict[str, Policy] = {p.name: p for p in base_table.policies}
    head_by_name: dict[str, Policy] = {p.name: p for p in head_table.policies}

    changes: list[Change] = []
    for name in sorted(set(base_by_name) | set(head_by_name)):
        in_base = name in base_by_name
        in_head = name in head_by_name

        if not in_base and in_head:
            # Policy added.
            policy = head_by_name[name]
            location = f"{head_table.qualified_name}.{name}"
            if not policy.permissive:
                changes.append(
                    Change(
                        kind=ChangeKind.POLICY_ADDED_RESTRICTIVE,
                        classification="safe",
                        location=location,
                        message=(
                            f"Policy {head_table.qualified_name}.{name}"
                            " (RESTRICTIVE) added."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
            else:
                changes.append(
                    Change(
                        kind=ChangeKind.POLICY_ADDED_PERMISSIVE,
                        classification="dangerous",
                        location=location,
                        message=(
                            f"Policy {head_table.qualified_name}.{name}"
                            " (PERMISSIVE) added"
                            " — broadens the row set;"
                            " previously-blocked rows may become visible."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
        elif in_base and not in_head:
            # Policy dropped.
            policy = base_by_name[name]
            location = f"{base_table.qualified_name}.{name}"
            if not policy.permissive:
                changes.append(
                    Change(
                        kind=ChangeKind.POLICY_DROPPED_RESTRICTIVE,
                        classification="dangerous",
                        location=location,
                        message=(
                            f"Policy {base_table.qualified_name}.{name}"
                            " (RESTRICTIVE) dropped — removes a constraint."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
            else:
                changes.append(
                    Change(
                        kind=ChangeKind.POLICY_DROPPED_PERMISSIVE,
                        classification="breaking",
                        location=location,
                        message=(
                            f"Policy {base_table.qualified_name}.{name}"
                            " (PERMISSIVE) dropped"
                            " — previously-visible rows may no longer be."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
        # Both sides present: shape changes are Task 7.

    return changes


def _command_change(
    base_cmd: str, head_cmd: str
) -> tuple[ChangeKind, Classification] | None:
    """Return (ChangeKind, Classification) for a command transition, or None if equal.

    Partial order: each of SELECT/INSERT/UPDATE/DELETE is strictly less than ALL;
    the four narrow commands are mutually incomparable.

    - narrow → ALL: COMMAND_BROADENED (dangerous)
    - ALL → narrow: COMMAND_NARROWED (breaking)
    - narrow → different narrow (side-grade): COMMAND_NARROWED (breaking)
    """
    if base_cmd == head_cmd:
        return None
    if head_cmd == "ALL":
        # narrow → ALL
        return ChangeKind.COMMAND_BROADENED, "dangerous"
    # ALL → narrow  OR  narrow → different narrow
    return ChangeKind.COMMAND_NARROWED, "breaking"


def _diff_policy_shapes(base_table: Table, head_table: Table) -> list[Change]:
    """Return Changes for policy shape differences on policies present on both sides.

    Only handles policies present in both base and head — added/dropped policies
    are Task 6's domain (_diff_policies).

    Per-policy sub-checks run in fixed order for determinism:
      1. permissive flag
      2. command field
      3. roles set
      4. predicate diff (USING then WITH CHECK)

    Policy names are iterated in sorted order for deterministic output.
    """
    base_by_name: dict[str, Policy] = {p.name: p for p in base_table.policies}
    head_by_name: dict[str, Policy] = {p.name: p for p in head_table.policies}

    changes: list[Change] = []
    qname = base_table.qualified_name

    for name in sorted(set(base_by_name) & set(head_by_name)):
        base_pol = base_by_name[name]
        head_pol = head_by_name[name]
        location = f"{qname}.{name}"

        # 1. permissive flag
        if base_pol.permissive != head_pol.permissive:
            if base_pol.permissive and not head_pol.permissive:
                # permissive → restrictive: row set narrows (safe)
                changes.append(
                    Change(
                        kind=ChangeKind.PERMISSIVE_FLAG_TIGHTENED,
                        classification="safe",
                        location=location,
                        message=(
                            f"Policy {location} changed from PERMISSIVE to"
                            " RESTRICTIVE (tightened)."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
            else:
                # restrictive → permissive: row set broadens (dangerous)
                changes.append(
                    Change(
                        kind=ChangeKind.PERMISSIVE_FLAG_LOOSENED,
                        classification="dangerous",
                        location=location,
                        message=(
                            f"Policy {location} changed from RESTRICTIVE to"
                            " PERMISSIVE (loosened)."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )

        # 2. command field
        cmd_result = _command_change(base_pol.command, head_pol.command)
        if cmd_result is not None:
            kind, classification = cmd_result
            label = "narrowed" if kind == ChangeKind.COMMAND_NARROWED else "broadened"
            changes.append(
                Change(
                    kind=kind,
                    classification=classification,
                    location=location,
                    message=(
                        f"Policy {location} command"
                        f" {base_pol.command} → {head_pol.command} ({label})."
                    ),
                    before_sql=None,
                    after_sql=None,
                )
            )

        # 3. roles set
        base_roles = set(base_pol.roles)
        head_roles = set(head_pol.roles)
        if base_roles != head_roles:
            if head_roles > base_roles:
                # strict superset: more roles covered (dangerous)
                changes.append(
                    Change(
                        kind=ChangeKind.ROLES_WIDENED,
                        classification="dangerous",
                        location=location,
                        message=(
                            f"Policy {location} roles widened"
                            f" from {sorted(base_roles)} to {sorted(head_roles)}."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
            elif head_roles < base_roles:
                # strict subset: fewer roles covered (safe)
                changes.append(
                    Change(
                        kind=ChangeKind.ROLES_NARROWED,
                        classification="safe",
                        location=location,
                        message=(
                            f"Policy {location} roles narrowed"
                            f" from {sorted(base_roles)} to {sorted(head_roles)}."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
            else:
                # Else-branch covers two distinct shapes that share a
                # ChangeKind: fully disjoint (no overlap, e.g.
                # {a} → {b}) AND mixed-overlap (intersection non-empty
                # AND each side has unique members, e.g.
                # {a, b} → {b, c}). Both produce ROLES_DISJOINT_REPLACED
                # because the auto-classifier can't reliably decide
                # whether the change is safe.
                changes.append(
                    Change(
                        kind=ChangeKind.ROLES_DISJOINT_REPLACED,
                        classification="requires_review",
                        location=location,
                        message=(
                            f"Policy {location} roles replaced"
                            f" from {sorted(base_roles)} to {sorted(head_roles)}"
                            " — review required."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )

        # 4. predicate diff (USING then WITH CHECK).
        # USING runs before WITH CHECK so a refactor that reorders
        # them surfaces in the deterministic-output tests.
        for clause_label, base_sql, head_sql, mapping in (
            (
                "USING",
                base_pol.using_sql,
                head_pol.using_sql,
                _USING_RESULT_TO_CHANGE,
            ),
            (
                "WITH CHECK",
                base_pol.with_check_sql,
                head_pol.with_check_sql,
                _WITH_CHECK_RESULT_TO_CHANGE,
            ),
        ):
            result = compare_predicates(
                base_sql,
                head_sql,
                location=location,
                clause=clause_label,
            )
            if result == "unchanged":
                continue
            kind, classification = mapping[result]
            message_fragment = _PREDICATE_RESULT_MESSAGES[result]
            changes.append(
                Change(
                    kind=kind,
                    classification=classification,
                    location=location,
                    message=(
                        f"Policy {location} {clause_label} predicate "
                        f"{message_fragment}."
                    ),
                    before_sql=base_sql,
                    after_sql=head_sql,
                )
            )

    return changes


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
    referenced_names: set[str] = set()
    for policy in head_table.policies:
        for ast_node in (policy.using_ast, policy.with_check_ast):
            if ast_node is None:
                continue
            for ref in extract_column_refs(ast_node):
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


def _diff_grants(base_table: Table, head_table: Table) -> list[Change]:
    """Detect grant revoke/add per role; flag PUBLIC + no-RLS as dangerous.

    Builds privilege sets per role for both sides, then iterates over
    the sorted union of all role names. For each role:
    - Revoked privileges (in base, not head) → GRANT_REVOKED (safe).
    - Added privileges (in head, not base) → GRANT_ADDED (requires_review),
      UNLESS role == "PUBLIC" AND head_table has no policies AND
      head_table.rls_enabled is False, in which case → GRANT_PUBLIC_NO_RLS
      (dangerous).

    Roles iterated in sorted order; privilege lists in messages sorted
    for determinism. If base and head both have empty grants, returns [].
    """
    base_grants_by_role: dict[str, set[str]] = {
        g.role: set(g.privileges) for g in base_table.grants
    }
    head_grants_by_role: dict[str, set[str]] = {
        g.role: set(g.privileges) for g in head_table.grants
    }

    all_roles = sorted(set(base_grants_by_role) | set(head_grants_by_role))
    if not all_roles:
        return []

    changes: list[Change] = []
    qname = head_table.qualified_name

    for role in all_roles:
        base_privs = base_grants_by_role.get(role, set())
        head_privs = head_grants_by_role.get(role, set())

        revoked_privs = base_privs - head_privs
        added_privs = head_privs - base_privs

        location = f"{qname}.{role}"

        if revoked_privs:
            # Render as comma-joined uppercase tokens (e.g.
            # "INSERT, SELECT") rather than Python list repr —
            # human-readable in CLI output, still deterministic
            # because the input list is sorted.
            revoked_str = ", ".join(sorted(revoked_privs))
            changes.append(
                Change(
                    kind=ChangeKind.GRANT_REVOKED,
                    classification="safe",
                    location=location,
                    message=(
                        f"On {qname}, role {role} lost privileges"
                        f" {revoked_str}."
                    ),
                    before_sql=None,
                    after_sql=None,
                )
            )

        if added_privs:
            added_str = ", ".join(sorted(added_privs))
            public_no_rls = (
                role == "PUBLIC"
                and head_table.policies == ()
                and not head_table.rls_enabled
            )
            if public_no_rls:
                changes.append(
                    Change(
                        kind=ChangeKind.GRANT_PUBLIC_NO_RLS,
                        classification="dangerous",
                        location=location,
                        message=(
                            f"On {qname}, role PUBLIC gained"
                            f" {added_str} on a table with no RLS"
                            " — every connected role can read every row."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )
            else:
                changes.append(
                    Change(
                        kind=ChangeKind.GRANT_ADDED,
                        classification="requires_review",
                        location=location,
                        message=(
                            f"On {qname}, role {role} gained privileges"
                            f" {added_str}."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )

    return changes


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

    Tasks 9–10 append to this order. Reordering branches silently
    breaks the contract the text and JSON formatters rely on —
    prefer a docstring update + new branch over reshuffling.

    The text and JSON formatters rely on this ordering being
    stable across runs against the same inputs — reorder the
    branches and the formatter output reorders too.
    """
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
