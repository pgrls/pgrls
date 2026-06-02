"""Per-policy diff helpers — presence (add / drop) and shape changes.

Two helpers used by `pgrls.diff.differ.diff_schemas`'s both-sides
branch:

* ``_diff_policies(base, head)`` — policies whose name is present
  on only one side. Restrictive vs permissive directionality drives
  the SAFE / DANGEROUS / BREAKING classification — see the
  classification table in AGENTS.md and the rationale comment on
  ``_diff_policies`` itself.
* ``_diff_policy_shapes(base, head)`` — policies present on both
  sides. Compares permissive flag, command, roles, and (USING /
  WITH CHECK) predicates in that fixed order. Predicate
  comparison delegates to ``pgrls.diff.ast_compare.compare_predicates``.

Module-private helpers and dispatch tables live here too.
"""
from __future__ import annotations

from pgrls.diff.ast_compare import compare_predicates, counterexample_for
from pgrls.diff.differ import Change, ChangeKind, Classification
from pgrls.model import Policy, Table

# `compare_predicates` result → (USING ChangeKind, Classification).
# "unchanged" is not in the table — callers skip it before looking
# up. The two dicts must stay in lockstep: same keys, same
# Classification, only the kind enum differs.
_USING_RESULT_TO_CHANGE: dict[str, tuple[ChangeKind, Classification]] = {
    "tightened_and":       (ChangeKind.USING_TIGHTENED,       "safe"),
    "loosened_and_drop":   (ChangeKind.USING_LOOSENED,        "dangerous"),
    "loosened_or":         (ChangeKind.USING_LOOSENED,        "dangerous"),
    "tightened_or_drop":   (ChangeKind.USING_TIGHTENED,       "safe"),
    "semantic_tightened":  (ChangeKind.USING_TIGHTENED,       "safe"),
    "semantic_loosened":   (ChangeKind.USING_LOOSENED,        "dangerous"),
    "requires_review":     (ChangeKind.USING_REQUIRES_REVIEW, "requires_review"),
}
_WITH_CHECK_RESULT_TO_CHANGE: dict[str, tuple[ChangeKind, Classification]] = {
    "tightened_and":       (ChangeKind.WITH_CHECK_TIGHTENED,       "safe"),
    "loosened_and_drop":   (ChangeKind.WITH_CHECK_LOOSENED,        "dangerous"),
    "loosened_or":         (ChangeKind.WITH_CHECK_LOOSENED,        "dangerous"),
    "tightened_or_drop":   (ChangeKind.WITH_CHECK_TIGHTENED,       "safe"),
    "semantic_tightened":  (ChangeKind.WITH_CHECK_TIGHTENED,       "safe"),
    "semantic_loosened":   (ChangeKind.WITH_CHECK_LOOSENED,        "dangerous"),
    "requires_review":     (ChangeKind.WITH_CHECK_REQUIRES_REVIEW, "requires_review"),
}

# Per-result message fragment, keyed off compare_predicates's result.
# Joined with the clause label and policy location at the call site
# to produce the user-facing Change.message string. Keyed off
# `result` (not the kind) so the text describes the actual transform
# detected — `tightened_and` says "clause added" while
# `tightened_or_drop` says "disjunct removed", whereas the prior
# substring-on-kind branching collapsed both into one message.
_PREDICATE_RESULT_MESSAGES: dict[str, str] = {
    "tightened_and":       "tightened (clause added)",
    "loosened_and_drop":   "loosened (clause removed) — broader row set",
    "loosened_or":         "loosened (disjunct added) — broader row set",
    "tightened_or_drop":   "tightened (disjunct removed)",
    "semantic_tightened":  "tightened (Z3-verified semantic stricter — head admits a strict subset of base's row set)",
    "semantic_loosened":   "loosened (Z3-verified semantic looser — head admits a strict superset of base's row set)",
    "requires_review":     (
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

    No release through v0.5.10 implements rename detection; each rename
    appears here as one drop + one add. The `POLICY_RENAMED` enum value
    is reserved in `ChangeKind` for a future implementation.
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
        # Both sides present: shape changes are _diff_policy_shapes's domain.

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
    are `_diff_policies`'s domain.

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
            if result in ("unchanged", "semantic_equivalent"):
                # "semantic_equivalent" is Z3's verdict that the two
                # predicates prove logically equal despite differing
                # syntax — i.e. no Change, exactly like "unchanged" (see
                # diff/_z3_compare). It is deliberately absent from the
                # mapping tables below, so it MUST be skipped here too,
                # else `mapping[result]` raises KeyError on valid input
                # whenever the diff-z3 extra is installed.
                continue
            kind, classification = mapping[result]
            message_fragment = _PREDICATE_RESULT_MESSAGES[result]
            # Counterexample only on the Z3 "semantic_loosened" verdict:
            # the syntactic loosen results (`loosened_or`,
            # `loosened_and_drop`) are also DANGEROUS but never went
            # through Z3, so there's no model to mine. Gating on the
            # result (not the "dangerous" classification) keeps the
            # leaking-row feature strictly tied to the verifier path.
            cx = (
                counterexample_for(
                    base_sql, head_sql, location=location, clause=clause_label
                )
                if result == "semantic_loosened"
                else None
            )
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
                    counterexample=cx,
                )
            )

    return changes
