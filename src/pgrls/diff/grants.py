"""Grant diff helper.

`_diff_grants(base, head)` detects per-role privilege changes:
revoked privileges (SAFE), added privileges (REQUIRES_REVIEW), and
the special PUBLIC + no-RLS combination (DANGEROUS — every
connected role gains the privilege without a row filter).
"""
from __future__ import annotations

from pgrls.diff.differ import Change, ChangeKind
from pgrls.model import Table


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
