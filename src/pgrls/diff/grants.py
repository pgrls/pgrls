"""Grant diff helper.

`_diff_grants(base, head)` detects per-role privilege changes:
revoked privileges (SAFE), added privileges (REQUIRES_REVIEW), and
the special PUBLIC + no-RLS combination (DANGEROUS — every
connected role gains the privilege without a row filter).
"""
from __future__ import annotations

from typing import Any

from pgrls.diff.differ import Change, ChangeKind
from pgrls.model import Table


def _diff_grants(base_table: Table, head_table: Table) -> list[Change]:
    """Detect grant revoke/add per role; flag PUBLIC + no-RLS as dangerous.

    Builds privilege sets per role for both sides, then iterates over
    the sorted union of all role names. For each role:
    - Revoked privileges (in base, not head) → GRANT_REVOKED (safe).
    - Added privileges (in head, not base) → GRANT_ADDED (requires_review),
      UNLESS role == "PUBLIC" AND head_table.rls_enabled is False, in
      which case → GRANT_PUBLIC_NO_RLS (dangerous). Postgres only
      enforces policies when RLS is on; with RLS off, any policies on
      the table are dormant, so a PUBLIC grant exposes every row
      regardless of whether policies are defined.

    Roles iterated in sorted order; privilege lists in messages sorted
    for determinism. Returns [] when no per-role privilege difference
    exists (including the trivial both-sides-empty case).
    """
    # UNION per role rather than a dict comprehension keyed on role: a Schema
    # may legitimately carry more than one `Grant` for the same role (a
    # hand-built one, an older snapshot, or any producer that does not
    # pre-merge), and `{g.role: ...}` silently keeps only the LAST — which made
    # a head that added `GRANT SELECT ... TO PUBLIC` alongside an existing
    # INSERT grant compare EQUAL to the base and report no change at all.
    base_grants_by_role = _privileges_by_role(base_table.grants)
    head_grants_by_role = _privileges_by_role(head_table.grants)

    all_roles = sorted(set(base_grants_by_role) | set(head_grants_by_role))

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
                role == "PUBLIC" and not head_table.rls_enabled
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

    changes.extend(_diff_column_grants(base_table, head_table))
    return changes


def _diff_column_grants(
    base_table: Table, head_table: Table
) -> list[Change]:
    """Same revoke/add/PUBLIC-no-RLS logic as `_diff_grants`, at COLUMN
    granularity (`pg_attribute.attacl`).

    A column-level PUBLIC grant added on a table with RLS off is the same
    exposure as the table-level case — every connected role can read that
    column with no row filter — so it routes to the dangerous
    GRANT_PUBLIC_NO_RLS path, naming the exposed column. Keyed by
    `(role, column)`; iterated in sorted order for determinism.
    """
    # Union per (role, column) — same overwrite hazard as `_diff_grants`.
    base_by_key = _privileges_by_column_key(base_table.column_grants)
    head_by_key = _privileges_by_column_key(head_table.column_grants)

    changes: list[Change] = []
    qname = head_table.qualified_name

    for role, column in sorted(set(base_by_key) | set(head_by_key)):
        base_privs = base_by_key.get((role, column), set())
        head_privs = head_by_key.get((role, column), set())
        revoked_privs = base_privs - head_privs
        added_privs = head_privs - base_privs
        location = f"{qname}.{role}.{column}"

        if revoked_privs:
            revoked_str = ", ".join(sorted(revoked_privs))
            changes.append(
                Change(
                    kind=ChangeKind.GRANT_REVOKED,
                    classification="safe",
                    location=location,
                    message=(
                        f"On {qname}, role {role} lost column privileges"
                        f" {revoked_str} on column {column!r}."
                    ),
                    before_sql=None,
                    after_sql=None,
                )
            )

        if added_privs:
            added_str = ", ".join(sorted(added_privs))
            if role == "PUBLIC" and not head_table.rls_enabled:
                changes.append(
                    Change(
                        kind=ChangeKind.GRANT_PUBLIC_NO_RLS,
                        classification="dangerous",
                        location=location,
                        message=(
                            f"On {qname}, role PUBLIC gained {added_str}"
                            f" on column {column!r} of a table with no RLS"
                            " — every connected role can read that column"
                            " for every row."
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
                            f"On {qname}, role {role} gained column"
                            f" privileges {added_str} on column {column!r}."
                        ),
                        before_sql=None,
                        after_sql=None,
                    )
                )

    return changes


def _privileges_by_role(grants: Any) -> dict[str, set[str]]:
    """Union each role's privileges across every `Grant` row for that role."""
    out: dict[str, set[str]] = {}
    for g in grants:
        out.setdefault(g.role, set()).update(g.privileges)
    return out


def _privileges_by_column_key(
    grants: Any,
) -> dict[tuple[str, str], set[str]]:
    """Union each `(role, column)`'s privileges across every `ColumnGrant`."""
    out: dict[tuple[str, str], set[str]] = {}
    for g in grants:
        out.setdefault((g.role, g.column), set()).update(g.privileges)
    return out
