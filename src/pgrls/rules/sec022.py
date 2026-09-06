"""SEC022 — RLS-enabled table whose policies cover reads only.

When a table has RLS enabled and a working read policy, but every
policy is `FOR SELECT`, the table has no write-side coverage.
Postgres's RLS model is deny-by-default per command: a command is
permitted only if some policy's command list includes it. With
only `FOR SELECT` policies the write commands have no policy at
all, so for every non-owner role:

  * `INSERT` raises `new row violates row-level security policy`.
  * `UPDATE` and `DELETE` silently match zero rows — no error, no
    effect. The application sees a successful statement that
    changed nothing.

That asymmetry — INSERT erroring loudly, UPDATE / DELETE failing
silently — makes a forgotten write policy easy to miss in
development and painful to diagnose in production.

This is often a genuine mistake: the author wrote the read
policies and never added the write ones. But it is also a
perfectly valid intentional design — a table that is read-only for
the RLS-controlled roles, with writes performed by a privileged
role that owns the table or carries `BYPASSRLS`. pgrls cannot tell
the two apart, so SEC022 is **info** severity: a "did you mean
this?" nudge, not a hard finding. Allowlist the table when the
read-only surface is intentional.

Detection is command-based. SEC022 fires when a table has
`rls_enabled`, at least one policy, at least one *permissive*
policy, and *no* policy whose command covers a write — `FOR ALL`,
`FOR INSERT`, `FOR UPDATE`, or `FOR DELETE`. A single `FOR ALL`
policy (of any kind) counts as write coverage and silences the
rule; permissive-vs-restrictive write-grant semantics are
deliberately not analysed beyond the one check below — that
complexity belongs in a stricter rule, not a narrow info nudge.

The permissive requirement matters: a table whose policies are
*all* restrictive has no working read access either — the
permissive group is empty, so every row is filtered out and even
`SELECT` returns nothing. That is a different finding (SEC012's
"restrictive-only policy set"), and flagging it as a read-only
table would be both redundant and mis-framed, so SEC022 stays
quiet and leaves it to SEC012.

Out of scope (intentional):

* **Zero-policy tables.** RLS on with no policy at all is
  deny-everything — a different signal (deny-by-default), not
  "read-only coverage". SEC022 requires at least one policy.
* **Restrictive-only tables.** No permissive policy means reads
  are denied too; that is SEC012's surface (see above).
* **RLS-disabled tables.** SEC001's surface.
* **Partition members.** Any table that is itself a partition —
  at any level of a multi-level partition hierarchy — is skipped.
  A partition's writes normally route through the partition root,
  whose policies govern them — but only for a write that NAMES the
  parent; a direct child write is governed by the child's own RLS
  (measured), which SEC041 covers. Flagging a partition for missing
  write policies it is not expected to carry would be a false
  positive. Only tables that are not themselves partitions
  (standalone tables and partition roots) are evaluated.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.violations import Severity, Violation

# Commands whose presence on any policy means the table has
# write-side coverage. `ALL` covers every command; the three write
# verbs cover themselves. A table carrying a policy with any of
# these is not a SEC022 finding. The only command left out is
# `SELECT` — a table whose every policy is `FOR SELECT` is exactly
# what SEC022 flags.
_WRITE_COVERING_COMMANDS = frozenset(
    {"ALL", "INSERT", "UPDATE", "DELETE"}
)


class SEC022:
    id: str = "SEC022"
    severity: Severity = "info"
    title: str = "RLS-enabled table has no write-side policy"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_table_ref_allowlist("SEC022", options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                continue
            # Any table that is itself a partition — at any level —
            # has its writes route through the partition root, whose
            # policies govern them. Flagging it for a missing write
            # policy it is not expected to carry would false-positive.
            # `partition_of` is set for every partition, leaf or
            # mid-level, so this skips the whole hierarchy below root.
            if table.partition_of is not None:
                continue
            if not table.policies:
                continue
            # No permissive policy → reads are denied too. That is
            # SEC012's "restrictive-only" finding, not a read-only
            # surface — leave it to SEC012 and stay quiet.
            if not any(
                policy.permissive for policy in table.policies
            ):
                continue
            # Any write-covering command on any policy means the
            # table's writes are not a SEC022 concern.
            if any(
                policy.command in _WRITE_COVERING_COMMANDS
                for policy in table.policies
            ):
                continue
            if table_in_allowlist(table, allowlist):
                continue
            out.append(self._violation(table))
        return out

    def _violation(self, table: Table) -> Violation:
        count = len(table.policies)
        policy_word = "policy" if count == 1 else "policies"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Table {table.qualified_name} has RLS enabled and "
                f"{count} {policy_word}, but every policy is FOR "
                "SELECT — no policy covers INSERT, UPDATE, or "
                "DELETE. With RLS enforced and no write-side "
                "policy, writes by non-owner roles are denied: "
                "INSERT raises a row-violates-policy error, while "
                "UPDATE and DELETE silently affect zero rows. If "
                "the table is meant to be read-only for these "
                "roles (writes done by a table-owning or BYPASSRLS "
                "role), allowlist it as "
                f"{table.qualified_name!r} in [lint.rules.SEC022]. "
                "Otherwise add a policy covering the write commands "
                "— a FOR ALL policy, or a FOR INSERT / UPDATE / "
                "DELETE policy."
            ),
            location=table.qualified_name,
        )
