"""SEC050 — Supabase Storage policy not scoped to a bucket (cross-bucket access).

In Supabase Storage, *all* object access is enforced by RLS policies on the
single table ``storage.objects``; the bucket a row belongs to is the
``bucket_id`` column. Supabase's own guidance is explicit: "your RLS policy
must explicitly specify the ``bucket_id`` condition … preventing cross-bucket
access." A permissive policy that authorizes by owner or path but **omits a
``bucket_id`` predicate** therefore applies uniformly to *every* bucket — a
caller authorized for one bucket can read (or write) objects in another.

```sql
-- FOOTGUN: scopes by the per-user folder but not the bucket, so it authorizes
-- that folder in EVERY bucket, not just `avatars`.
CREATE POLICY user_files ON storage.objects FOR SELECT TO authenticated
    USING ((storage.foldername(name))[1] = auth.uid()::text);

-- SAFE: the bucket_id predicate confines it to one bucket.
CREATE POLICY user_files ON storage.objects FOR SELECT TO authenticated
    USING (bucket_id = 'avatars'
           AND (storage.foldername(name))[1] = auth.uid()::text);
```

SEC050 fires (warning) once per permissive ``storage.objects`` policy whose
**row-reach clause** — the ``USING`` of a SELECT/UPDATE/DELETE/ALL policy, the
``WITH CHECK`` of an INSERT policy — has a non-trivial predicate that does not
reference ``bucket_id``. (Checking the row-reach clause specifically catches an
``ALL`` policy that scopes the bucket only in ``WITH CHECK`` while its ``USING``
reads across every bucket; the converse — bucket-scoped ``USING`` with an
unscoped ``WITH CHECK`` — is a cross-bucket *write* footgun left to recall.)
It is deliberately narrow to stay low-FP:

* A literal ``USING (true)`` / ``WITH CHECK (true)`` is ceded to
  [SEC008](#rule-sec008) / [SEC006](#rule-sec006) (the "admits everything"
  rules) — this rule targets the subtler case of a policy that *does* scope by
  something, just not by bucket.
* If any **restrictive** policy on ``storage.objects`` constrains ``bucket_id``,
  the table is bucket-floored regardless of the permissive policies, so SEC050
  stays silent.
* It only looks at ``storage.objects`` (the Supabase convention), so a database
  with no ``storage`` schema produces no findings. ``storage.buckets``
  (bucket-level RLS) is out of scope for this v1.

Any reference to the table's own ``bucket_id`` is taken as bucket-aware. A
*non-confining* mention (``bucket_id IS NOT NULL``) is therefore a deliberate
accepted false negative: detecting only confining equality forms would over-fit
and raise FP risk across the many legitimate shapes (``bucket_id = ANY(...)``,
``IN (SELECT …)``, ``= current_setting(...)`` — and ``IN`` is normalised to
``= ANY(ARRAY[...])`` by ``pg_get_expr``).

Pure rule logic over already-captured policy data — no introspection or snapshot
change. No auto-fix (pgrls cannot know the intended bucket). Allowlist a policy
id in ``[lint.rules.SEC050]`` for a deliberately single-bucket or cross-bucket
deployment.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import extract_column_refs, is_literal_true, own_column_ref
from pgrls.model import Policy, Schema, Table
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation

_STORAGE_SCHEMA = "storage"
_STORAGE_OBJECTS = "objects"
_BUCKET_COLUMN = "bucket_id"


def _references_bucket_id(ast: Any, table: Table) -> bool:
    """Does the predicate reference ``storage.objects``'s own ``bucket_id``?

    Resolves each ref against the table's own columns (`own_column_ref` handles
    bare / `objects.bucket_id` / `storage.objects.bucket_id`, and rejects a
    *different* table's `b.bucket_id`), and skips sublinks — so a `bucket_id`
    column belonging to some other table reached through a subquery (e.g.
    ``EXISTS (SELECT 1 FROM buckets b WHERE b.bucket_id = …)``) does NOT count
    as confining the policy's own rows.
    """
    if ast is None:
        return False
    return any(
        own_column_ref(ref, table) == _BUCKET_COLUMN
        for ref in extract_column_refs(ast, exclude_sublinks=True)
    )


def _policy_scopes_bucket(policy: Policy, table: Table) -> bool:
    """The policy mentions own ``bucket_id`` in either clause → bucket-aware."""
    return _references_bucket_id(
        policy.using_ast, table
    ) or _references_bucket_id(policy.with_check_ast, table)


def _command_clause(policy: Policy) -> Any:
    """The clause whose predicate gates which bucket's rows the command reaches.

    INSERT is gated by ``WITH CHECK``; every other command's row reach is gated
    by ``USING``.
    """
    if policy.command == "INSERT":
        return policy.with_check_ast
    return policy.using_ast


class SEC050:
    id: str = "SEC050"
    severity: Severity = "warning"
    title: str = "Storage policy not scoped to a bucket (cross-bucket access)"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC050", options)
        out: list[Violation] = []
        for table in schema.tables:
            if not (
                table.schema == _STORAGE_SCHEMA
                and table.name == _STORAGE_OBJECTS
            ):
                continue
            if _BUCKET_COLUMN not in table.columns:
                # Without the column list, a `bucket_id` reference cannot be
                # resolved to an own column, so every policy would look
                # unscoped. This happens offline when a ``--sql-file`` lints
                # only ``CREATE POLICY ON storage.objects`` with no
                # ``CREATE TABLE`` (the table is extension-managed in Supabase).
                # Abstain rather than false-positive — fail-closed; the rule
                # still fires against a live database or a captured snapshot,
                # where ``storage.objects``'s columns are always populated.
                continue
            # A restrictive bucket_id floor confines the whole table to a
            # bucket regardless of the permissive policies — not cross-bucket.
            if any(
                (not p.permissive) and _policy_scopes_bucket(p, table)
                for p in table.policies
            ):
                continue
            for policy in table.policies:
                if not policy.permissive:
                    continue
                # Check the clause that gates which bucket's rows this command
                # reaches: USING for read/affect (SELECT/UPDATE/DELETE/ALL),
                # WITH CHECK for INSERT. (A policy that scopes bucket only in
                # the *other* clause still leaks on its row-reach side.)
                clause = _command_clause(policy)
                if clause is None:
                    continue  # nothing to analyze
                if is_literal_true(clause):
                    continue  # SEC008 / SEC006 territory
                if _references_bucket_id(clause, table):
                    continue  # the row-reach clause scopes bucket
                pid = f"{table.qualified_name}.{policy.name}"
                if pid in allowlist:
                    continue
                out.append(self._violation(table, policy, pid))
        return out

    def _violation(
        self, table: Table, policy: Policy, pid: str
    ) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                f"({policy.command}) authorizes object access but its predicate "
                f"references no {_BUCKET_COLUMN} condition, so it applies to "
                "every bucket — a caller authorized for one bucket can reach "
                "objects in another. Scope the policy with a "
                f"`{_BUCKET_COLUMN} = '<bucket>'` predicate, or allowlist "
                f"{pid!r} in [lint.rules.SEC050] if cross-bucket access is "
                "intended."
            ),
            location=pid,
        )
