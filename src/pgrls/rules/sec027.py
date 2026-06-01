"""SEC027 — RLS table has a principal column no policy scopes by.

Row-Level Security isn't only about tenant isolation. Within a
single tenant, rows are still often *per-user*: a user's drafts,
private uploads, direct messages, personal settings. The
discriminator there is an owner / user column, not `tenant_id`.

SEC027 is the under-scoping nudge for that case. It fires when a
table has RLS enabled, carries at least one policy, has a column
whose name looks like a principal identity (`owner`, `owner_id`,
`user_id` by default), and **no policy references that column** in
its `USING` or `WITH CHECK`. The typical shape:

```sql
CREATE TABLE documents (id uuid, tenant_id int, owner_id uuid, body text);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON documents
    USING (tenant_id = current_setting('app.tenant')::int);
```

The policy scopes by tenant, so cross-tenant reads are blocked —
but every user *within* a tenant can read every other user's rows,
because nothing keys on `owner_id`. If `documents` is meant to hold
per-user-private data, that's a leak; if it's a tenant-shared table
(a catalogue, a settings table where `owner_id` is just audit
provenance), it's intentional and you allowlist it.

pgrls cannot read that intent, so SEC027 is **info** severity — it
never fails CI by default. It's a "did you mean to scope this by
user too?" prompt, deliberately conservative:

* **Only flags tables that already have a policy.** A table with
  RLS on and *no* policy is SEC009's silent-deny-all surface, not
  this rule's.
* **Treats a column as "scoped" if any policy references it
  anywhere** — including inside a sub-select. This under-fires
  rather than over-fires: a membership-table join
  (`owner_id IN (SELECT ...)`) counts as scoping, so the rule stays
  quiet on the legitimate ACL pattern.
* **Default principal set is narrow** (`owner`, `owner_id`,
  `user_id`). Audit-style columns (`created_by`, `updated_by`,
  `author_id`) are *not* in the default set — they're usually
  provenance, not access boundaries — but a project that uses one
  as a real boundary can add it via
  `[lint.rules.SEC027].principal_columns`.

Configure the principal-column set (replaces the default):

```toml
[lint.rules.SEC027]
principal_columns = ["owner_id", "user_id", "created_by"]
```

Allowlist tables that are intentionally tenant-shared:

```toml
[lint.rules.SEC027]
allowlist = ["public.catalogue", "public.tenant_settings"]
```

Severity: info. No auto-fix — the remedy (add a per-user predicate,
or confirm the table is tenant-shared and allowlist it) is an
intent decision pgrls can't make.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import extract_column_refs
from pgrls.model import Schema, Table
from pgrls.rules._allowlist import parse_table_ref_allowlist, table_in_allowlist
from pgrls.violations import Severity, Violation

# Column names that, by default, denote a per-user access boundary
# rather than tenant scoping or audit provenance. Conservative on
# purpose — see the module docstring on why `created_by` et al. are
# excluded from the default set.
_DEFAULT_PRINCIPAL_COLUMNS: frozenset[str] = frozenset(
    {"owner", "owner_id", "user_id"}
)


def _parse_principal_columns(options: dict[str, Any]) -> set[str]:
    raw = options.get("principal_columns")
    if raw is None:
        return set(_DEFAULT_PRINCIPAL_COLUMNS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC027].principal_columns must be a list of "
            'column names (e.g. ["owner_id", "user_id"]).'
        )
    return set(raw)


def _columns_referenced_by_policies(table: Table) -> set[str]:
    """Bare column names referenced by ANY policy on the table.

    Collects the trailing element of every ColumnRef tuple across
    every policy's USING and WITH CHECK, INCLUDING refs inside
    sub-selects. Including sub-select refs is deliberate: a
    membership-table predicate like `owner_id IN (SELECT user_id
    FROM members WHERE ...)` should count `owner_id` as scoped, so
    the rule under-fires (stays quiet on a legitimate ACL join)
    rather than over-fires.
    """
    referenced: set[str] = set()
    for policy in table.policies:
        for ast in (policy.using_ast, policy.with_check_ast):
            if ast is None:
                continue
            for ref in extract_column_refs(ast):
                referenced.add(ref[-1])
    return referenced


class SEC027:
    id: str = "SEC027"
    severity: Severity = "info"
    title: str = "RLS table has a principal column no policy scopes by"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        principal_columns = _parse_principal_columns(options)
        allowlist = parse_table_ref_allowlist("SEC027", options)
        out: list[Violation] = []
        for table in schema.tables:
            # Needs RLS on, at least one policy (no-policy is SEC009),
            # and a captured column list (hand-built fixtures without
            # columns are skipped, like SEC005 / SEC018).
            if not table.rls_enabled:
                continue
            if not table.policies:
                continue
            if not table.columns:
                continue
            if table_in_allowlist(table, allowlist):
                continue

            present = [c for c in table.columns if c in principal_columns]
            if not present:
                continue

            referenced = _columns_referenced_by_policies(table)
            unscoped = [c for c in present if c not in referenced]
            if not unscoped:
                continue

            cols = ", ".join(repr(c) for c in sorted(unscoped))
            out.append(
                Violation(
                    rule_id="SEC027",
                    severity=self.severity,
                    title=self.title,
                    message=(
                        f"Table {table.qualified_name} has RLS enabled "
                        f"and a policy, but no policy references the "
                        f"principal column(s) {cols}. Rows are scoped "
                        "by whatever the policies do key on (often "
                        "tenant), so users that share that scope can "
                        "see each other's rows. If this table holds "
                        "per-user-private data, add a predicate keying "
                        f"on {cols}; if it is intentionally shared "
                        "(a catalogue, a tenant-wide settings table), "
                        "add it to [lint.rules.SEC027].allowlist."
                    ),
                    location=f"{table.schema}.{table.name}",
                )
            )
        return out
