"""SEC025 — policy predicate references a table that has RLS disabled.

A row-level security policy on table `T` often gates row visibility
on *another* table `T'` — typically a membership / ACL / lookup
table reached through a sub-select:

    CREATE POLICY tenant_scope ON public.documents
        USING (
            tenant_id IN (
                SELECT tenant_id FROM public.team_members
                WHERE user_id = current_setting('app.user_id', true)::int
            )
        );

The row-level isolation on `documents` is only as strong as the
isolation on `team_members`. If `team_members` itself does **not**
have RLS enabled, every column of it is freely readable (and, if
the role has INSERT, freely writable) by the same role. An
attacker who can write to `team_members` can grant themselves
access to `documents` — the policy honours the row they planted.

SEC025 fires when a policy's `USING` or `WITH CHECK` expression
references another table whose `rls_enabled` is false. The check
is a cross-reference over the schema, not an AST pattern: walk
the parsed policy expression for `RangeVar` nodes (table
references in sub-selects / `FROM` clauses), look up each one in
the introspected schema, and report the ones whose RLS is off.

Severity: warning. The pattern is sometimes intentional — a
read-only reference table (countries, currencies, plan types,
feature flags) that every tenant is meant to read. Allowlist by
qualified policy ID (`schema.table.policy_name`) when the
cross-table read is deliberate.

What SEC025 flags — and what it deliberately does not:

* **Flagged:** a policy whose `USING` / `WITH CHECK` references —
  in a sub-select, a JOIN, anywhere `RangeVar` reaches — a table
  whose `rls_enabled` is false within the introspected schema set.
* **Not flagged — self-references.** A policy on `t` that
  references `t` itself inherits the same RLS gate (its own
  policies apply transitively), so self-references are skipped.
* **Not flagged — views.** Views do not carry an `rls_enabled`
  flag — their security model is `security_invoker` /
  `security_barrier`, which is VIEW001 / VIEW002's surface —
  so SEC025 stops at the table boundary rather than guess at a
  view's effective isolation.
* **Not flagged — out-of-scope references.** A reference to a
  table outside `--schemas` is not in the introspected set;
  pgrls cannot know its RLS state and would not have a
  reliable signal. The conservative call is silence — widen
  `--schemas` to include the dependent schema for SEC025 to see
  it. (System catalogs — `pg_catalog.*` — are similarly skipped
  by default because they are never introspected.)

Out of scope (intentional):

* **Predicate-implication analysis.** SEC025 does not try to
  prove that the cross-table reference *would* leak (e.g., that
  the sub-select's `WHERE` clause already constrains `T'` to
  the same tenant). The structural reference alone is the
  signal; allowlist a policy whose cross-table read is
  intentionally safe.
* **Function references.** A policy that calls a `SECURITY
  DEFINER` function reading another RLS-off table is a separate
  surface (SEC014 / VIEW004 — the function bypasses the
  caller's RLS by design). SEC025 inspects table references
  only.
* **Write-side enforcement.** SEC025 does not gate against an
  attacker writing to `T'`; it surfaces the structural
  dependency so the operator can decide whether `T'` needs RLS
  too, or whether writes to `T'` are themselves locked down via
  `GRANT` / a separate workflow.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import CommonTableExpr, Node

from pgrls.ast_utils import extract_range_vars
from pgrls.model import Policy, Schema, Table, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _resolve_table_ref(
    schema_name: str | None,
    rel_name: str,
    own_schema: str,
    table_map: dict[tuple[str, str], bool],
    view_set: set[tuple[str, str]],
) -> tuple[str, str] | None:
    """Resolve a `RangeVar` (schema?, name) against the schema.

    Returns the qualified `(schema, name)` if the reference is a
    *table* in the introspected set (not a view, not out of scope);
    returns None when the reference cannot be resolved or names a
    view — those are out of SEC025's surface.

    Unqualified names are resolved against the policy's own schema
    first. A name that doesn't match a known table there could
    live in another schema not in `--schemas`; SEC025 stays silent
    rather than guessing.
    """
    if schema_name is None:
        if (own_schema, rel_name) in table_map:
            schema_name = own_schema
        else:
            return None
    qualified = (schema_name, rel_name)
    if qualified in view_set:
        return None
    if qualified in table_map:
        return qualified
    return None


def _cte_names(node: Any) -> set[str]:
    """Collect every CTE name (`WITH <name> AS …`) defined in `node`.

    A reference to a CTE parses as an *unqualified* RangeVar whose
    relname is the CTE name — it is NOT a base-table reference, and in
    Postgres a CTE name shadows a same-named table within its scope.
    SEC025 must therefore not resolve such a ref to a same-named
    RLS-disabled table (the false positive). Collecting names across
    the whole predicate is a safe over-approximation: the only effect
    is to not flag an unqualified ref that matches a CTE name, which is
    exactly the ref Postgres resolves to the CTE anyway.
    """
    names: set[str] = set()

    def walk(n: Any) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, CommonTableExpr):
            ctename = getattr(n, "ctename", None)
            if isinstance(ctename, str) and ctename:
                names.add(ctename)
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(node)
    return names


class SEC025:
    id: str = "SEC025"
    severity: Severity = "warning"
    title: str = (
        "Policy predicate references a table that has RLS disabled"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_policy_id_allowlist("SEC025", options)
        table_map: dict[tuple[str, str], bool] = {
            (t.schema, t.name): t.rls_enabled for t in schema.tables
        }
        view_set: set[tuple[str, str]] = {
            (v.schema, v.name) for v in schema.views
        }
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                # Resolve each clause INDEPENDENTLY: a CTE is scoped to
                # the clause that defines it. USING and WITH CHECK are
                # separate expression scopes in Postgres, so a CTE in
                # one must NOT shadow a base-table reference in the
                # other — unioning the CTE names across both clauses
                # (the previous behavior) silently suppressed a real
                # RLS-disabled-table reference in the sibling clause, a
                # security false negative. Mirrors VIEW004's
                # per-statement CTE discipline.
                unprotected: set[str] = set()
                for ast in (policy.using_ast, policy.with_check_ast):
                    if ast is not None:
                        unprotected |= self._unprotected_in_clause(
                            ast, table, table_map, view_set
                        )
                if not unprotected:
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(
                    self._violation(
                        table, policy, pid, sorted(unprotected)
                    )
                )
        return out

    @staticmethod
    def _unprotected_in_clause(
        ast: Any,
        table: Table,
        table_map: dict[tuple[str, str], bool],
        view_set: set[tuple[str, str]],
    ) -> set[str]:
        """RLS-disabled tables a SINGLE policy clause references.

        CTE names are collected from THIS clause only, so an unqualified
        ref matching a CTE defined in the same clause is treated as the
        CTE (Postgres resolves it there) and skipped — but a CTE defined
        in a *different* clause never suppresses it.
        """
        cte_names = _cte_names(ast)
        unprotected: set[str] = set()
        for ref_schema, ref_name in extract_range_vars(ast):
            # An unqualified ref whose name matches a CTE defined in
            # this clause is a CTE reference, not a base table — skip
            # it. It would otherwise resolve to a same-named
            # RLS-disabled table (a false positive); Postgres resolves
            # it to the CTE.
            if ref_schema is None and ref_name in cte_names:
                continue
            resolved = _resolve_table_ref(
                ref_schema, ref_name, table.schema, table_map, view_set,
            )
            if resolved is None:
                continue
            # A self-reference (policy on T referencing T) inherits the
            # same RLS gate — its own policies apply transitively, so
            # skip it.
            if resolved == (table.schema, table.name):
                continue
            if not table_map[resolved]:
                unprotected.add(f"{resolved[0]}.{resolved[1]}")
        return unprotected

    def _violation(
        self,
        table: Table,
        policy: Policy,
        pid: str,
        unprotected: list[str],
    ) -> Violation:
        if len(unprotected) == 1:
            phrase = f"table {unprotected[0]}, which has"
        else:
            phrase = (
                f"tables {', '.join(unprotected)}, which have"
            )
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Policy {policy.name!r} on {table.qualified_name} "
                f"references {phrase} RLS disabled. The row-level "
                "isolation on this table is only as strong as the "
                "isolation on the referenced table(s): every row is "
                "freely readable (and, if the role has INSERT, "
                "freely writable) there, so an attacker who can "
                "write to the referenced table can grant themselves "
                "access through this policy. Enable RLS on the "
                "referenced table(s), or — if the cross-table read "
                "is intentional (a read-only reference table such "
                "as countries / currencies / plan types every "
                "tenant is meant to read) — allowlist this policy "
                f"as {pid!r} in [lint.rules.SEC025]."
            ),
            location=pid,
        )
