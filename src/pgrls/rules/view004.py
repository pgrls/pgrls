"""VIEW004 — view through SECDEF function reading RLS-protected table.

A view's body may call a SECURITY DEFINER function that, in turn, reads
from an RLS-protected table. Because the function runs with the function
owner's privileges (typically a privileged migration/admin role), RLS on
the underlying table is evaluated against the function owner — NOT the
calling user. This bypasses the per-tenant filter even when the *view*
itself is configured with `security_invoker = true` (VIEW001's defense),
because the bypass happens one frame deeper, inside the function call.

The two architectural fixes are mutually exclusive — pgrls can't pick:

* Re-write the function as INVOKER (drop SECURITY DEFINER). The function
  then runs with the caller's privileges and RLS applies normally.

* Document why the bypass is intentional (e.g. a system-level function
  that legitimately needs to see all rows for an aggregation/audit
  purpose) and allowlist the view via
  `[lint.rules.VIEW004].allowlist = ["schema.view"]`.

Hence: severity `warning`, no auto-fix. The rule's job is to surface the
implicit RLS bypass so the operator chooses one of the above explicitly.

Tolerance: the rule parses `pg_proc.prosrc` with pglast. Three
documented false-negative paths, each handled silently or with a
stderr warning:

1. **Non-SQL language** (PL/pgSQL with `DECLARE`/`BEGIN`, PL/Python,
   etc.): skipped with a stderr warning naming the function.
2. **Unparseable SQL** (e.g. dynamic SQL via `EXECUTE` constructed
   at runtime): skipped with a stderr warning naming the function.
3. **Cross-scope SECDEF function**: a view whose
   `security_definer_calls` resolves to a function NOT in the
   introspected `--schemas` set is skipped silently. The function
   exists somewhere on the database but pgrls hasn't read its body,
   so VIEW004 can't analyze it. To exercise the rule against such
   functions, expand `--schemas` to include the function's home
   schema.

These match the existing AST-based rule convention.
"""
from __future__ import annotations

import sys
from typing import Any

import pglast

from pgrls.ast_utils import extract_range_vars
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_view_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_qualified_view_allowlist('VIEW004', options)


class VIEW004:
    id: str = "VIEW004"
    severity: Severity = "warning"
    title: str = "View calls SECURITY DEFINER function that reads RLS-protected table"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        rls_tables: set[tuple[str, str]] = {
            (t.schema, t.name) for t in schema.tables if t.rls_enabled
        }
        if not rls_tables:
            # Nothing to leak — early-exit before parsing function bodies.
            return []

        # qname → SecdefFunction for body lookup. Empty when the view's
        # `security_definer_calls` references a function we didn't
        # introspect (e.g. lives in a schema outside `--schemas` scope).
        secdef_bodies = {
            f.qualified_name: f for f in schema.security_definer_functions
        }

        # Build bare-name → list-of-qualified mapping for table refs in
        # function bodies. `pg_proc.prosrc` may emit either form
        # depending on how the function was written. When two
        # RLS-protected tables in different schemas share a bare name
        # (e.g. `core.user` AND `staging.user`), a function body
        # `SELECT * FROM "user"` can't be unambiguously attributed —
        # the actual target depends on the search_path the function
        # ran with. We over-report rather than under-attribute: emit
        # all RLS-protected qualified candidates and let the operator
        # decide which one(s) actually leak. False negatives in a
        # security check are corrosive; false positives the operator
        # can dismiss via the allowlist. Iterate sorted so the message
        # ordering is deterministic across runs.
        bare_table_to_qual: dict[str, list[tuple[str, str]]] = {}
        for s, n in sorted(rls_tables):
            bare_table_to_qual.setdefault(n, []).append((s, n))

        out: list[Violation] = []
        for view in schema.views:
            if view.qualified_name in allowlist:
                continue
            if not view.security_definer_calls:
                continue

            # (function_qname, leaked_table_qname) pairs found for this
            # view. A single function may leak multiple tables; each
            # appears as its own pair so the message-format step can
            # de-duplicate to a sorted-comma-joined list per axis.
            leaked_fns: set[str] = set()
            leaked_tables: set[str] = set()
            for fn_qname in view.security_definer_calls:
                secdef_fn = secdef_bodies.get(fn_qname)
                if secdef_fn is None:
                    # Function not introspected — skip silently. (This
                    # happens when a view's SECDEF call resolves to a
                    # function in a schema outside `--schemas`.)
                    continue
                if secdef_fn.language != "sql":
                    # PL/pgSQL and other non-SQL languages aren't
                    # parseable as a top-level pglast statement. Emit
                    # a less-alarming "non-SQL language" warning so
                    # the user knows the function wasn't analyzed,
                    # then skip — the documented false-negative path.
                    print(
                        f"pgrls: warning: VIEW004 skipped SECURITY "
                        f"DEFINER function {fn_qname} "
                        f"(language={secdef_fn.language!r}). pglast "
                        "cannot parse non-SQL bodies as top-level "
                        "statements; rule may have false negatives "
                        "for this function.",
                        file=sys.stderr,
                    )
                    continue
                try:
                    parsed = pglast.parse_sql(secdef_fn.body)
                except pglast.parser.ParseError:
                    # Match `parse_expr`'s warning shape — name the
                    # function so the user can grep `pg_proc` for the
                    # actual SQL pglast couldn't handle.
                    print(
                        f"pgrls: warning: could not parse SECURITY "
                        f"DEFINER function body for {fn_qname}. "
                        "VIEW004 skipped for this function (likely "
                        "PL/pgSQL with dynamic SQL or non-SQL "
                        "language). Original body length: "
                        f"{len(secdef_fn.body)} chars",
                        file=sys.stderr,
                    )
                    continue
                if not parsed:
                    continue
                # A SQL function body may have multiple statements
                # (e.g. `SELECT 1; SELECT * FROM secret;`). Walk every
                # parsed RawStmt — the leaking SELECT could be at any
                # position.
                fn_leaks_a_table = False
                for raw_stmt in parsed:
                    range_vars = extract_range_vars(raw_stmt.stmt)
                    for sname, tname in range_vars:
                        if sname is not None:
                            if (sname, tname) in rls_tables:
                                leaked_tables.add(f"{sname}.{tname}")
                                fn_leaks_a_table = True
                        elif tname in bare_table_to_qual:
                            for s, n in bare_table_to_qual[tname]:
                                leaked_tables.add(f"{s}.{n}")
                            fn_leaks_a_table = True
                if fn_leaks_a_table:
                    leaked_fns.add(fn_qname)

            if not leaked_fns:
                continue

            fn_qnames_csv = ", ".join(sorted(leaked_fns))
            referenced_qnames_csv = ", ".join(sorted(leaked_tables))
            out.append(
                Violation(
                    rule_id="VIEW004",
                    severity="warning",
                    title=self.title,
                    message=(
                        f"View {view.qualified_name} calls SECURITY "
                        f"DEFINER function {fn_qnames_csv}, which "
                        f"reads RLS-protected {referenced_qnames_csv}. "
                        "The function bypasses RLS via the function "
                        "owner's privileges. Either re-write the "
                        "function as INVOKER, or document why the "
                        "bypass is intentional."
                    ),
                    location=view.qualified_name,
                )
            )
        return out
