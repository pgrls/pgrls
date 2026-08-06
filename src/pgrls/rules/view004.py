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
from pglast.ast import CommonTableExpr, Node

from pgrls.ast_utils import function_body_sql, extract_range_vars
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_view_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_qualified_view_allowlist('VIEW004', options)


def _cte_names(node: Any) -> set[str]:
    """Collect every CTE name (`WITH <name> AS …`) defined in `node`.

    A reference to a CTE parses as an *unqualified* RangeVar whose
    relname is the CTE name — it is NOT a base-table reference, and in
    Postgres a CTE name shadows a same-named table within its scope. A
    SECDEF function body `WITH "orders" AS (...) SELECT * FROM "orders"`
    reads the inline CTE, not the RLS-protected `public.orders`; without
    this guard the bare `orders` ref would be misattributed to every
    RLS-protected table sharing that bare name (a false positive, since
    bare refs over-report by design). Mirrors SEC025's CTE-shadow guard.
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


def _secdef_fn_leaks(
    secdef_fn: Any,
    fn_qname: str,
    rls_tables: set[tuple[str, str]],
    bare_table_to_qual: dict[str, list[tuple[str, str]]],
) -> set[str]:
    """RLS-protected tables a single SECDEF function overload reads.

    Returns the set of leaked-table qualified names (`schema.table`)
    found by parsing one overload's body and walking its range vars.
    Empty when the overload reads no RLS-protected table — and also
    on the two documented false-negative paths, each of which emits a
    stderr warning naming the overload before returning empty:

    * **non-SQL language** (PL/pgSQL etc.): pglast can't parse the
      body as a top-level statement, so the overload is skipped; and
    * **unparseable SQL** (dynamic SQL via `EXECUTE`, etc.).

    A qualified body ref (`schema.table`) is attributed only when it
    is itself RLS-protected. A bare ref (`"user"`) is attributed to
    every RLS-protected table sharing that bare name — over-reporting
    rather than under-attributing, because the body's effective
    target depends on the function's runtime search_path. The caller
    unions these sets across a function's overloads (and across a
    view's SECDEF calls) and flags the function if the union is
    non-empty.
    """
    # A per-overload display label: `fn(integer)` for v12+ snapshots
    # with `signature`, falling back to bare `fn` for older snapshots
    # where `signature == ""`. Keeps stderr messages informative when
    # overload-many.
    fn_display = (
        f"{fn_qname}({secdef_fn.signature})"
        if secdef_fn.signature
        else fn_qname
    )
    if secdef_fn.language != "sql":
        # PL/pgSQL and other non-SQL languages aren't parseable as a
        # top-level pglast statement. Emit a "non-SQL language"
        # warning so the user knows this overload wasn't analyzed,
        # then skip — the documented false-negative path.
        print(
            f"pgrls: warning: VIEW004 skipped "
            f"SECURITY DEFINER function {fn_display} "
            f"(language={secdef_fn.language!r}). "
            "pglast cannot parse non-SQL bodies as "
            "top-level statements; rule may have "
            "false negatives for this overload.",
            file=sys.stderr,
        )
        return set()
    try:
        parsed = pglast.parse_sql(function_body_sql(secdef_fn.body))
    except pglast.parser.ParseError:
        print(
            f"pgrls: warning: could not parse "
            f"SECURITY DEFINER function body for "
            f"{fn_display}. VIEW004 skipped for this "
            "overload (likely PL/pgSQL with dynamic "
            "SQL or non-SQL language). Original body "
            f"length: {len(secdef_fn.body)} chars",
            file=sys.stderr,
        )
        return set()
    if not parsed:
        return set()

    leaked: set[str] = set()
    # A SQL function body may have multiple statements (e.g.
    # `SELECT 1; SELECT * FROM secret;`). Walk every parsed RawStmt —
    # the leaking SELECT could be at any position.
    for raw_stmt in parsed:
        # CTE names defined within THIS statement shadow same-named
        # tables in its scope. Collect per-statement (not across the
        # whole body) so a CTE in one statement can't suppress a real
        # bare-ref leak in another — a security rule must not
        # under-attribute.
        cte_names = _cte_names(raw_stmt.stmt)
        range_vars = extract_range_vars(raw_stmt.stmt)
        for sname, tname in range_vars:
            if sname is not None:
                if (sname, tname) in rls_tables:
                    leaked.add(f"{sname}.{tname}")
            elif tname in cte_names:
                # An unqualified ref to a CTE defined in this statement —
                # Postgres resolves it to the CTE, not the base table.
                continue
            elif tname in bare_table_to_qual:
                for s, n in bare_table_to_qual[tname]:
                    leaked.add(f"{s}.{n}")
    return leaked


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

        # qname → list[SecdefFunction] for body lookup. Snapshot v12+
        # captures one entry per overload (the SECDEF SQL never had
        # SELECT DISTINCT — overloads were always separate rows;
        # v12 just made it explicit by adding the `signature` field).
        # Two overloads of the same qualified name can have different
        # bodies (one might read an RLS-protected table, another not);
        # a previous dict-comprehension `{q: f for f in ...}` was
        # last-wins on duplicate qnames, so VIEW004 would analyze only
        # the lex-last overload's body and miss leaks in the others.
        # Walking every overload's body per qname closes that gap.
        # Empty when the view's `security_definer_calls` references a
        # function we didn't introspect (e.g. lives in a schema outside
        # `--schemas` scope).
        secdef_bodies: dict[str, list[Any]] = {}
        for f in schema.security_definer_functions:
            secdef_bodies.setdefault(f.qualified_name, []).append(f)

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
            # view. A single function (across all its overloads) may
            # leak multiple tables; each appears as its own pair so
            # the message-format step can de-duplicate to a sorted-
            # comma-joined list per axis.
            leaked_fns: set[str] = set()
            leaked_tables: set[str] = set()
            for fn_qname in view.security_definer_calls:
                matching_fns = secdef_bodies.get(fn_qname, [])
                if not matching_fns:
                    # Function not introspected — skip silently. (This
                    # happens when a view's SECDEF call resolves to a
                    # function in a schema outside `--schemas`.)
                    continue
                # Walk EVERY overload's body for this qname (snapshot
                # v12+ captures one entry per overload). Any overload
                # that leaks an RLS table flags the function as a
                # leak. The unsuppressable PL/pgSQL / parse-error
                # warnings per overload are emitted (inside
                # `_secdef_fn_leaks`) once per (fn_qname, signature)
                # so the operator sees which specific overload wasn't
                # analyzed.
                fn_leaks: set[str] = set()
                for secdef_fn in matching_fns:
                    fn_leaks |= _secdef_fn_leaks(
                        secdef_fn,
                        fn_qname,
                        rls_tables,
                        bare_table_to_qual,
                    )
                if fn_leaks:
                    leaked_tables |= fn_leaks
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
