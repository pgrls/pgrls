"""Shared `ALTER VIEW … SET (<reloption> = true)` fixer factory.

VIEW001 and VIEW002 both remediate an RLS-leaking view by flipping a
single boolean reloption to `true` via one `ALTER VIEW` statement per
offending view. They differ only in four parameters:

* the reloption name (`security_invoker` / `security_barrier`),
* the `View` attribute whose truthiness means "already set" (so the
  view is skipped),
* the rule id, and
* the human-readable description.

Everything else — the materialized-view skip (VIEW003's domain), the
allowlist parse + match, the "references an RLS-protected table" filter,
the identifier quoting, and the `Fix` shape — is identical. This factory
captures the shared body once; each rule's module instantiates it with
its four parameters, so the two fixers can never drift.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_view_allowlist


def alter_view_reloption_fixer(
    *,
    rule_id: str,
    reloption: str,
    attr: str,
    description: Callable[[str, str], str],
) -> type:
    """Build a fixer class that sets `reloption = true` on leaking views.

    `attr` is the `View` field consulted to decide a view already has
    the option (truthy → skip). `description` receives
    `(view.qualified_name, leaked_qnames)` and returns the `Fix`
    description text — the one place the two rules' wording diverges.
    """

    class _AlterViewReloptionFixer:
        # Set as a class attribute below (after the class is built) so
        # both `VIEW00xFixer.rule_id` and `VIEW00xFixer().rule_id`
        # resolve — matching the hand-written fixers' class-level
        # `rule_id: str = "VIEW00x"` and the `Fixer` Protocol.
        rule_id: str

        def fix(
            self, schema: Schema, options: dict[str, Any]
        ) -> list[Fix]:
            # Strict allowlist parsing (the same parser the rule uses):
            # a malformed allowlist raises, surfaced by the `fix` CLI.
            allowlist = parse_qualified_view_allowlist(rule_id, options)
            rls_tables: set[tuple[str, str]] = {
                (t.schema, t.name) for t in schema.tables if t.rls_enabled
            }
            out: list[Fix] = []
            for view in schema.views:
                # Mirror the rule's detection in lockstep.
                if view.is_materialized:
                    continue
                if getattr(view, attr):
                    continue
                if view.qualified_name in allowlist:
                    continue
                leaked = sorted(
                    ref for ref in view.references if ref in rls_tables
                )
                if not leaked:
                    continue
                qname = quote_qualified(view.schema, view.name)
                leaked_qnames = ", ".join(f"{s}.{n}" for s, n in leaked)
                sql = f"ALTER VIEW {qname} SET ({reloption} = true);"
                out.append(
                    Fix(
                        rule_id=rule_id,
                        location=view.qualified_name,
                        sql=sql,
                        description=description(
                            view.qualified_name, leaked_qnames
                        ),
                    )
                )
            return out

    _AlterViewReloptionFixer.rule_id = rule_id
    return _AlterViewReloptionFixer
