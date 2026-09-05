"""SEC013 — Trigger on RLS-protected table can bypass policies.

A trigger fires as the table's OWNER, not as the role that ran the
statement. Any SELECT/INSERT/UPDATE/DELETE inside the trigger function
body therefore sees the owner's view of the database — every row,
RLS bypassed — even when the invoking role has policies that would
hide or reject those rows directly.

The bypass is silent: no SQLSTATE 42501 surfaces, no error in the
log. A multi-tenant table protected by `WHERE tenant_id =
current_setting('app.tenant_id')` looks impregnable until a BEFORE
INSERT trigger written for an unrelated purpose (denormalization,
audit logging, cache invalidation) cross-references another tenant's
data with the same logic and quietly leaks it into the invoking
session's view.

Examples of the silent leak in practice:

* Audit trigger writes `(NEW.id, current_setting('app.tenant_id'),
  (SELECT count(*) FROM the_table))` into an audit table. The
  subquery runs as owner and counts every tenant's rows.
* Trigger that "syncs" a derived column reads from a peer table with
  no tenant filter, exposing peer-tenant values through the synced
  column.
Detection is structural: every user-authored, enabled trigger on an
RLS-enabled table gets a warning. The rule can't read the trigger
function body (PL/pgSQL bodies aren't parseable by pglast as
top-level statements, and `SECURITY INVOKER` doesn't change the
trigger-fires-as-owner contract — `pg_proc.prosecdef` is irrelevant
here), so the warning is intentionally a prompt-to-audit rather
than a proof of leak. Internal triggers (foreign-key check helpers,
partition-routing triggers, RI plumbing) are filtered at the
introspection layer via `pg_trigger.tgisinternal = false`.
User-authored `CREATE CONSTRAINT TRIGGER` rows (`tgconstraint != 0`
but `tgisinternal = false`) are NOT filtered — deferred constraint
triggers still fire as the table owner and present the same RLS
bypass surface as any other AFTER trigger.

Out of scope in v0.5.8: INSTEAD OF triggers on views
(``relkind = 'v'``) and triggers on foreign tables
(``relkind = 'f'``). See docs/RULES.md#rule-sec013 for the full
rationale; operators in those situations should audit the
relevant triggers manually until follow-up rules land.

Severity: warning. Allowlist by qualified trigger ID
(`schema.table.trigger_name`) once the operator has audited the
function body and confirmed it doesn't escalate privilege or leak
data. Bare `trigger_name` is rejected because two tables can carry
identically-named triggers (Postgres scopes trigger names per
table); a name-only allowlist would silence both, and the cross-
table collision can be subtle.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table, Trigger
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    # The shape `schema.table.trigger_name` mirrors the policy-ID
    # allowlist (SEC003, SEC005, SEC006, ...). Reuse the helper —
    # it validates three non-empty parts and right-anchors the
    # rightmost split so a quoted identifier with a literal `.` in
    # the name still parses correctly.
    return parse_policy_id_allowlist("SEC013", options)


class SEC013:
    id: str = "SEC013"
    severity: Severity = "warning"
    title: str = "Trigger on RLS-protected table can bypass policies"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            if not table.rls_enabled:
                # Triggers on RLS-disabled tables aren't bypassing
                # anything — the policies don't apply in the first
                # place. SEC001 covers the "RLS off" case.
                continue
            for trigger in table.triggers:
                if not trigger.enabled:
                    # Disabled triggers can't fire under any
                    # session_replication_role; they're still in the
                    # snapshot so a re-enable surfaces as a diff,
                    # but they don't represent an active bypass
                    # path right now.
                    continue
                trigger_id = (
                    f"{table.schema}.{table.name}.{trigger.name}"
                )
                if trigger_id in allowlist:
                    continue
                out.append(self._violation(table, trigger))
        return out

    def _violation(self, table: Table, trigger: Trigger) -> Violation:
        trigger_id = f"{table.schema}.{table.name}.{trigger.name}"
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Table {table.qualified_name} has RLS enabled but trigger "
                f"{trigger.name!r} ({trigger.timing} {trigger.event}) "
                f"calls function {trigger.function_qualified_name}. "
                "Triggers fire as the table owner — any SELECT, "
                "INSERT, UPDATE, or DELETE inside the function body "
                "bypasses the invoker's RLS policies and sees / "
                "modifies every tenant's data. Audit the function "
                "body to confirm it doesn't read from peer tables "
                "without a tenant filter, doesn't write data the "
                "caller couldn't write directly, and doesn't echo "
                "owner-visible data back to the caller through "
                "derived columns or RAISE messages. Allowlist this "
                f"trigger as {trigger_id!r} in [lint.rules.SEC013] "
                "once the audit is complete."
            ),
            location=trigger_id,
        )
