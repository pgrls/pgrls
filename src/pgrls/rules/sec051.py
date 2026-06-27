"""SEC051 — Realtime-published table with RLS disabled (unfiltered broadcast).

In Supabase Realtime, a table added to the ``supabase_realtime`` publication has
its row changes streamed to subscribed clients over the Realtime websocket.
Realtime's "Postgres Changes" feature applies the table's RLS policies to each
change — evaluated as the *subscribed* role — before delivering it, but only
when RLS is **enabled**. A published table with RLS **off** has no policy to
apply, so every ``INSERT`` / ``UPDATE`` / ``DELETE`` is broadcast to every
subscriber verbatim, regardless of tenant — a side channel that bypasses the row
filtering the REST API would have enforced on the same table.

```sql
CREATE TABLE public.messages (id bigint, room_id uuid, body text);  -- RLS off
ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
-- Every connected client now receives every room's messages in real time.
```

SEC051 fires (warning) on a table that is a member of a Realtime publication
(default ``supabase_realtime``) and has ``ROW LEVEL SECURITY`` disabled.
Membership is resolved via ``pg_publication_tables`` at introspection time, so a
``FOR ALL TABLES`` or (PG15+) ``FOR TABLES IN SCHEMA`` publication is expanded,
not just explicit ``ADD TABLE`` members.

It is the Realtime-channel analog of [SEC001](#rule-sec001) (RLS disabled),
sharpened to name the broadcast consequence — much as [SEC049](#rule-sec049)
sharpens the PostgREST-read case. It deliberately co-fires with SEC001 (which
reports the bare RLS-off precondition); SEC051 is the ``warning`` that the
table's rows are *actively streamed* to subscribers.

Severity: warning. Scope / design (deliberately narrow, low-FP):

* **RLS-enabled tables are not flagged.** With RLS on, Realtime checks each
  change against the table's policies for the subscribed role, so the rows are
  filtered (this holds whether or not ``FORCE`` is set, since the subscriber is
  not the table owner). A permissive ``USING (true)`` policy that defeats that
  filtering is [SEC008](#rule-sec008)'s domain, not duplicated here.
* **Gated to Realtime publications.** Only the ``publications`` set (default
  ``["supabase_realtime"]``) is treated as broadcasting; a table in some other,
  non-Realtime logical-replication publication is not flagged. A database with
  no Realtime publication (the non-Supabase case) therefore produces no
  findings.
* Needs publication introspection (``pg_publication_tables``, snapshot v22+). On
  an offline ``--sql-file`` source — which cannot model ``CREATE PUBLICATION`` —
  the rule is reported as skipped rather than silently passing.

Configurable via ``[lint.rules.SEC051]``:

* ``publications`` — the publication names treated as Realtime broadcast
  channels (default ``["supabase_realtime"]``).
* ``allowlist`` — table ids (``schema.table``) deliberately broadcast without
  RLS (e.g. a public presence / heartbeat table), exempted from the rule.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, Table
from pgrls.rules._allowlist import (
    _list_of_strings,
    parse_table_ref_allowlist,
    table_in_allowlist,
)
from pgrls.violations import Severity, Violation

# Supabase's Realtime publication — the channel whose member tables stream row
# changes to subscribed clients.
_DEFAULT_PUBLICATIONS = ("supabase_realtime",)


def _parse_publications(options: dict[str, Any]) -> set[str]:
    raw = options.get("publications")
    if raw is None:
        return set(_DEFAULT_PUBLICATIONS)
    return set(
        _list_of_strings(
            "SEC051", raw, "publication names", option="publications"
        )
    )


class SEC051:
    id: str = "SEC051"
    severity: Severity = "warning"
    title: str = "Realtime-published table has RLS disabled (unfiltered broadcast)"

    def check(self, schema: Schema, options: dict[str, Any]) -> list[Violation]:
        publications = _parse_publications(options)
        allowlist = parse_table_ref_allowlist("SEC051", options)
        out: list[Violation] = []
        for table in schema.tables:
            if table.rls_enabled:
                continue  # RLS on → Realtime filters each change per policy
            member_of = sorted(set(table.in_publications) & publications)
            if not member_of:
                continue  # not a member of any Realtime publication
            if table_in_allowlist(table, allowlist):
                continue
            out.append(self._violation(table, member_of))
        return out

    def _violation(self, table: Table, publications: list[str]) -> Violation:
        pub_list = ", ".join(publications)
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Table {table.qualified_name} is a member of the Realtime "
                f"publication {pub_list} but has row level security disabled, "
                "so changes to every row are broadcast to all subscribed "
                "clients without row filtering — one tenant's row changes "
                "reach every subscriber. Enable RLS with a row-scoping policy "
                "(Realtime evaluates policies against each change once RLS is "
                "on), remove the table from the publication, or allowlist "
                f"{table.qualified_name!r} in [lint.rules.SEC051] if the "
                "broadcast is intentional."
            ),
            location=table.qualified_name,
        )
