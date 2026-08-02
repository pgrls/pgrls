"""SEC010 fixer — DROP a permissive policy that grants nothing.

SEC010 flags a policy clause that is the literal ``false``. The
**dual of the SEC031 fixer** (which drops a *restrictive* ``USING (true)``
no-op floor): a **permissive** policy whose access is constant-``false`` grants
nothing — permissive policies OR-combine, and ``… OR false`` adds no row, and a
``WITH CHECK (false)`` admits no write — so dropping it leaves the table's
effective RLS unchanged:

    DROP POLICY <name> ON <schema>.<table>;

With RLS enabled, a permissive ``USING (false)`` policy admits zero rows, which
is exactly what Postgres does with *no* permissive policy at all (default-deny);
and alongside other permissive policies the ``false`` one contributes nothing to
the OR. Either way the drop is behavior-preserving. The denial the author
*meant* belongs at the GRANT layer (``REVOKE … FROM role``), which the rule's
message already points at — but the dead policy itself is safe to remove.

**Never broadens — the security boundary.** A fixer must never widen access, so
the fixer drops a policy **only when it is provably inert on every axis the
policy governs** (a strict subset of what SEC010 reports):

* **RESTRICTIVE** constant-``false`` policies are **never** dropped. Restrictive
  policies AND-combine, so ``AND false`` is a hard *deny floor* — dropping it
  would *broaden* access. The fixer abstains; SEC010 still reports it.
* A **permissive** policy is dropped only when it grants no read *and* no write:

  - ``FOR SELECT`` / ``FOR DELETE``: inert iff ``USING`` is ``false`` (no
    write side).
  - ``FOR INSERT``: inert iff ``WITH CHECK`` is ``false`` (no ``USING`` side;
    an absent ``WITH CHECK`` is not constant-false → not dropped).
  - ``FOR UPDATE``: inert iff ``USING`` is ``false`` — no existing row is
    selectable to update, so no update happens regardless of ``WITH CHECK``.
  - ``FOR ALL``: inert iff ``USING`` is ``false`` (blocks read/update/delete)
    **and** ``WITH CHECK`` is absent or ``false`` (the INSERT path is gated by
    ``WITH CHECK``, falling back to ``USING`` when absent; a non-``false``
    ``WITH CHECK`` would still admit inserts, so the policy is *not* inert and
    is left for human review).

Like every fixer this is dry-run by default — review before ``--apply``. The
DROP re-emits no policy clause (``clauses`` is empty), so the clause-clobber
resolver leaves it untouched; separately, ``generate_fixes`` coordinates the
DROP fixers (``_DROP_FIXER_IDS``) so a sibling clause-ALTER (e.g. SEC020
mirroring ``WITH CHECK (false)``) never lands on a policy this drops, and a
policy is never dropped twice. Mirrors the SEC031 / HYG003 drop fixers.
"""
from __future__ import annotations

from typing import Any

from pgrls.ast_utils import is_literal_false
from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Policy, Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist

# A permissive policy clause grants nothing iff it is the literal `false`.
# `_WRITE_OPTIONAL` commands gate their INSERT path on WITH CHECK (falling back
# to USING when absent).
_READ_ONLY_COMMANDS = frozenset({"SELECT", "DELETE"})


def _is_inert_permissive(policy: Policy) -> bool:
    """True iff dropping this permissive policy removes no access at all.

    Read-side (USING) and write-side (WITH CHECK / USING fallback) must both be
    constant-false for the policy's command. Returns False for restrictive
    policies (a deny floor — never droppable) and for any policy that still
    grants something.
    """
    if not policy.permissive:
        return False
    command = (policy.command or "").upper()
    using_false = policy.using_ast is not None and is_literal_false(
        policy.using_ast
    )
    with_check_false = policy.with_check_ast is not None and is_literal_false(
        policy.with_check_ast
    )

    if command in _READ_ONLY_COMMANDS:
        # SELECT / DELETE: only USING gates access; no write side.
        return using_false
    if command == "INSERT":
        # Only WITH CHECK gates the insert (no USING). Absent WITH CHECK is not
        # constant-false, so it is not inert.
        return with_check_false
    if command == "UPDATE":
        # USING selects the rows to update; USING false → no row qualifies → no
        # update regardless of WITH CHECK.
        return using_false
    if command == "ALL":
        # Reads/updates/deletes blocked by USING (false); the INSERT path is
        # gated by WITH CHECK, falling back to USING when absent. Inert only
        # when the write side is also denied.
        if not using_false:
            return False
        return policy.with_check_ast is None or with_check_false
    return False


class SEC010Fixer:
    rule_id: str = "SEC010"

    def fix(self, schema: Schema, options: dict[str, Any]) -> list[Fix]:
        # Strict allowlist parsing (the parser SEC010 uses): a malformed
        # allowlist raises, surfaced by the `fix` CLI.
        skip = parse_policy_id_allowlist("SEC010", options)
        out: list[Fix] = []
        for table in schema.tables:
            for policy in table.policies:
                if not _is_inert_permissive(policy):
                    continue
                pid = policy_id(table, policy)
                if pid in skip:
                    continue
                out.append(self._fix(table.schema, table.name, policy.name))
        return out

    @staticmethod
    def _fix(schema: str, table: str, name: str) -> Fix:
        qtable = quote_qualified(schema, table)
        return Fix(
            rule_id="SEC010",
            location=f"{schema}.{table}.{name}",
            sql=f"DROP POLICY {quote_ident(name)} ON {qtable};",
            description=(
                f"Drop permissive policy {name!r} on {schema}.{table} — its "
                "constant-false clause grants nothing (permissive policies "
                "OR-combine, so it adds no access; with RLS on, that is the "
                "same default-deny as having no policy), so dropping it leaves "
                "access unchanged. If you meant to deny access, do it at the "
                "GRANT layer (REVOKE … FROM role), not as a policy."
            ),
        )
