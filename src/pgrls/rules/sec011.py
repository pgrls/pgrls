"""SEC011 — Policy expression has an `OR true` branch.

`x = 1 OR true` evaluates to `true` for every row — the `x = 1`
half is dead code. The shape commonly appears as a leftover debug
branch ("temporarily let everything through to test the data
model"), where the author never circles back to remove it.

SEC008 catches the literal `USING (true)` at the top level. SEC011
catches the same effect buried inside a larger expression: the
literal `true` ORed with anything else is still `true`, but a
casual reading misses the disjunction.

Detection is narrow on purpose — only the literal `true` A_Const
inside an OR-BoolExpr counts. Semantic equivalents (`1 = 1`,
`'a' = 'a'`, etc.) fall through to SEC005's "no own-column ref"
framing instead. A real tautology checker is significant
infrastructure for marginal real-world value.

Severity: warning. Allowlist by qualified policy ID.
"""
from __future__ import annotations

from typing import Any

from pglast.ast import BoolExpr, Node, SubLink
from pglast.enums import BoolExprType

from pgrls.ast_utils import is_literal_true
from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


def _parse_allowlist(options: dict[str, Any]) -> set[str]:
    return parse_policy_id_allowlist('SEC011', options)


def _has_or_true(node: Any) -> bool:
    """True if any OR-BoolExpr in the policy's predicate has a
    literal-true arg.

    Does NOT descend into `SubLink.subselect` — an `OR true` in a
    subquery's WHERE doesn't make the outer policy admit every row;
    it makes the subquery return its rows. Walking the subselect
    would produce false positives on legitimate
    `EXISTS (SELECT 1 FROM t WHERE flag OR true)` patterns. We do
    walk `SubLink.testexpr` (the LHS of `IN`/`ANY`/`ALL`) since
    that's the policy's own expression. Mirrors the shape of
    `extract_column_refs(exclude_sublinks=True)`.
    """
    if node is None:
        return False
    if isinstance(node, SubLink):
        return _has_or_true(node.testexpr)
    if isinstance(node, BoolExpr) and node.boolop == BoolExprType.OR_EXPR:
        for arg in node.args or ():
            if is_literal_true(arg):
                return True
    if isinstance(node, Node):
        for field_name in node:
            value = getattr(node, field_name, None)
            if isinstance(value, (list, tuple)):
                for item in value:
                    if _has_or_true(item):
                        return True
            elif isinstance(value, Node):
                if _has_or_true(value):
                    return True
    return False


class SEC011:
    id: str = "SEC011"
    severity: Severity = "warning"
    title: str = "Policy expression has an `OR true` branch"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = _parse_allowlist(options)
        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                if not (
                    _has_or_true(policy.using_ast)
                    or _has_or_true(policy.with_check_ast)
                ):
                    continue
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC011",
                        severity="warning",
                        title=self.title,
                        message=(
                            f"Policy {policy.name!r} on "
                            f"{table.qualified_name} has an `OR true` "
                            "branch — the predicate admits rows it "
                            "was never meant to. At the top level that "
                            "is EVERY row; under `AND` it widens one "
                            "conjunct, and under `NOT` it inverts to a "
                            "constant FALSE (measured on one table: 3 "
                            "rows, 1 row and 0 rows). Almost always a "
                            "leftover debug branch. Remove the `OR "
                            "true` or, if the intent is genuinely "
                            "'admit every row,' drop the policy and "
                            "rely on RLS-disabled (note `REVOKE ALL` "
                            "does the OPPOSITE — it denies access "
                            "denial)."
                        ),
                        location=pid,
                    )
                )
        return out
