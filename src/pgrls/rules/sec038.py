"""SEC038 — Semantic anonymous-read leak (Z3-backed Kleene 3VL).

A read-capable policy (FOR ALL or FOR SELECT) leaks to anonymous if its
USING predicate is provably, unconditionally TRUE for an unauthenticated
session — one where every auth-context function (auth.uid / auth.role /
auth.jwt, current_user, session_user, current_setting) returns NULL. Under
SQL three-valued (Kleene) logic a row is visible iff USING evaluates to
exactly TRUE; NULL and FALSE both hide the row. SEC038 proves the property
with Z3.

This is the *semantic* sibling of SEC004. SEC004 is purely syntactic — it
flattens OR disjuncts and matches the literal shape `auth_func() IS NULL`.
SEC038 catches the inverted-auth variants that shape misses:

    NOT (auth.uid() IS NOT NULL) OR <real check>   -- NOT-wrapped
    (auth.uid() IS NULL)::bool   OR <real check>   -- cast-wrapped
    (SELECT current_setting('app.user'))::uuid IS NULL OR <real check>

In each case, under an anonymous session the inverting disjunct is TRUE for
*every* row, so the policy reads all rows — the Lovable-CVE catastrophic
class. SEC004 stays the always-on, dependency-free guard; SEC038 is the
deeper check.

Firing criterion (zero-false-positive on the precision corpus): SEC038
fires iff USING, evaluated under an anonymous session with Kleene 3VL, is
VALID — TRUE for EVERY row assignment, i.e. `NOT(USING_anon is TRUE)` is
UNSAT. This provably leaves SAFE policies clean:

  * A tenant / owner predicate `col = (SELECT current_setting('app.x'))`
    becomes, under anon, `col = NULL` → Kleene U (not TRUE) → not valid →
    does NOT fire.
  * An inverted-auth disjunct `auth.uid() IS NULL OR real_check` becomes
    `TRUE OR real_check` → TRUE for all rows → valid → fires.
  * A narrow / intentional public carve-out (`col = <const> OR …`) is TRUE
    only for *some* rows → not valid → does NOT fire — no false positive on
    intentional public data.

Soundness over recall: any sub-expression that cannot be translated to the
3VL encoding makes the predicate's truth UNKNOWN, so validity cannot be
proven and SEC038 does NOT fire. A missed exotic leak is acceptable (SEC004
still guards syntactically); a false positive is not.

SEC038 uses the Z3 SMT solver, a core dependency since 0.16.0, so it runs
on a plain `pip install pgrls`. In the unusual case where z3 can't be
imported the rule NO-OPs — it returns no findings rather than guessing.

Because validity means "TRUE for every row", the proof artifact is "all
rows" — SEC038 reports an unconditional leak, not a single example row.

Configuration: `[lint.rules.SEC038]` accepts:

  - `auth_functions` (list[str]) — the function names treated as
    anonymous-NULL under an unauthenticated session. Replaces the default
    `["auth.uid", "auth.role", "auth.jwt", "current_user", "session_user",
    "current_setting"]`. Mirrors SEC004's option so the two rules stay
    consistent.
  - `allowlist` (list[str]) — `schema.table.policy` IDs to exempt
    (intentional public-data tables, audit fallbacks, etc.).
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, policy_id
from pgrls.rules._allowlist import parse_policy_id_allowlist
from pgrls.violations import Severity, Violation


_DEFAULT_AUTH_FUNCTIONS: frozenset[str] = frozenset({
    "auth.uid",
    "auth.role",
    "auth.jwt",
    "current_user",
    "session_user",
    "current_setting",
})


def _parse_auth_functions(options: dict[str, Any]) -> set[str]:
    raw = options.get("auth_functions")
    if raw is None:
        return set(_DEFAULT_AUTH_FUNCTIONS)
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise TypeError(
            "[lint.rules.SEC038].auth_functions must be a list of "
            "function names (qualified or bare), e.g. "
            '["auth.uid", "current_setting"]'
        )
    return set(raw)


def _format_message(policy: Any, table: Any, witness: dict[str, object]) -> str:
    head = (
        f"Policy {policy.name!r} on {table.qualified_name} leaks every row "
        "to an anonymous session. Under an unauthenticated connection every "
        "auth function (auth.uid(), auth.role(), current_setting(), …) "
        "returns NULL, and Z3 proves the USING predicate is then "
        "unconditionally TRUE for every row (three-valued / Kleene logic) — "
        "so the policy reads all rows."
    )
    # Under the v1 validity criterion the predicate is TRUE for *every*
    # row, so the honest artifact is "all rows" — the witness dict is
    # empty. The non-empty branch is dead for v1; it stays only for a
    # future "satisfiable read" criterion (amendment #6).
    if witness:
        pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
        artifact = (
            f" For example, a row with {{{pairs}}} is visible to an "
            "unauthenticated client."
        )
    else:
        artifact = (
            " Every row is visible unconditionally (the predicate is "
            "constant-true under anon — it pins no row column)."
        )
    fix = (
        " Gate the policy on a non-null auth check (e.g. "
        "`auth.uid() IS NOT NULL AND <tenant/owner check>`) or remove the "
        "inverting disjunct that admits anonymous. This is the semantic "
        "form of the SEC004 inverted-auth hole — see SEC004 for the "
        "syntactic variant."
    )
    return head + artifact + fix


class SEC038:
    id: str = "SEC038"
    severity: Severity = "error"
    title: str = (
        "Anonymous read leak (USING is unconditionally true for an "
        "unauthenticated session)"
    )

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        # Lazy import: the Z3 codepath is an optional extra, and the
        # rules package must stay import-dependency-free (mirrors how the
        # CLI imports the diff Z3 module lazily). When z3 is absent,
        # Z3_AVAILABLE is False and the rule NO-OPs (HARD CONSTRAINT).
        from pgrls.diff._z3_compare import (
            Z3_AVAILABLE,
            anon_read_counterexample,
        )

        if not Z3_AVAILABLE:
            return []

        auth_functions = _parse_auth_functions(options)
        allowlist = parse_policy_id_allowlist("SEC038", options)

        out: list[Violation] = []
        for table in schema.tables:
            for policy in table.policies:
                pid = policy_id(table, policy)
                if pid in allowlist:
                    continue
                # RESTRICTIVE policies can only narrow access — they can
                # never grant anonymous read on their own.
                if not policy.is_permissive:
                    continue
                # Only read-capable policies expose rows on SELECT.
                if policy.command not in ("ALL", "SELECT"):
                    continue
                if policy.using_ast is None:
                    continue
                witness = anon_read_counterexample(
                    policy.using_ast, auth_functions
                )
                if witness is None:
                    continue
                out.append(
                    Violation(
                        rule_id="SEC038",
                        severity="error",
                        title=self.title,
                        message=_format_message(policy, table, witness),
                        location=pid,
                    )
                )
        return out
