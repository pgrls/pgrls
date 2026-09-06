"""SEC017 fixer — emit `ALTER FUNCTION ... NOT LEAKPROOF` per overload.

SEC017 flags a function marked `LEAKPROOF`. The planner trusts a
LEAKPROOF promise and may evaluate the function below a security
barrier (ahead of an RLS qual, ahead of a security_barrier view's
WHERE) — so a wrongly-LEAKPROOF function applied to an RLS-protected
column runs on rows the caller cannot see and any error / timing it
exhibits leaks those rows' contents. The mechanical fix is the
inverse `ALTER FUNCTION`:

    ALTER FUNCTION <schema>.<name>(<signature>) NOT LEAKPROOF;

Snapshot v12+ captures one `LeakproofFunction` entry per overload
with its `signature` (the `pg_get_function_identity_arguments` output
that `ALTER FUNCTION` requires), so the fixer emits ONE Fix per
overload — distinct from how SEC017 itself reports per qualified
name (deduping across overloads in its message surface). Two
overloads of the same function both need un-marking; a single
`ALTER FUNCTION` cannot reach both.

**Abstains on pre-v12 snapshots.** A `SecdefFunction` /
`LeakproofFunction` loaded from a pre-v12 snapshot has `signature
= ""` because the older introspection query did not capture it.
Emitting `ALTER FUNCTION name() NOT LEAKPROOF` would target the
**zero-argument** overload — wrong for every function that actually
has arguments. The fixer detects the empty signature and skips with
no Fix; the operator re-snapshots against a live database (v12+) to
populate signatures, then re-runs `pgrls fix`. A skipped function
is not silently fixed wrong; the operator sees fewer fixes than
SEC017 violations and knows to re-snapshot.

Allowlist semantics mirror the rule: `[lint.rules.SEC017].allowlist`
is a list of qualified function names (`schema.function`). An entry
silences EVERY overload (the allowlist key is the qualified name —
the operator who allowlists `audit.redact` accepts every overload's
LEAKPROOF marking, not just the one they happened to see in the
report).

The other remedy SEC017 documents — proving the function genuinely
is leakproof and keeping the marking — is operator judgment, out of
scope for an auto-fix. The Fix description points at it.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_function_allowlist


class SEC017Fixer:
    rule_id: str = "SEC017"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing — same parser SEC017 uses; a
        # malformed allowlist raises TypeError, surfaced by `pgrls
        # fix` as a tool error.
        allowlist = parse_qualified_function_allowlist(
            "SEC017", options
        )
        out: list[Fix] = []
        for fn in schema.leakproof_functions:
            if fn.qualified_name in allowlist:
                continue
            # Abstain on pre-v12 snapshots — signature is "" and a
            # Abstain only when the signature was NOT CAPTURED (a v4-v11
            # snapshot). An EMPTY signature is a real value — a zero-argument
            # function — and `ALTER FUNCTION name()` targets it exactly.
            if fn.signature is None:
                continue
            # Abstain on pre-v14 snapshots — schema_name/function_name
            # were not captured, and splitting the ambiguous
            # qualified_name targets the wrong object when the schema
            # name contains a dot. Live introspection always sets these.
            if not fn.schema_name or not fn.function_name:
                continue
            out.append(
                self._fix(
                    fn.qualified_name,
                    fn.schema_name,
                    fn.function_name,
                    fn.signature,
                )
            )
        return out

    @staticmethod
    def _fix(
        qualified_name: str,
        schema_name: str,
        function_name: str,
        signature: str,
    ) -> Fix:
        # schema_name / function_name are captured as separate fields
        # (snapshot v14+). Splitting the ambiguous `qualified_name`
        # (`nspname || '.' || proname`) targets the wrong object when
        # the schema name contains a dot, so use the components
        # directly. Route each through `quote_qualified` so a function
        # or schema named `Order` / `a.b` / a reserved keyword still
        # produces valid SQL. The `signature` side already comes from
        # `pg_get_function_identity_arguments` (server-formatted).
        qident = quote_qualified(schema_name, function_name)
        return Fix(
            rule_id="SEC017",
            # Location keeps the un-quoted human form — the
            # operator-facing dry-run report shouldn't grow ``"…"``
            # noise unless a name actually needed it. The SQL is
            # the source of truth for execution.
            location=f"{qualified_name}({signature})",
            sql=f"ALTER FUNCTION {qident}({signature}) NOT LEAKPROOF;",
            description=(
                f"Remove the LEAKPROOF marking from "
                f"{qualified_name}({signature}). The planner will "
                "stop evaluating it below the RLS / security_barrier "
                "qual, eliminating the side-channel leak vector. "
                "Other overloads of the same function are remediated "
                "separately by their own Fix. If the function is "
                "genuinely leakproof (audited for error/timing side "
                "channels) and the marking is load-bearing for plan "
                "performance, keep it and allowlist "
                f"'{qualified_name}' in [lint.rules.SEC017]."
            ),
        )
