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
            # bare `ALTER FUNCTION name()` would target the zero-
            # arg overload, wrong for every function with arguments.
            # The operator re-snapshots to populate signatures.
            if not fn.signature:
                continue
            out.append(self._fix(fn.qualified_name, fn.signature))
        return out

    @staticmethod
    def _fix(qualified_name: str, signature: str) -> Fix:
        return Fix(
            rule_id="SEC017",
            # Location combines qname + signature so per-overload
            # Fix objects sort deterministically and the dry-run
            # report distinguishes them.
            location=f"{qualified_name}({signature})",
            sql=(
                f"ALTER FUNCTION {qualified_name}({signature}) "
                "NOT LEAKPROOF;"
            ),
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
