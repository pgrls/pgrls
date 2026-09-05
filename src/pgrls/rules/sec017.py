"""SEC017 — function with the LEAKPROOF attribute bypasses the RLS barrier.

A function marked `LEAKPROOF` carries a promise to the query planner:
it has *no side channels* — it will not reveal anything about its
arguments through an error message, through how long it runs, or
through any other observable behaviour. On the strength of that
promise the planner is allowed to evaluate the function *below* a
security barrier — ahead of a table's row-level security qual, ahead
of a `security_barrier` view's `WHERE`. A non-leakproof function, by
contrast, is held *above* the barrier and only ever sees rows the
caller is already entitled to.

That is the whole point of `LEAKPROOF`, and for a genuinely
side-channel-free function it is a safe, useful optimization. The
danger is a function that is *marked* `LEAKPROOF` but is not actually
leak-free. Applied to a column of an RLS-protected table, it runs on
**every** row — including rows the caller's policy would have hidden
— and any error it raises (or any argument-dependent timing it
exhibits) discloses those hidden rows' contents. The classic shape:

    SELECT * FROM rls_protected
    WHERE leaky_fn(secret_column) = 'probe';

If `leaky_fn` is `LEAKPROOF`, the planner may push `leaky_fn(
secret_column)` below the RLS qual; an attacker who cannot see those
rows still learns `secret_column` from the error text or response
time.

Marking a function `LEAKPROOF` requires superuser — it is always a
deliberate act, never a default. SEC017 flags **every** function in
the introspected schemas whose `pg_proc.proleakproof` is true, so
each one gets an explicit audit decision: confirm that no error path
and no timing channel can expose an argument, or remove the marking.
pgrls cannot make that determination itself — proving leakproofness
means reasoning about every error path and timing characteristic of
the body, exactly the brittle analysis the rule deliberately does
not attempt (the same stance SEC014 takes on SECDEF bodies).

Postgres's own built-in leakproof functions (the operators behind
`=`, `<`, and so on) live in `pg_catalog`, which is never part of
the linted `--schemas`, so they never surface here. What SEC017
reports is the user-defined functions a superuser chose to mark
`LEAKPROOF` — a deliberately small, high-signal set.

Detection is structural: walk `Schema.leakproof_functions` (captured
by introspection from `pg_proc.proleakproof = TRUE` since snapshot
v10). Allowlist entries are qualified function names
(`schema.function`). A bare function name is rejected — two
identically-named functions in different schemas would otherwise
both be silenced.

Severity: warning. Auto-fix: `pgrls fix` emits `ALTER FUNCTION
<schema>.<name>(<signature>) NOT LEAKPROOF` per flagged overload
(abstaining on a pre-v12 snapshot with an empty signature, or a pre-v14
snapshot without the separate schema/function-name fields). The other
remedy — establishing that the function genuinely is leakproof and
keeping the marking — is human judgement; allowlist it to take that path.

Relationship to the other attribute/audit rules: SEC014 and SEC015
flag `SECURITY DEFINER` functions (which run as their owner); SEC016
flags roles with the `BYPASSRLS` attribute (which skip RLS
entirely). SEC017 is the fourth such rule — `LEAKPROOF` is a
function attribute that relaxes *where* in the plan a function runs.
All four say "a privileged attribute is set here; confirm it is
intended."

Out of scope (intentional):

* **Body-level leak analysis.** SEC017 does not parse the function
  body to decide whether it actually leaks. A proof would have to
  enumerate every `RAISE`/error path and every data-dependent code
  path — brittle, and defeated by dynamic SQL the same way the
  body analysis VIEW004 documents false-negatives for is. The rule
  flags on the `proleakproof` flag alone and lets the operator
  allowlist the audited-safe functions.
* **Argument signatures.** The allowlist key is `schema.function`
  with no signature. Overloaded functions (`public.f(int)` vs
  `public.f(text)`) are collapsed to one finding and one allowlist
  entry — introspection captures each overload as its own row (so the
  fixer can target each signature) and SEC017 dedupes by qualified name
  when reporting. Audit every `LEAKPROOF` overload of a flagged
  name; operators needing per-overload granularity should
  `ALTER FUNCTION` one to a different name.
* **Cross-scope functions.** A `LEAKPROOF` function defined in a
  schema outside the introspector's ``--schemas`` set is invisible
  to SEC017 — `Schema.leakproof_functions` only carries what
  introspection captured. Expand ``--schemas`` to audit it.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import LeakproofFunction, Schema
from pgrls.rules._allowlist import parse_qualified_function_allowlist
from pgrls.violations import Severity, Violation


class SEC017:
    id: str = "SEC017"
    severity: Severity = "warning"
    title: str = "Function with LEAKPROOF attribute bypasses the RLS barrier"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_qualified_function_allowlist("SEC017", options)
        out: list[Violation] = []
        # Snapshot v12+ captures one `LeakproofFunction` entry per
        # overload (the `_LEAKPROOF_FUNCS_SQL` query dropped its
        # SELECT DISTINCT so a SEC017 fixer can target each overload
        # individually). The rule itself reports per qualified name
        # — the message names the function, not a specific overload
        # signature — so dedupe by qualified_name as we walk. This
        # preserves the pre-v12 message surface exactly: two
        # overloads of `public.fast_eq` produce ONE SEC017
        # violation, not two with identical text.
        #
        # `leakproof_functions` is captured in `(qname, signature)`
        # order at introspection time, so the first-seen overload
        # determines the captured entry's location; the order is
        # deterministic without a `sorted(...)` here.
        seen: set[str] = set()
        for fn in schema.leakproof_functions:
            if fn.qualified_name in allowlist:
                continue
            if fn.qualified_name in seen:
                continue
            seen.add(fn.qualified_name)
            out.append(self._violation(fn))
        return out

    def _violation(self, fn: LeakproofFunction) -> Violation:
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Function {fn.qualified_name} is marked LEAKPROOF. "
                "The planner treats a LEAKPROOF function as free of "
                "side channels and may evaluate it below a security "
                "barrier — before a table's row-level security "
                "policy filters rows, before a security_barrier "
                "view's WHERE. If the function is not genuinely "
                "leak-free — it raises an error that echoes an "
                "argument, or its running time depends on an "
                "argument value — an attacker can apply it to a "
                "column of an RLS-protected table "
                "(`WHERE leaky_fn(secret_column) = '...'`) and read "
                "rows their policy would hide, via the error message "
                "or the response timing. Marking a function LEAKPROOF "
                "requires superuser, so this is a deliberate "
                "assertion that pgrls cannot verify. Audit the "
                "function body: confirm no error path and no timing "
                "channel can expose an argument. If the leakproof "
                "claim does not hold, remove it — `ALTER FUNCTION "
                f"{fn.qualified_name}(<args>) NOT LEAKPROOF` (the "
                "argument types complete the signature). If the "
                "claim does hold, allowlist this function as "
                f"{fn.qualified_name!r} in [lint.rules.SEC017]."
            ),
            location=fn.qualified_name,
        )
