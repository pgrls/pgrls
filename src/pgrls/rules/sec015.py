"""SEC015 — SECURITY DEFINER function exposed to pg_temp shadowing.

A `SECURITY DEFINER` function runs as its owner. When the function
body references a relation or data type (a table, view, sequence,
or type) by an *unqualified* name, Postgres resolves that name
against the function's effective `search_path`. If `pg_temp` — the
per-session temporary schema, writable by every connected role —
can be searched *before* the schema the legitimate object lives in,
an attacker
creates a same-named object in their session's `pg_temp` and the
privileged function silently resolves to the attacker's object
instead. The function then executes attacker-controlled SQL with the
owner's privileges: the classic Postgres privilege-escalation chain
(CVE-2018-1058 and the whole family of "search_path" advisories).

The danger is the default. Postgres searches `pg_temp` **first** —
before even `pg_catalog` — for relation and type names *unless*
`pg_temp` is named explicitly in `search_path`, in which case it's
searched at the written position. So:

* A SECDEF function with **no** `SET search_path` clause inherits the
  *caller's* search_path. The caller is the attacker; `pg_temp` is
  implicitly first. **Unsafe.**
* A SECDEF function with `SET search_path = pg_catalog, public` (the
  common "pin it" attempt) still leaves `pg_temp` implicitly first —
  it isn't named, so the default applies. **Unsafe.**
* A SECDEF function with `SET search_path = …, pg_temp` — `pg_temp`
  named explicitly as the **last** entry — forces the temp schema to
  be searched last. **Safe.** This is the pattern the Postgres docs
  prescribe for SECURITY DEFINER functions.

SEC015 therefore fires on every SECDEF function whose effective
search_path does not end with an explicit `pg_temp` token. The fix is
mechanical — append `pg_temp` to the function's `SET search_path` (or
add the clause if absent) — but it isn't auto-applied: rewriting the
clause needs the function's full argument signature for the
`ALTER FUNCTION name(argtypes) SET search_path = …` statement, and
introspection captures `proname` without `proargtypes`. The operator
runs the `ALTER FUNCTION` by hand, or allowlists the function after
confirming its body fully-qualifies every object reference (in which
case `search_path` is moot).

Relationship to the other SECDEF rules: SEC014 flags every SECDEF
function as a generic audit surface; VIEW004 flags the view-mediated
RLS-bypass path; SEC013 the trigger-mediated path. SEC015 is
narrower and sharper than SEC014 — it doesn't say "audit this," it
says "this specific function has an exploitable search_path and here
is the one-line fix."

Severity: warning. Allowlist by qualified function name
(`schema.function`); a bare name is rejected (two same-named
functions in different schemas would both be silenced).

Out of scope (intentional):

* **Body-level qualification analysis.** A SECDEF function with an
  unsafe search_path but a body that fully-qualifies every reference
  (`SELECT * FROM public.t`, never bare `t`) is not actually
  exploitable. SEC015 doesn't parse the body to prove that — it
  flags on the search_path shape alone and lets the operator
  allowlist the audited-safe cases. Rationale: a body-qualification
  proof is exactly the brittle AST analysis VIEW004 documents
  false-negatives for (dynamic SQL, PL/pgSQL `EXECUTE`); a
  structural search_path check has no false negatives.
* **Cross-scope functions.** A SECDEF function in a schema outside
  the introspector's ``--schemas`` set is invisible to SEC015 (it
  isn't in `Schema.security_definer_functions`). Expand ``--schemas``
  to audit it.
"""
from __future__ import annotations

from typing import Any

from pgrls.model import Schema, SecdefFunction
from pgrls.rules._allowlist import parse_qualified_function_allowlist
from pgrls.violations import Severity, Violation


def _search_path_tokens(search_path: str) -> list[str]:
    """Split a `search_path` GUC value into normalized schema tokens.

    The value is comma-separated (`pg_catalog, public, pg_temp`).
    Each token is whitespace-trimmed, surrounding double quotes
    stripped (`"My Schema"` → `My Schema`), and lower-cased so the
    `pg_temp` comparison is case-insensitive. Empty tokens (from a
    trailing comma or an entirely empty value) are dropped.

    Known limitation: a quoted schema name containing a literal
    comma (`"My, Schema"`) is shredded by the naive comma split.
    This does not affect SEC015's verdict — the rule checks
    whether `pg_temp` is the sole, final token (see
    `_is_pg_temp_safe`), and a comma can't appear inside the bare
    `pg_temp` identifier, so a shredded quoted name can never
    spuriously become — or duplicate — a `pg_temp` token. The
    intermediate tokens for such a path are unreliable, but the
    safe/unsafe decision is not. Comma-in-schema-name is rare
    enough that a full quote-aware tokenizer isn't worth the
    complexity here.
    """
    out: list[str] = []
    for raw in search_path.split(","):
        tok = raw.strip()
        if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
            tok = tok[1:-1]
        tok = tok.strip().lower()
        if tok:
            out.append(tok)
    return out


def _is_pg_temp_safe(search_path: str | None) -> bool:
    """True iff `search_path` forces `pg_temp` to be searched last.

    The only structurally-safe shape: a pinned search_path in which
    `pg_temp` appears *exactly once*, as the *final* token. `None`
    (no clause) and any pinned path that doesn't end with `pg_temp`
    (including the empty string `''`) leave `pg_temp` implicitly
    first for relation lookups — unsafe.

    The exactly-once requirement matters: Postgres resolves
    search_path entries in *first-occurrence* order, so a path like
    `pg_temp, public, pg_temp` is searched `pg_temp`-first despite
    the trailing duplicate — still exploitable. Checking only the
    last token would mis-report that as safe.
    """
    if search_path is None:
        return False
    tokens = _search_path_tokens(search_path)
    if not tokens:
        return False
    return tokens[-1] == "pg_temp" and tokens.count("pg_temp") == 1


class SEC015:
    id: str = "SEC015"
    severity: Severity = "warning"
    title: str = "SECURITY DEFINER function exposed to pg_temp shadowing"

    def check(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Violation]:
        allowlist = parse_qualified_function_allowlist("SEC015", options)
        out: list[Violation] = []
        # Snapshot v12+ captures one `SecdefFunction` entry per
        # overload. The rule reports per qualified name — the message
        # names the function, not a specific overload — so dedupe by
        # qualified_name as we walk. Same shape as SEC014 / SEC017.
        # In practice all overloads of a function share the same
        # `proconfig` (search_path is set with `ALTER FUNCTION` per
        # overload but is rarely set differently); the rare case
        # where one overload is safe and another isn't reports the
        # first-encountered unsafe overload — the allowlist (per
        # qualified name) silences the whole function anyway, so the
        # operator who hits this allowlists or hand-fixes both. The
        # paired SEC015 fixer emits a per-overload ALTER FUNCTION,
        # so the FIX surface retains overload granularity even
        # though the rule surface dedupes.
        seen: set[str] = set()
        for fn in schema.security_definer_functions:
            if fn.qualified_name in allowlist:
                continue
            if _is_pg_temp_safe(fn.search_path):
                continue
            if fn.qualified_name in seen:
                continue
            seen.add(fn.qualified_name)
            out.append(self._violation(fn))
        return out

    def _violation(self, fn: SecdefFunction) -> Violation:
        if fn.search_path is None:
            state = (
                "pins no search_path, so it inherits the caller's "
                "search_path — attacker-controlled, with pg_temp "
                "searched first"
            )
        else:
            state = (
                f"sets search_path to {fn.search_path!r}, which does "
                "not end with an explicit pg_temp token — so pg_temp "
                "is still searched ahead of the listed schemas for "
                "relation and type names"
            )
        return Violation(
            rule_id=self.id,
            severity=self.severity,
            title=self.title,
            message=(
                f"Function {fn.qualified_name} is SECURITY DEFINER and "
                f"{state}. An attacker can create a same-named table, "
                "view, or type in their session's pg_temp schema; the "
                "function — running as its owner — resolves an "
                "unqualified reference to the attacker's object and "
                "executes attacker-controlled SQL with the owner's "
                "privileges. Fix: append pg_temp as the last entry of "
                "the function's search_path — keep every schema the "
                "function already needs and add pg_temp after them, "
                "e.g. `ALTER FUNCTION "
                f"{fn.qualified_name}(<args>) SET search_path = "
                "<existing schemas>, pg_temp` — naming pg_temp "
                "explicitly last forces it to be searched last. If "
                "the function body already fully-qualifies every "
                "object reference, the search_path is moot; audit "
                "the body and allowlist this function as "
                f"{fn.qualified_name!r} in [lint.rules.SEC015]."
            ),
            location=fn.qualified_name,
        )
