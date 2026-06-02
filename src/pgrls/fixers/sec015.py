"""SEC015 fixer — pin `pg_temp` last in a SECDEF function's search_path.

SEC015 flags a `SECURITY DEFINER` function whose effective search_path
does not end with an explicit `pg_temp` token. Postgres searches
`pg_temp` (the per-session writable temp schema) **first** for
relation / type names unless `pg_temp` is named in the path — at the
position written. A SECDEF function inheriting the caller's path, or
pinning a path that omits `pg_temp`, is exploitable: an attacker
creates a same-named object in their pg_temp, the function's
unqualified reference resolves to the attacker's object, and the
function executes attacker-controlled SQL as its owner
(CVE-2018-1058 and the whole search_path-shadowing family).

The mechanical fix is to pin `pg_temp` as the **last** token of the
function's `SET search_path` (Postgres resolves entries in
first-occurrence order, so the explicit final position forces
pg_temp to be searched last):

    ALTER FUNCTION <schema>.<name>(<signature>)
        SET search_path = <existing tokens minus pg_temp>, pg_temp;

For a function with no pinned path at all, we emit a minimal safe
default:

    ALTER FUNCTION <schema>.<name>(<signature>)
        SET search_path = pg_catalog, pg_temp;

This narrows the search to system catalog only — strictly tighter
than the caller's path, so the function's body references must be
either fully-qualified (`public.t`) or relative to pg_catalog. The
operator who needs a broader path (e.g. wanted the function to see
its own home schema unqualified) edits the generated SQL before
--apply; the description names this.

**Abstains** on:

* **Pre-v12 snapshots** — `signature == ""` because v3-v11
  introspection didn't capture argument types. A bare
  `ALTER FUNCTION name()` would target only the zero-arg overload,
  wrong for every function with arguments. Operator re-snapshots
  to populate signatures.
* **Quoted schema names containing literal commas** — the rule's
  tokenizer (and ours) is naive comma-split, which shreds tokens
  for a path like `"My, Schema", public`. The rule explicitly
  documents this limitation. Rather than emit a wrong fix, the
  fixer abstains when it detects both `"` and `,` in the raw GUC
  string. The narrow case where this triggers spuriously (a quoted
  schema name without internal commas) is acceptable noise —
  operator can audit by hand.

Per-overload emission mirrors SEC017: snapshot v12 captures one
`SecdefFunction` entry per overload with its `signature`, and each
overload needs its own `ALTER FUNCTION`.

Allowlist: `[lint.rules.SEC015].allowlist` is a list of qualified
function names (`schema.function`). An entry silences every overload.
"""
from __future__ import annotations

from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_function_allowlist
from pgrls.rules.sec015 import _is_pg_temp_safe


def _safe_to_rewrite(search_path: str) -> bool:
    """Detect the documented quoted-comma corner case the naive
    comma-split tokenizer can't handle. A search_path containing
    both `"` and `,` *might* be a quoted schema with an inner
    comma; the fixer abstains rather than emit a wrong rewrite.

    Conservative: a path like `"weird_schema", public` (no inner
    comma in the quoted name) also abstains. That's a false-negative
    on rewrite, never a false-positive — the operator simply runs
    the rule's allowlist or hand-fixes the function. Better than
    silently rewriting `"My, Schema"` → `My, Schema, pg_temp` and
    losing the original schema.
    """
    return not ('"' in search_path and ',' in search_path)


def _rewritten_path(existing: str | None) -> str:
    """Build the safe search_path string.

    `None` → `pg_catalog, pg_temp` (minimal-but-safe default; any
    function relying on a broader caller path needs operator review,
    which the description prompts).

    Non-`None` → strip any pg_temp tokens from the existing path
    (preserving case for the rest), then append `, pg_temp` so it's
    pinned last with exactly one occurrence — the structurally safe
    shape `_is_pg_temp_safe` requires.
    """
    if existing is None:
        return "pg_catalog, pg_temp"
    # Naive comma-split + case-preserving filter. The caller has
    # already verified `_safe_to_rewrite(existing)`, so we don't
    # need to defend against quoted commas here.
    tokens: list[str] = []
    for raw in existing.split(","):
        tok = raw.strip()
        if not tok:
            continue
        # Match pg_temp case-insensitively (Postgres GUC token
        # comparison is case-insensitive for built-in schema names).
        if tok.lower() == "pg_temp":
            continue
        tokens.append(tok)
    tokens.append("pg_temp")
    return ", ".join(tokens)


class SEC015Fixer:
    rule_id: str = "SEC015"

    def fix(
        self, schema: Schema, options: dict[str, Any]
    ) -> list[Fix]:
        # Strict allowlist parsing — same parser SEC015 uses.
        allowlist = parse_qualified_function_allowlist(
            "SEC015", options
        )
        out: list[Fix] = []
        for fn in schema.security_definer_functions:
            if fn.qualified_name in allowlist:
                continue
            # Mirror SEC015's detection: only flag when the path
            # isn't already pg_temp-safe. The fixer is a strict
            # subset of what the rule reports.
            if _is_pg_temp_safe(fn.search_path):
                continue
            # Abstain on pre-v12 snapshots — empty signature would
            # produce `ALTER FUNCTION name()` targeting the wrong
            # overload. Operator re-snapshots to populate.
            if not fn.signature:
                continue
            # Abstain on pre-v14 snapshots — schema_name/function_name
            # were not captured, and splitting the ambiguous
            # qualified_name targets the wrong object when the schema
            # name contains a dot. Live introspection always sets
            # these; operator re-snapshots an older baseline to populate.
            if not fn.schema_name or not fn.function_name:
                continue
            # Abstain on quoted-comma schema names the naive
            # tokenizer can't safely rewrite.
            if (
                fn.search_path is not None
                and not _safe_to_rewrite(fn.search_path)
            ):
                continue
            out.append(
                self._fix(
                    fn.qualified_name,
                    fn.schema_name,
                    fn.function_name,
                    fn.signature,
                    fn.search_path,
                )
            )
        return out

    @staticmethod
    def _fix(
        qualified_name: str,
        schema_name: str,
        function_name: str,
        signature: str,
        original_path: str | None,
    ) -> Fix:
        # schema_name / function_name are captured as separate fields
        # (snapshot v14+) precisely so the fixer never splits the
        # ambiguous `qualified_name` (`nspname || '.' || proname`),
        # which yields the wrong schema/function when either component
        # contains a dot (e.g. a schema named `a.b`). Route each
        # component through `quote_qualified` so a name like `Order` /
        # `a.b` / a reserved keyword still produces valid server SQL.
        qident = quote_qualified(schema_name, function_name)
        new_path = _rewritten_path(original_path)
        return Fix(
            rule_id="SEC015",
            location=f"{qualified_name}({signature})",
            sql=(
                f"ALTER FUNCTION {qident}({signature}) "
                f"SET search_path = {new_path};"
            ),
            description=(
                f"Pin pg_temp as the last entry of "
                f"{qualified_name}({signature})'s search_path so "
                "Postgres searches it last for relation / type "
                "names, blocking the pg_temp shadowing escalation "
                "path. "
                + (
                    "Defaults to `pg_catalog, pg_temp` — minimal and "
                    "safe. If the function's body needs unqualified "
                    "names from another schema (e.g. its home schema), "
                    "edit the generated SQL to insert the schema "
                    "BEFORE pg_temp."
                    if original_path is None
                    else "Preserves the existing search_path entries "
                    "and pins pg_temp at the end (any earlier "
                    "pg_temp occurrences are stripped so pg_temp is "
                    "searched LAST, exactly once)."
                )
                + " Other overloads of the same function are remediated "
                "separately by their own Fix. If the function body "
                "fully-qualifies every object reference (search_path "
                "is moot), keep it and allowlist "
                f"'{qualified_name}' in [lint.rules.SEC015]."
            ),
        )
