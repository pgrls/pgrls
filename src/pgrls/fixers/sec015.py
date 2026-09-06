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
        SET search_path = pg_catalog, <the function's own schema>, pg_temp;

The own schema is included for a SECURITY reason: `pg_catalog,
pg_temp` alone looks tighter but leaves the hole open, because an
unqualified name the body reads is not in pg_catalog and resolution
falls through to pg_temp — which the attacker writes (measured). A
body that reads unqualified names from a THIRD schema still needs
that schema added before pg_temp, or the references fully qualified;
the operator who needs that edits the generated SQL before
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

import re
from typing import Any

from pgrls.fixers import Fix
from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema
from pgrls.rules._allowlist import parse_qualified_function_allowlist
from pgrls.rules.sec015 import _is_pg_temp_safe

# A search_path entry is safe to splice verbatim into `SET search_path =
# …` only if it cannot carry statement-terminating punctuation or a
# comment. Two benign shapes:
#   * a bare SQL identifier — letters/digits/underscore/`$`, not starting
#     with a digit (covers `public`, `pg_catalog`, `pg_temp`); and
#   * the special `$user` placeholder.
# A double-quoted identifier (`"My Schema"`, `"$user"`) is handled
# separately — the surrounding quotes neutralize any interior
# punctuation, so a `;` inside quotes names a schema rather than ending
# the statement.
_BARE_PATH_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _is_safe_path_token(tok: str) -> bool:
    """True iff `tok` is a benign search_path element (see above)."""
    if tok == "$user":
        return True
    if _BARE_PATH_TOKEN.match(tok):
        return True
    # Double-quoted identifier: opens and closes with `"`, and every
    # interior `"` is doubled (`""`).
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        body = tok[1:-1]
        # Reject a zero-length delimited identifier — `""` (or a token
        # that is only doubled quotes) — which Postgres rejects as
        # "zero-length delimited identifier". The unescaped body, with
        # each `""` collapsed to a single `"`, must be non-empty.
        if not body.replace('""', '"'):
            return False
        # Strip the doubled quotes, then the remainder must contain no
        # lone `"` — otherwise the closing quote is spurious and
        # punctuation after it would be unquoted SQL.
        return '"' not in body.replace('""', "")
    return False


def _safe_to_rewrite(search_path: str) -> bool:
    """Whether the fixer can safely rebuild this search_path.

    Two abstain conditions, both conservative (a false-negative on
    rewrite is harmless — the operator allowlists or hand-fixes the
    function — while a wrong/unsafe rewrite is not):

    1. **Quoted-comma ambiguity.** A path containing both `"` and `,`
       *might* be a quoted schema with an inner comma the naive
       comma-split would mis-tokenize. Abstain (so `"My, Schema",
       public` is never silently flattened to `My, Schema, pg_temp`).
       A path like `"weird_schema", public` (no inner comma) also
       abstains — acceptable over-caution.

    2. **Unsafe token (snapshot trust boundary).** A snapshot's
       `proconfig` is replayed into the emitted `ALTER FUNCTION … SET
       search_path = …`. A poisoned value such as
       `public; DROP TABLE t; --` would otherwise be spliced verbatim.
       Abstain unless every comma-token is a benign identifier
       (`_is_safe_path_token`). Live introspection always yields
       well-formed tokens, so this only ever rejects a hand-edited /
       tampered snapshot.
    """
    if '"' in search_path and ',' in search_path:
        return False
    for raw in search_path.split(","):
        tok = raw.strip()
        if not tok:
            continue
        if not _is_safe_path_token(tok):
            return False
    return True


def _rewritten_path(existing: str | None, own_schema: str | None = None) -> str:
    """Build the safe search_path string.

    `None` → `pg_catalog, <the function's own schema>, pg_temp`.

    The function's own schema is in there for a SECURITY reason, not a
    convenience one. `pg_catalog, pg_temp` looks tighter but leaves the
    hole open: an unqualified name the body reads is not in `pg_catalog`,
    so resolution falls through to `pg_temp` — which the ATTACKER writes.
    Measured on PG16 with a SECDEF function reading an unqualified
    `secrets`: under `pg_catalog, pg_temp` a planted `pg_temp.secrets`
    was read (`ATTACKER`), and under `pg_catalog, <own schema>, pg_temp`
    the real table was (`real`). Since pgrls reports SEC015 resolved
    after applying its own fix, the tighter-looking default would have
    signed off on a still-exploitable function.

    Non-`None` → strip any pg_temp tokens from the existing path
    (preserving case for the rest), then append `, pg_temp` so it's
    pinned last with exactly one occurrence — the structurally safe
    shape `_is_pg_temp_safe` requires.
    """
    if existing is None:
        return (
            f"pg_catalog, {quote_ident(own_schema)}, pg_temp"
            if own_schema
            else "pg_catalog, pg_temp"
        )
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
        # Quote on emit any BARE token that is not a valid unquoted
        # identifier — a reserved keyword (`order`, `user`, `select`) or
        # the `$user` placeholder (bare `$user` is a syntax error). All
        # are accepted by _is_safe_path_token (so _safe_to_rewrite did not
        # abstain), but splicing them verbatim into `SET search_path = …`
        # produces unrunnable DDL that, under fix --apply's single
        # transaction, rolls back every other fix. quote_ident is minimal
        # (leaves `public`/`pg_catalog` bare, emits `"order"` / `"$user"`),
        # so the common output is unchanged. An already-double-quoted
        # token (`"My Schema"`, which _is_safe_path_token also accepts) is
        # left verbatim — re-quoting it would double the quotes.
        if not (tok.startswith('"') and tok.endswith('"')):
            tok = quote_ident(tok)
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
        new_path = _rewritten_path(original_path, schema_name)
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
                    "Defaults to `pg_catalog, <the function's own "
                    "schema>, pg_temp`. The own schema is there for "
                    "SECURITY, not convenience: without it an "
                    "unqualified name in the body falls through to "
                    "pg_temp, which the attacker writes. If the body "
                    "reads unqualified names from a THIRD schema, add "
                    "it before pg_temp too — or fully-qualify them."
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
