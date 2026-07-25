"""`pgrls vector` — detect an RLS bypass on the RAG **retrieval path**.

The pattern under audit is Supabase's own *RAG with Permissions* guide: chunk
embeddings live in a `document_sections`-shaped table whose RLS gates rows by
the owning document, and retrieval goes through a `match_document_sections()`
similarity-search function. The guide states semantic search keeps respecting
those policies — and it does, *unless the retrieval function is* `SECURITY
DEFINER`, which the same ecosystem recommends for RLS performance.

**Why a probe and not a lint rule.** Every table-level check passes on the
leaking shape: RLS is enabled, `FORCE`'d, the policy is correct, and a direct
`SELECT` as another tenant returns zero rows. The bypass lives in the *composed
path*, so a rule reading the table sees nothing. `SEC014` does warn that a
SECDEF function reads an RLS table, but in a Supabase project that fires on a
haystack of platform functions and only ever says "this *could* bypass". This
module **executes the path and returns the leaked row**.

**The differential.** Rather than planting fixture chunks (which needs the
probe to understand a join-based policy, and writes to a real database), the
probe compares two reads made *as the same low-trust role in one rolled-back
transaction*:

* ``A`` — rows the retrieval function returns
* ``B`` — rows a direct ``SELECT`` on the embeddings table returns

The table's RLS *defines* what that role may see, so ``B`` is ground truth. A
key the function surfaces that a direct read denies is a proven bypass, and the
row is returned as evidence.

**What this is and is not.** ``A`` is a *sample* — one (or a few) synthesized
calls, not the function's entire reachable output. So the differential is a
sound **leak detector** (a surfaced-but-denied key is unambiguously a bypass)
but **not** an isolation prover: "no leak found" means only that *this* probe
surfaced nothing extra, never that the path is safe for all arguments and all
data. That is why there is no `isolated`/PROVEN verdict — only `leak`,
`no_leak` (a spot-check that came up clean), and `abstained`.

**Correlating on the key, not the row.** A safe function that *transforms* a
row it is allowed to return (``upper(content)``, ``left(content, 200)``, a
rounded score) would differ from the stored row and look "extra" under a naive
full-row ``EXCEPT``. So the differential compares **primary-key** columns only:
a leaked key is one the function surfaced that the role's own RLS-filtered read
does not contain. Transforms touch non-key columns, so they can't fabricate a
false leak; and a primary key is ``NOT NULL``, so the ``NOT IN`` test is exact.
When the function does not return the table's full primary key, the probe
**abstains** rather than risk a transform false positive.

**Soundness guards** (an audit that can't false-clear is the whole point):

* The direct read ``B`` is only ground truth if RLS actually *discriminates*
  for the probe role. If the role owns the table (without ``FORCE``), holds
  ``BYPASSRLS``, or is the grantee of a ``USING (true)`` policy, ``B`` is
  everything and the differential is vacuously empty. The probe measures the
  table's cardinality once as the (RLS-exempt) introspection role and again as
  the probe role; if they are equal it **abstains** instead of reporting a
  clean spot-check.
* If the synthesized call returns no rows at all, there is nothing to
  discriminate on → **abstain**.
* If an argument type can't be synthesized, the result has no named columns, or
  the function is overloaded / variadic → **abstain**.

**Not fully read-only.** The probe issues only ``SELECT``s and always rolls the
transaction back, but it *executes the retrieval function* with the definer's
privileges. A function that commits a side effect outside the transaction
(``dblink``, an FDW write, ``COPY … TO PROGRAM``) is not contained by the
rollback. A ``statement_timeout`` bounds a runaway body.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass
from typing import Any, Literal

import psycopg

from pgrls.fixers._idents import quote_ident, quote_qualified
from pgrls.model import Schema, Table

Verdict = Literal["leak", "no_leak", "abstained"]

_MAX_EVIDENCE_ROWS = 5
# A synthesized call is one sample; a threshold argument can point either way
# (distance `< t` wants a big t, similarity `> t` wants a small one), so the
# probe tries a few argument tuples and unions the leaks. Bound the fan-out.
_MAX_ARG_TUPLES = 8
# Bound a runaway SECDEF body / a full-scan count on a huge embeddings table.
_STATEMENT_TIMEOUT_MS = 15_000


@dataclass(frozen=True)
class RetrievalPath:
    """One (embeddings table → SECDEF retrieval function) pair to probe."""

    table: str
    table_schema: str
    table_name: str
    embedding_column: str
    dimension: int | None
    function: str
    function_schema: str
    function_name: str
    signature: str
    execute_roles: tuple[str, ...]
    owner_bypasses_rls: bool


@dataclass(frozen=True)
class VectorResult:
    path: RetrievalPath
    verdict: Verdict
    detail: str
    probe_role: str | None
    leaked_rows: tuple[str, ...]


@dataclass(frozen=True)
class VectorAudit:
    results: tuple[VectorResult, ...]
    # Languages of SECDEF functions whose bodies the SQL parser can't read, so a
    # leaking retrieval function written in one of them yields no path. Surfaced
    # so "no path found" is never silently hiding an unanalyzed PL/pgSQL leak.
    unanalyzed_languages: tuple[str, ...] = ()

    @property
    def has_leak(self) -> bool:
        return any(r.verdict == "leak" for r in self.results)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"leak": 0, "no_leak": 0, "abstained": 0}
        for r in self.results:
            counts[r.verdict] += 1
        return {"paths": len(self.results), **counts}


# --- topology discovery (pure; no database) --------------------------------


def _vector_columns(table: Table) -> list[tuple[str, int | None]]:
    """`(column, dimension)` for every pgvector-typed column on `table`.

    Introspection records the declared type verbatim (`vector(3)`, or a bare
    `vector` when the column is unconstrained), so the dimension — which the
    probe needs to synthesize a call argument — comes straight off the column.
    """
    out: list[tuple[str, int | None]] = []
    for col in table.column_details:
        dt = (col.data_type or "").strip().lower()
        if dt == "vector" or dt.startswith("vector("):
            m = re.search(r"\((\d+)\)", dt)
            out.append((col.name, int(m.group(1)) if m else None))
    return out


def discover_paths(schema: Schema) -> list[RetrievalPath]:
    """Every retrieval path in `schema`: a SECDEF function reading an
    RLS-protected table that stores embeddings.

    Reuses VIEW004's body parser to resolve which tables a function body reads,
    so the same documented abstentions apply (an opaque PL/pgSQL or dynamic-SQL
    body reads *nothing* as far as the parser is concerned, and simply yields no
    path — see `unanalyzed_secdef_languages` for surfacing that gap).
    """
    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415

    from pgrls.rules.view004 import _secdef_fn_leaks  # noqa: PLC0415

    embeddings: dict[str, tuple[Table, str, int | None]] = {}
    for table in schema.tables:
        if not table.rls_enabled:
            continue  # no RLS to bypass — SEC001's domain, not ours
        cols = _vector_columns(table)
        if cols:
            name, dim = cols[0]
            embeddings[table.qualified_name] = (table, name, dim)
    if not embeddings:
        return []

    rls_tables = {(t.schema, t.name) for t in schema.tables if t.rls_enabled}
    bare_to_qual: dict[str, list[tuple[str, str]]] = {}
    for s, n in sorted(rls_tables):
        bare_to_qual.setdefault(n, []).append((s, n))

    paths: list[RetrievalPath] = []
    seen: set[tuple[str, str]] = set()  # dedup overloads (same function+table pair)
    for fn in schema.security_definer_functions:
        # `_secdef_fn_leaks` warns to stderr for non-SQL bodies under the VIEW004
        # brand; we surface that gap ourselves via `unanalyzed_secdef_languages`,
        # so suppress the cross-branded line during discovery.
        with contextlib.redirect_stderr(io.StringIO()):
            read = _secdef_fn_leaks(fn, fn.qualified_name, rls_tables, bare_to_qual)
        for qname in sorted(read & embeddings.keys()):
            if (fn.qualified_name, qname) in seen:
                continue
            seen.add((fn.qualified_name, qname))
            tbl, col, dim = embeddings[qname]
            paths.append(
                RetrievalPath(
                    table=qname,
                    table_schema=tbl.schema,
                    table_name=tbl.name,
                    embedding_column=col,
                    dimension=dim,
                    function=fn.qualified_name,
                    function_schema=fn.schema_name,
                    function_name=fn.function_name,
                    signature=fn.signature or "",
                    execute_roles=tuple(fn.execute_roles or ()),
                    owner_bypasses_rls=bool(fn.owner_bypasses_rls),
                )
            )
    return paths


def unanalyzed_secdef_languages(schema: Schema) -> set[str]:
    """Languages of SECDEF functions whose bodies the SQL parser can't read.

    A leaking retrieval function written in PL/pgSQL yields *no* path (the body
    parser only understands SQL), which would otherwise look identical to "no
    retrieval path exists". Reporting these languages keeps that recall gap
    visible rather than silent.
    """
    return {
        (fn.language or "").lower()
        for fn in schema.security_definer_functions
        if (fn.language or "").lower() not in ("", "sql")
    }


# --- call synthesis --------------------------------------------------------


def _arg_candidates(type_name: str, dimension: int | None) -> list[str] | None:
    """Candidate SQL literals for one argument of the given base type.

    `type_name` is a canonical `format_type` name (`vector`, `integer`, `double
    precision`, `text`, …) drawn from `pg_proc.proargtypes` — input arguments
    only, never OUT/TABLE columns. An unrecognised type returns None so the
    caller ABSTAINS rather than guess a literal that changes what the function
    returns.

    A vector is a *non-zero* unit-ish vector, not the zero vector: cosine and
    inner-product distance are undefined (NaN) for a zero-norm vector, and
    `NaN < threshold` is false, which would silently filter every row out.
    """
    s = type_name.strip().lower()
    if "vector" in s and "tsvector" not in s:
        if dimension is None:
            return None  # can't size the literal; the column was unconstrained
        comps = ["1"] + ["0"] * (dimension - 1) if dimension >= 1 else []
        return ["'[" + ",".join(comps) + f"]'::vector({dimension})"]
    if s in ("smallint", "integer", "bigint", "int2", "int4", "int8"):
        # A generous LIMIT: the differential only detects a leak among rows the
        # function actually returns, so a small match_count could hide one.
        return ["1000"]
    if s in ("double precision", "real", "numeric", "float4", "float8") or s.startswith(
        "numeric("
    ):
        # A threshold could gate either direction; try both extremes so a
        # `distance < t` and a `similarity > t` shape are each made permissive.
        return ["1000000000", "-1000000000"]
    if s in ("text", "character varying", "character", "name", "citext") or s.startswith(
        ("varchar", "char(", "character varying(")
    ):
        return ["''"]
    if s == "boolean":
        return ["true"]
    if s == "jsonb":
        return ["'{}'::jsonb"]
    if s == "json":
        return ["'{}'::json"]
    if s == "uuid":
        return ["'00000000-0000-0000-0000-000000000000'::uuid"]
    return None


def _synthesize_arg_tuples(
    type_names: list[str], dimension: int | None
) -> list[str] | None:
    """Every argument tuple worth trying, as ready-to-interpolate SQL strings.

    Returns None (→ abstain) if any argument type is unsynthesizable. The
    cartesian product across per-argument candidates is capped; leak detection
    is a union over samples, so truncating only lowers recall, never soundness.
    """
    per_arg = [_arg_candidates(t, dimension) for t in type_names]
    if any(c is None for c in per_arg):
        return None
    if not per_arg:
        return [""]  # a no-argument function
    tuples = [
        ", ".join(combo)
        for combo in itertools.islice(
            itertools.product(*[c for c in per_arg if c is not None]),
            _MAX_ARG_TUPLES,
        )
    ]
    return tuples


# --- catalog lookups -------------------------------------------------------


def _fn_input_types(cur: psycopg.Cursor[Any], path: RetrievalPath) -> list[str] | None:
    """Canonical type names of the function's INPUT arguments, or None.

    None means the function is absent, overloaded (can't pick an overload), or
    variadic (needs `VARIADIC` call syntax the probe won't guess).
    `proargtypes` excludes OUT/TABLE columns, so this never sees result columns.
    """
    cur.execute(
        """
        SELECT p.provariadic,
               (SELECT array_agg(format_type(t, NULL) ORDER BY o)
                  FROM unnest(p.proargtypes) WITH ORDINALITY AS u(t, o))
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = %s AND p.proname = %s
        """,
        (path.function_schema, path.function_name),
    )
    rows = cur.fetchall()
    if len(rows) != 1:
        return None  # absent, or overloaded
    provariadic, types = rows[0]
    if provariadic:
        return None  # variadic — don't guess the call shape
    return [str(t) for t in (types or [])]


def _fn_result_columns(
    cur: psycopg.Cursor[Any], path: RetrievalPath
) -> list[str] | None:
    """Column names of a set-returning function (`RETURNS TABLE(...)` or
    `RETURNS SETOF <relation>`), or None for a scalar / unnamed result."""
    cur.execute(
        """
        SELECT pg_get_function_result(p.oid), p.prorettype, p.proretset
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = %s AND p.proname = %s
        """,
        (path.function_schema, path.function_name),
    )
    rows = cur.fetchall()
    if len(rows) != 1:
        return None
    result, prorettype, proretset = rows[0]
    m = re.match(r"^TABLE\((.*)\)$", str(result).strip(), re.S | re.I)
    if m:
        cols: list[str] = []
        for part in m.group(1).split(","):
            tok = part.strip().split()
            if tok:
                cols.append(tok[0])
        return cols or None
    if proretset:
        # RETURNS SETOF <relation>: the columns are the relation's columns.
        cur.execute(
            """
            SELECT a.attname
            FROM pg_attribute a
            WHERE a.attrelid = (SELECT typrelid FROM pg_type WHERE oid = %s)
              AND a.attnum > 0 AND NOT a.attisdropped
            ORDER BY a.attnum
            """,
            (prorettype,),
        )
        cols = [str(r[0]) for r in cur.fetchall()]
        return cols or None
    return None  # scalar / SETOF scalar — no per-column names to correlate


def _table_columns(cur: psycopg.Cursor[Any], qualified: str) -> set[str]:
    cur.execute(
        """
        SELECT a.attname FROM pg_attribute a
        WHERE a.attrelid = %s::regclass AND a.attnum > 0 AND NOT a.attisdropped
        """,
        (qualified,),
    )
    return {str(r[0]) for r in cur.fetchall()}


def _primary_key_columns(cur: psycopg.Cursor[Any], qualified: str) -> list[str]:
    cur.execute(
        """
        SELECT a.attname
        FROM pg_index i
        JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
        WHERE i.indrelid = %s::regclass AND i.indisprimary
        ORDER BY array_position(i.indkey, a.attnum)
        """,
        (qualified,),
    )
    return [str(r[0]) for r in cur.fetchall()]


def _table_count(cur: psycopg.Cursor[Any], qtbl: str) -> int:
    cur.execute(f"SELECT count(*) FROM {qtbl}")  # noqa: S608
    row = cur.fetchone()
    return int(row[0]) if row else 0


def _connection_bypasses_rls(cur: psycopg.Cursor[Any]) -> bool:
    """Whether the *connection* role bypasses RLS (superuser or BYPASSRLS).

    The differential's `unfiltered` baseline and the leaked-row provenance check
    both read the embeddings table expecting to see *every* row — true only for
    an RLS-exempt role. If pgrls is connected as an RLS-subject role, those reads
    are themselves filtered, and a coincidental `visible == unfiltered` (or a
    phantom baseline of 0) would silently false-clear a real leak. So the probe
    checks this first and abstains rather than trust an untrustworthy baseline.
    Read as `current_user` *before* any `SET ROLE`.
    """
    cur.execute(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user"
    )
    row = cur.fetchone()
    return bool(row and row[0])


def _keep_rows_with_real_keys(
    cur: psycopg.Cursor[Any],
    qtbl: str,
    q_pk: str,
    pk_cols: list[str],
    display_cols: list[str],
    rows: list[tuple[Any, ...]],
) -> list[tuple[Any, ...]]:
    """Drop surfaced rows whose primary key is not a real embeddings-table row.

    A retrieval function can `RETURN` a key sourced from a *different* relation
    (reading the embeddings table only for `ORDER BY`); that key is denied by
    the probe role's direct read yet is not a bypass of *this* table's RLS. Only
    the connection role — verified RLS-exempt by the caller — can see every real
    key, so `RESET ROLE` back to it and keep only rows whose key genuinely
    exists in the embeddings table.
    """
    pk_idx = [display_cols.index(c) for c in pk_cols]
    keys: list[tuple[Any, ...]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        key = tuple(row[i] for i in pk_idx)
        if key not in seen:
            seen.add(key)
            keys.append(key)
    if not keys:
        return []
    cur.execute("RESET ROLE")  # back to the RLS-exempt connection role
    # Cast each placeholder to its PK column's exact type. An untyped `%s` in a
    # `VALUES` list resolves to `text`, and comparing a `char(n)` column against
    # a text value strips the column's blank-padding — so a real `char(n)` key
    # would never match its own row and a genuine leak would be dropped.
    pk_types = _pk_column_types(cur, qtbl, pk_cols)
    one_row = "(" + ", ".join(f"%s::{t}" for t in pk_types) + ")"
    placeholders = ", ".join(one_row for _ in keys)
    cur.execute(
        f"SELECT {q_pk} FROM {qtbl} WHERE ({q_pk}) IN (VALUES {placeholders})",  # noqa: S608
        [v for key in keys for v in key],
    )
    real = {tuple(r) for r in cur.fetchall()}
    return [row for row in rows if tuple(row[i] for i in pk_idx) in real]


def _pk_column_types(
    cur: psycopg.Cursor[Any], regclass: str, pk_cols: list[str]
) -> list[str]:
    """`format_type` for each PK column, in `pk_cols` order.

    Catalog-derived type names (`character(12)`, `numeric(10,2)`, `uuid`, …) —
    safe to interpolate as cast targets, and required so the provenance
    membership test compares like-typed values rather than silently widening to
    `text`.
    """
    cur.execute(
        """
        SELECT a.attname, format_type(a.atttypid, a.atttypmod)
        FROM pg_attribute a
        WHERE a.attrelid = %s::regclass AND a.attname = ANY(%s)
        """,
        (regclass, pk_cols),
    )
    by_name = {str(n): str(t) for n, t in cur.fetchall()}
    return [by_name[c] for c in pk_cols]


# --- live probe ------------------------------------------------------------


def _candidate_roles(path: RetrievalPath, probe_role: str | None) -> list[str]:
    if probe_role:
        return [probe_role]
    # PUBLIC is not a settable role; probe every concrete grantee instead, so a
    # per-grantee `USING(true)` on one role can't hide a leak visible to another.
    return [r for r in path.execute_roles if r != "PUBLIC"]


def _apply_settings(cur: psycopg.Cursor[Any], settings: dict[str, str]) -> None:
    """Stamp the session identity the policies read (``--set guc=value``).

    Without it the probe runs identity-less, so a policy gating on
    ``current_setting('app.user_id')`` matches NOTHING and the direct read `B`
    is empty — every retrieved row would look "extra". Supplying the identity is
    what makes the differential sharp. `set_config(..., true)` is
    transaction-local and rolls back with everything else.
    """
    for key, value in settings.items():
        cur.execute("SELECT set_config(%s, %s, true)", (key, value))


def _probe_pair(
    cur: psycopg.Cursor[Any],
    path: RetrievalPath,
    role: str,
    settings: dict[str, str],
) -> VectorResult:
    def result(v: Verdict, detail: str, rows: tuple[str, ...] = ()) -> VectorResult:
        return VectorResult(
            path=path, verdict=v, detail=detail, probe_role=role, leaked_rows=rows
        )

    qtbl = quote_qualified(path.table_schema, path.table_name)
    qfn = quote_qualified(path.function_schema, path.function_name)
    regclass_arg = qtbl  # a quoted ident parses correctly as ::regclass

    # -- static shape checks (no role change yet) ---------------------------
    type_names = _fn_input_types(cur, path)
    if type_names is None:
        return result(
            "abstained",
            "retrieval function is absent, overloaded, or variadic — cannot pick "
            "one call to make unambiguously",
        )
    arg_tuples = _synthesize_arg_tuples(type_names, path.dimension)
    if arg_tuples is None:
        return result(
            "abstained",
            f"cannot synthesize a call: unrecognised argument type in "
            f"({', '.join(type_names)})",
        )

    fn_cols = _fn_result_columns(cur, path)
    if not fn_cols:
        return result(
            "abstained",
            "retrieval function has no named result columns (not RETURNS "
            "TABLE(...) / SETOF <relation>) — nothing to correlate to the table",
        )

    try:
        table_cols = _table_columns(cur, regclass_arg)
        pk_cols = _primary_key_columns(cur, regclass_arg)
    except psycopg.Error as exc:
        return result("abstained", f"cannot resolve {path.table}: {exc}".strip())

    if not pk_cols:
        return result(
            "abstained",
            f"{path.table} has no primary key, so a surfaced row can't be "
            "distinguished from a transformed copy of a row the caller owns",
        )
    if not set(pk_cols) <= set(fn_cols):
        return result(
            "abstained",
            f"retrieval function does not return the primary key "
            f"({', '.join(pk_cols)}) of {path.table}, so a leaked row can't be "
            "told apart from a transformed copy of an owned row",
        )

    # `display_cols` includes the primary key (pk ⊆ fn_cols ∩ table_cols), so
    # the CTE projects it once and the predicate reuses those same columns — no
    # duplicate-column ambiguity.
    display_cols = [c for c in fn_cols if c in table_cols]
    q_pk = ", ".join(quote_ident(c) for c in pk_cols)
    q_display = ", ".join(quote_ident(c) for c in display_cols)

    # -- establish the probe session and its ground truth -------------------
    try:
        cur.execute(f"SET LOCAL statement_timeout = {_STATEMENT_TIMEOUT_MS}")
        if not _connection_bypasses_rls(cur):
            return result(
                "abstained",
                "the connection role is itself subject to RLS, so the "
                "'all rows' baseline this probe compares against cannot be "
                "trusted — run pgrls as a superuser or BYPASSRLS role",
            )
        unfiltered = _table_count(cur, qtbl)  # trustworthy: connection bypasses RLS
        _apply_settings(cur, settings)
        cur.execute(f"SET LOCAL ROLE {quote_ident(role)}")
    except psycopg.Error as exc:
        return result("abstained", f"cannot set up probe session: {exc}".strip())

    if unfiltered == 0:
        return result(
            "abstained",
            f"{path.table} is empty as the introspection role — no data to "
            "discriminate on (seed the table to make the probe meaningful)",
        )

    try:
        visible = _table_count(cur, qtbl)  # as the probe role, RLS-filtered
    except psycopg.Error as exc:
        return result("abstained", f"cannot read {path.table} as {role}: {exc}".strip())

    if visible >= unfiltered:
        return result(
            "abstained",
            f"RLS does not restrict {role} on {path.table} (it sees all "
            f"{unfiltered} rows — it owns the table, holds BYPASSRLS, or a "
            "USING(true) policy grants it everything), so a direct read is "
            "already unfiltered and the comparison could not detect a bypass",
        )

    # -- the differential: keys the function surfaces that the role is denied -
    leaked: list[tuple[Any, ...]] = []
    retrieved_any = False
    last_err = ""
    pk_predicate = f"({q_pk}) NOT IN (SELECT {q_pk} FROM {qtbl})"
    for args in arg_tuples:
        call = f"{qfn}({args})"
        try:
            # A savepoint per tuple: a call that errors on synthesized args
            # (wrong-dimension vector, a domain violation) proves nothing and
            # must not poison the transaction — roll back to the savepoint and
            # try the next tuple, surfacing the error only if every tuple fails.
            with cur.connection.transaction():
                # DISTINCT ON the primary key, not the whole row: a result
                # column can have a type with no equality operator (`json`,
                # `xml`, `point`), on which a plain `SELECT DISTINCT` errors and
                # a leaking path would abstain instead of report. The PK always
                # has equality (it is a key).
                cur.execute(
                    f"WITH a AS (SELECT {q_display} FROM {call}) "  # noqa: S608
                    f"SELECT DISTINCT ON ({q_pk}) {q_display} FROM a "
                    f"WHERE {pk_predicate} ORDER BY {q_pk} LIMIT {_MAX_EVIDENCE_ROWS}"
                )
                rows = cur.fetchall()
                if rows:
                    retrieved_any = True  # a surfaced row implies the call retrieved
                elif not retrieved_any:
                    # No leak from this call: a SECOND invocation only to learn
                    # whether it returned anything (so an empty result reads as
                    # "no rows to judge" rather than "clean"). Never runs once a
                    # leak is in hand, so a fetched leak can't be rolled back.
                    cur.execute(f"SELECT EXISTS (SELECT 1 FROM {call})")  # noqa: S608
                    ex = cur.fetchone()
                    retrieved_any = bool(ex and ex[0])
        except psycopg.Error as exc:
            last_err = str(exc).strip()
            continue
        leaked.extend(rows)
        if len(leaked) >= _MAX_EVIDENCE_ROWS:
            break

    if leaked:
        # Provenance: keep only surfaced keys that are REAL embeddings-table rows
        # the probe role is denied. A function returning a same-named key from a
        # different relation (reading this table only for ORDER BY) is denied by
        # the direct read but bypasses nothing — drop it, don't false-leak.
        leaked = _keep_rows_with_real_keys(
            cur, qtbl, q_pk, pk_cols, display_cols, leaked
        )
    if leaked:
        evidence = tuple(
            "(" + ", ".join(f"{c}={v!r}" for c, v in zip(display_cols, r)) + ")"
            for r in leaked[:_MAX_EVIDENCE_ROWS]
        )
        return result(
            "leak",
            f"as {role}, {path.function} surfaced {len(leaked)} row(s) whose key "
            f"a direct SELECT on {path.table} denies — the retrieval path "
            "bypasses the table's RLS",
            evidence,
        )
    if last_err:
        return result("abstained", f"every synthesized call failed: {last_err}")
    if not retrieved_any:
        return result(
            "abstained",
            f"the retrieval function returned no rows as {role} for any "
            "synthesized argument — nothing to discriminate on",
        )
    return result(
        "no_leak",
        f"as {role}, no row {path.function} surfaced was denied by a direct "
        f"SELECT on {path.table} (spot-check over {len(arg_tuples)} synthesized "
        "call(s); not a proof of isolation for all arguments)",
    )


def run_vector_audit(
    conn: psycopg.Connection[Any],
    schema: Schema,
    *,
    probe_role: str | None = None,
    settings: dict[str, str] | None = None,
) -> VectorAudit:
    """Probe every discovered retrieval path, per candidate role. Each probe
    runs in its own always-rolled-back transaction."""
    paths = discover_paths(schema)
    results: list[VectorResult] = []
    for path in paths:
        roles = _candidate_roles(path, probe_role)
        if not roles:
            results.append(
                VectorResult(
                    path=path,
                    verdict="abstained",
                    detail="no concrete role holds EXECUTE on the retrieval "
                    "function (only PUBLIC); pass --probe-role to name the role "
                    "your API uses",
                    probe_role=None,
                    leaked_rows=(),
                )
            )
            continue
        for role in roles:
            with conn.transaction(force_rollback=True), conn.cursor() as cur:
                results.append(_probe_pair(cur, path, role, settings or {}))
    return VectorAudit(
        tuple(results),
        unanalyzed_languages=tuple(sorted(unanalyzed_secdef_languages(schema))),
    )


# --- rendering -------------------------------------------------------------

_LABEL = {"leak": "LEAK", "no_leak": "NO LEAK", "abstained": "UNVERIFIED"}


def _unanalyzed_note(audit: VectorAudit) -> str | None:
    if not audit.unanalyzed_languages:
        return None
    langs = ", ".join(audit.unanalyzed_languages)
    return (
        f"note: {langs} SECURITY DEFINER function(s) were not analyzed (the body "
        "parser reads SQL only) — a retrieval path written in one is not covered "
        "by this probe."
    )


def render_text(audit: VectorAudit) -> str:
    note = _unanalyzed_note(audit)
    if not audit.results:
        head = (
            "No RAG retrieval path found: no RLS-enabled table stores a "
            "pgvector column that a SECURITY DEFINER SQL function reads."
        )
        return f"{head}\n{note}" if note else head
    lines: list[str] = []
    for r in audit.results:
        role = f" as {r.probe_role}" if r.probe_role else ""
        lines.append(f"{_LABEL[r.verdict]:<11} {r.path.function} -> {r.path.table}{role}")
        lines.append(f"            {r.detail}")
        for row in r.leaked_rows:
            lines.append(f"              leaked row: {row}")
    s = audit.summary
    lines.append("")
    lines.append(
        f"{s['paths']} retrieval-path probe(s): {s['leak']} leak, "
        f"{s['no_leak']} no-leak, {s['abstained']} unverified"
    )
    if note:
        lines.append(note)
    return "\n".join(lines)


def render_json(audit: VectorAudit) -> str:
    import json  # noqa: PLC0415

    return json.dumps(
        {
            "summary": audit.summary,
            "unanalyzed_languages": list(audit.unanalyzed_languages),
            "paths": [
                {
                    "table": r.path.table,
                    "embedding_column": r.path.embedding_column,
                    "dimension": r.path.dimension,
                    "function": r.path.function,
                    "execute_roles": list(r.path.execute_roles),
                    "owner_bypasses_rls": r.path.owner_bypasses_rls,
                    "verdict": r.verdict,
                    "detail": r.detail,
                    "probe_role": r.probe_role,
                    "leaked_rows": list(r.leaked_rows),
                }
                for r in audit.results
            ],
        },
        indent=2,
        ensure_ascii=False,
    )
