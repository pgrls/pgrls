"""Runnable leak reproductions for `pgrls verify --emit-repro`.

A `pgrls verify` LEAK is abstract: "an anonymous session can read a row of
public.docs under policy p." `--emit-repro` turns that proof into something a
developer runs and watches happen — per leaking (table, policy) it writes:

* a self-contained ``.sql`` script (``BEGIN … ROLLBACK``) that recreates a
  throwaway copy of the table from the introspected column types, installs the
  leaking policy verbatim, inserts the counterexample row, drops into an
  anonymous session, and ``SELECT``s the row back — the leak, reproduced and
  then rolled back; and
* a ``test_*.py`` pytest that runs the same steps against ``$DATABASE_URL`` and
  asserts the row is (wrongly) visible — a red test that captures the bug.

The reproduction demonstrates the leak structurally (a ``SELECT`` returns a row
the policy should hide). Counterexample columns the proof pins (verify's
witness) are set to their leak-triggering values; the rest get type-appropriate
placeholders so the script runs. A policy that references other tables/
subqueries, or columns of exotic types, may need a hand-edit — the header says
so.

``--mode cross-tenant`` reproduces the cross-tenant leak instead: the SELECT
runs as a session **authenticated as tenant A** (the JWT-claim GUC the policy's
auth function reads, or a direct ``current_setting('<guc>')``, is set to A) and
the inserted row belongs to a **different tenant B** — which the leaking policy
nonetheless returns. Either mode runs as a NOSUPERUSER/NOBYPASSRLS runner, so a
*fixed* policy returns zero rows (the reproduction is sound, not an RLS bypass).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass

from pglast import parse_sql
from pglast.ast import A_Const, A_Expr, ColumnRef, FuncCall, Node, String, TypeCast

from pgrls.ast_utils import func_name_parts
from pgrls.diff._z3_compare import cross_tenant_session_identity
from pgrls.fixers._idents import quote_ident
from pgrls.model import Column, Policy, Schema, Table
from pgrls.verify import DEFAULT_AUTH_FUNCTIONS, Verification

# auth.* stubs so a Supabase-style policy is creatable in a throwaway database;
# under an anonymous session (no JWT GUC set) each returns NULL — exactly the
# state verify proves the leak under.
# `NULLIF(…, '')` so both an unset GUC and an empty one collapse to NULL — the
# anonymous state — without the bare `''::uuid` / `''::jsonb` cast erroring.
_AUTH_STUB = """CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
CREATE OR REPLACE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('request.jwt.claim.role', true), '') $$;
CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('request.jwt.claims', true), '')::jsonb $$;"""

_INT_TYPES = frozenset(
    {"smallint", "integer", "int", "int2", "int4", "int8", "bigint", "oid"}
)
_NUM_TYPES = frozenset(
    {"numeric", "decimal", "real", "double precision", "float4", "float8", "money"}
)
_BOOL_TYPES = frozenset({"boolean", "bool"})
_TEXT_TYPES = frozenset(
    {"text", "varchar", "character varying", "char", "character", "bpchar",
     "citext", "name"}
)

# A canonical UUID literal. Z3's symbolic string for a free/don't-care uuid
# column ('!0!', '') never matches, so such a witness value is rejected and a
# placeholder is used instead of an INSERT-crashing ''::uuid.
_UUID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)


def _base_type(data_type: str) -> str:
    """Strip length/precision and array suffix: ``varchar(64)[]`` → ``varchar``."""
    t = data_type.strip().lower()
    t = re.sub(r"\[\s*\]", "", t)  # drop array markers
    t = t.split("(", 1)[0].strip()
    return t


def _placeholder(data_type: str) -> str:
    """A type-appropriate literal to satisfy a NOT NULL column the proof does
    not pin. Common types only; anything else falls back to NULL (fine for a
    nullable column; flagged in the header for a NOT NULL exotic type)."""
    if data_type.strip().endswith("]"):
        return "'{}'"  # empty array literal
    t = _base_type(data_type)
    if t in _INT_TYPES or t in _NUM_TYPES:
        return "0"
    if t in _BOOL_TYPES:
        return "false"
    if t == "uuid":
        return "'00000000-0000-0000-0000-000000000000'::uuid"
    if t in {"json", "jsonb"}:
        return "'{}'::" + t
    if t == "date":
        return "current_date"
    if t in {"timestamp", "timestamptz", "timestamp with time zone",
             "timestamp without time zone"}:
        return "now()"
    if t in {"time", "timetz", "time with time zone", "time without time zone"}:
        return "current_time"
    if t in _TEXT_TYPES:
        return "''"
    return "NULL"


def _is_valid_literal(value: str, base_type: str) -> bool:
    """Best-effort check that a *string* witness value is a syntactically valid
    literal for a non-text, non-array column type (arrays are short-circuited by
    the caller). Z3 decodes a free/don't-care String-sorted column to a symbolic
    placeholder (``'!0!'``) or ``''`` that is not a valid ``uuid``/
    ``timestamptz``/``json`` literal; emitting ``'!0!'::uuid`` would crash the
    INSERT before the leak SELECT runs. Conservative — returns True only when
    confident, so anything dubious falls back to a placeholder."""
    if base_type == "uuid":
        return bool(_UUID_RE.match(value))
    if base_type in {"json", "jsonb"}:
        try:
            json.loads(value)
        except (ValueError, TypeError):
            return False
        return True
    if base_type in {"inet", "cidr"}:
        try:
            ipaddress.ip_interface(value)
        except ValueError:
            return False
        return True
    # Numeric/bool columns decode to a python int/bool (not str), so a *string*
    # for one is symbolic; temporal and every other non-text type can't be
    # cheaply validated and Z3's value is symbolic anyway — reject and let the
    # caller substitute a type-appropriate placeholder.
    return False


# Z3's free-String placeholder for a don't-care column ('!0!', '!1!', …). It is
# never a real policy literal, so a witness value of this shape is a column the
# prover did not constrain. (An empty string is NOT treated as a placeholder —
# it can be a load-bearing ``col = ''`` value — so it is emitted verbatim.)
_Z3_PLACEHOLDER = re.compile(r"\A!\d+!\Z")


def _witness_literal(value: object, data_type: str) -> str | None:
    """Render a verify witness value as a SQL literal for a column of
    `data_type`, or ``None`` when the value is a don't-care the prover left
    symbolic (so the caller substitutes a placeholder and flags it). Booleans/
    numbers emit directly; a text value is a quoted string (except Z3's ``!N!``
    placeholder); a non-text string is validated and cast (``'…'::uuid``) or
    rejected rather than emit an INSERT that crashes."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    lit = "'" + s.replace("'", "''") + "'"
    if data_type.strip().endswith("]"):
        # An array column: _base_type strips the '[]', so the text branch below
        # would emit a bare scalar string into an array column (a malformed
        # array literal). Defer to the caller's '{}' placeholder.
        return None
    t = _base_type(data_type)
    if t in _TEXT_TYPES:
        return None if _Z3_PLACEHOLDER.match(s) else lit
    if not _is_valid_literal(s, t):
        return None
    return f"{lit}::{t}"


@dataclass(frozen=True)
class ReproArtifact:
    stem: str  # sanitized, policy-inclusive identifier, e.g. "public_docs_p"
    sql: str
    pytest: str
    sql_filename: str  # e.g. "public_docs_p.sql"
    pytest_filename: str  # e.g. "test_public_docs_p.py"


def _column_map(table: Table) -> dict[str, Column]:
    return {c.name: c for c in table.column_details}


def _row_columns(
    table: Table, witness: dict[str, object]
) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """The (column, value-literal) pairs to INSERT: every NOT NULL column plus
    every witness column, witness values winning. Also returns two best-effort
    flags ``build_repro`` surfaces as caveats: ``unpinned`` (witness columns the
    prover left symbolic → a placeholder) and ``null_fallback`` (NOT NULL
    columns of an unrecognized type that got a literal ``NULL`` — the INSERT
    fails only if the type is a NOT NULL domain). ``build_repro`` guarantees a
    non-empty ``column_details`` before this is reached."""
    cols = _column_map(table)
    chosen: dict[str, str] = {}
    unpinned: list[str] = []
    null_fallback: list[str] = []
    for name, col in cols.items():
        if name in witness:
            lit = _witness_literal(witness[name], col.data_type)
            if lit is None:  # symbolic / type-invalid value → placeholder
                chosen[name] = _placeholder(col.data_type)
                unpinned.append(name)
            else:
                chosen[name] = lit
        elif not col.is_nullable:
            ph = _placeholder(col.data_type)
            chosen[name] = ph
            if ph == "NULL":  # unrecognized type → NULL into a NOT NULL column
                null_fallback.append(name)
    # A witness column absent from column_details can't be honored — it's not in
    # the throwaway CREATE TABLE, so emitting it would make the INSERT reference
    # a non-existent column. Drop it; the in-schema pins still characterize the
    # leak. (Unreachable via live introspection — pg_get_expr unqualifies every
    # single-table policy column, so the witness is a subset of column_details —
    # but a guard against a future divergent schema source.)
    ordered = [(n, chosen[n]) for n in cols if n in chosen]
    return ordered, unpinned, null_fallback


def _policy_roles(policy: Policy) -> tuple[str, ...]:
    return policy.roles or ("public",)


_BUILTIN_AUTH_STUBBED = frozenset({"auth.uid", "auth.role", "auth.jwt"})
_RUNNER_ROLE = "pgrls_repro_runner"
# Schemas we never synthesize a stub in — they already exist with real
# functions in any Postgres (stubbing pg_catalog.now() would both fail to
# CREATE and shadow a builtin).
_NON_STUB_SCHEMAS = frozenset({"pg_catalog", "information_schema"})


def _referenced_function_arities(using_ast: object) -> dict[str, set[int]]:
    """Map each schema-qualified function the policy's USING references to the
    argument counts it is called with (``auth.user_id`` → {0},
    ``auth.has_access(tenant_id)`` → {1}). The reproduction stubs each one with a
    matching arity so a custom helper *not* passed via ``--auth-function`` still
    resolves — otherwise the generated CREATE POLICY fails with
    ``UndefinedFunction`` (and an arg-taking call fails even against a zero-arg
    stub: ``function auth.has_access(uuid) does not exist``)."""
    found: dict[str, set[int]] = {}

    def walk(n: object) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, FuncCall):
            qualified, _ = func_name_parts(n)
            if qualified and "." in qualified:
                found.setdefault(qualified, set()).add(len(n.args or ()))
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(using_ast)
    return found


_COMPARISON_OPS = frozenset({"=", "<>", "!=", "<", ">", "<=", ">="})


def _aexpr_operator(node: A_Expr) -> str | None:
    parts = [p.sval for p in (node.name or ()) if isinstance(p, String)]
    return parts[-1] if parts else None


def _funccall_qualified(node: object) -> str | None:
    qualified, _ = func_name_parts(node)
    return qualified if qualified and "." in qualified else None


def _columnref_name(node: object) -> str | None:
    if not isinstance(node, ColumnRef):
        return None
    parts = [f.sval for f in (node.fields or ()) if isinstance(f, String)]
    return parts[-1] if parts else None


def _infer_custom_auth_types(
    using_ast: object, column_types: dict[str, str]
) -> dict[str, str]:
    """Infer a stub return type for each custom auth function from how the
    policy compares it: ``tenant_id = auth.user_id()`` with ``tenant_id uuid``
    → ``auth.user_id`` RETURNS uuid, so the generated CREATE POLICY type-checks
    instead of failing with ``operator does not exist: uuid = text``. Only a
    bare function-vs-column comparison is matched; a cast or more complex shape
    falls back to text (the header caveat covers that residual case)."""
    inferred: dict[str, str] = {}

    def consider(fn_side: object, col_side: object) -> None:
        fn = _funccall_qualified(fn_side)
        col = _columnref_name(col_side)
        if fn and col and col in column_types:
            inferred.setdefault(fn, column_types[col])

    def walk(n: object) -> None:
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
            return
        if isinstance(n, A_Expr) and _aexpr_operator(n) in _COMPARISON_OPS:
            consider(n.lexpr, n.rexpr)
            consider(n.rexpr, n.lexpr)
        if isinstance(n, Node):
            for field_name in n:
                walk(getattr(n, field_name, None))

    walk(using_ast)
    return inferred


def _custom_auth_stub(
    name: str, return_type: str = "text", n_args: int = 0
) -> str | None:
    """A NULL-returning stub (+ schema USAGE) for an auth function not already
    covered by ``_AUTH_STUB``, so the leaking policy is still creatable.

    Bare builtins (``current_setting``, ``current_user`` …, no schema) and the
    three already in ``_AUTH_STUB`` need none. A schema-qualified custom helper
    (``auth.user_id``) is stubbed to return NULL under an anonymous session.
    `return_type` (inferred from the policy comparison, default ``text``) makes
    the stub's type match the column it is compared to, so ``tenant_id =
    auth.user_id()`` on a uuid column type-checks instead of raising ``operator
    does not exist``. `n_args` ``anyelement`` parameters match the call's arity
    so ``auth.has_access(tenant_id)`` resolves — a zero-arg stub would fail with
    ``function auth.has_access(uuid) does not exist``.
    """
    if "." not in name or name in _BUILTIN_AUTH_STUBBED:
        return None
    schema, _, fn = name.rpartition(".")
    if schema in _NON_STUB_SCHEMAS:
        return None  # pg_catalog / information_schema already exist
    qs = quote_ident(schema)
    cast = "" if return_type == "text" else f"::{return_type}"
    params = ", ".join("anyelement" for _ in range(n_args))
    return (
        f"CREATE SCHEMA IF NOT EXISTS {qs};\n"
        f"GRANT USAGE ON SCHEMA {qs} TO PUBLIC;\n"
        f"CREATE OR REPLACE FUNCTION {qs}.{quote_ident(fn)}({params}) RETURNS "
        f"{return_type} LANGUAGE sql STABLE AS $$ SELECT "
        f"NULLIF(current_setting('request.jwt.claim.sub', true), ''){cast} $$;"
    )


def _custom_auth_functions(auth_functions: set[str]) -> list[str]:
    """The schema-qualified auth functions that need a synthesized stub
    (excluding the auth.* builtins already in `_AUTH_STUB` and catalog-schema
    functions that always exist)."""
    return sorted(
        n
        for n in auth_functions
        if "." in n
        and n not in _BUILTIN_AUTH_STUBBED
        and n.rpartition(".")[0] not in _NON_STUB_SCHEMAS
    )


def _common_setup(
    table: Table,
    policy: Policy,
    repro_table: str,
    auth_functions: set[str],
) -> tuple[list[str], str]:
    """The setup statements shared by the anon and cross-tenant reproductions —
    everything up to (but not including) the INSERT: the auth-function stubs, a
    NOSUPERUSER/NOBYPASSRLS runner role, the throwaway table, its SELECT grant,
    ENABLE/FORCE RLS, and the leaking policy. Returns ``(setup, runner)``; each
    builder appends its own INSERT, session establishment, and SET ROLE."""
    qtbl = quote_ident(repro_table)
    roles = _policy_roles(policy)
    non_public = [r for r in roles if r != "public"]

    setup: list[str] = [_AUTH_STUB, "GRANT USAGE ON SCHEMA auth TO PUBLIC;"]
    col_types = {c.name: _base_type(c.data_type) for c in table.column_details}
    inferred_types = _infer_custom_auth_types(policy.using_ast, col_types)
    arities = _referenced_function_arities(policy.using_ast)
    for fn in _custom_auth_functions(auth_functions):
        for n_args in sorted(arities.get(fn, {0})):
            stub = _custom_auth_stub(fn, inferred_types.get(fn, "text"), n_args)
            if stub:
                setup.append(stub)

    # Roles are created NOSUPERUSER / NOBYPASSRLS so that, once we SET ROLE into
    # one, FORCE ROW LEVEL SECURITY actually applies — a superuser or BYPASSRLS
    # role would read every row regardless of the policy and make the
    # reproduction unsound (it would "leak" even against a fixed policy).
    runner = non_public[0] if non_public else _RUNNER_ROLE
    roles_to_create = list(non_public) + ([] if non_public else [_RUNNER_ROLE])
    for role in roles_to_create:
        setup.append(
            f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = "
            f"{_sql_str(role)}) THEN CREATE ROLE {quote_ident(role)} NOLOGIN "
            f"NOSUPERUSER NOBYPASSRLS; END IF; END $$;"
        )
    # Force the runner non-privileged even if it pre-existed. The IF NOT EXISTS
    # above leaves an already-present role untouched, so a real target role
    # carrying SUPERUSER/BYPASSRLS (e.g. a live `authenticated`) would bypass RLS
    # once we SET ROLE into it and make the reproduction unsound — a *fixed*
    # policy would still "leak". This ALTER is transactional and rolled back with
    # the rest of the setup, so it never persists to the (throwaway) database.
    setup.append(f"ALTER ROLE {quote_ident(runner)} NOSUPERUSER NOBYPASSRLS;")

    col_defs = ",\n    ".join(
        f"{quote_ident(c.name)} {c.data_type}" for c in table.column_details
    )
    setup.append(f"CREATE TABLE {qtbl} (\n    {col_defs}\n);")

    # The runner must hold SELECT; for a PUBLIC policy the PUBLIC grant covers
    # it, otherwise grant the named target role.
    grant_roles = list(roles) if non_public else ["public", _RUNNER_ROLE]
    grant_to = ", ".join(
        "PUBLIC" if r == "public" else quote_ident(r) for r in grant_roles
    )
    setup.append(f"GRANT SELECT ON {qtbl} TO {grant_to};")
    setup.append(f"ALTER TABLE {qtbl} ENABLE ROW LEVEL SECURITY;")
    setup.append(f"ALTER TABLE {qtbl} FORCE ROW LEVEL SECURITY;")

    to_clause = ", ".join(
        "PUBLIC" if r == "public" else quote_ident(r) for r in roles
    )
    setup.append(
        f"CREATE POLICY {quote_ident(policy.name)} ON {qtbl}\n"
        f"    FOR SELECT TO {to_clause}\n"
        f"    USING ({policy.using_sql});"
    )
    return setup, runner


def _insert_row(setup: list[str], qtbl: str, row: list[tuple[str, str]]) -> None:
    """Append the INSERT for the leaking row (or DEFAULT VALUES when empty)."""
    if row:
        cols_sql = ", ".join(quote_ident(n) for n, _ in row)
        vals_sql = ", ".join(v for _, v in row)
        setup.append(f"INSERT INTO {qtbl} ({cols_sql}) VALUES ({vals_sql});")
    else:
        setup.append(f"INSERT INTO {qtbl} DEFAULT VALUES;")


def _build_statements(
    table: Table,
    policy: Policy,
    witness: dict[str, object],
    repro_table: str,
    auth_functions: set[str],
) -> tuple[list[str], str, list[str], list[str]]:
    """Return (setup_statements, leak_query, unpinned_columns, null_columns) for
    the anonymous-read reproduction. The pytest runs setup then the query in one
    rolled-back transaction; the .sql wraps them in BEGIN/ROLLBACK.
    `unpinned_columns` are witness columns the proof left symbolic; `null_columns`
    are NOT NULL columns of an unrecognized type given a NULL placeholder (the
    caller flags both)."""
    qtbl = quote_ident(repro_table)
    setup, runner = _common_setup(table, policy, repro_table, auth_functions)
    row, unpinned, null_fallback = _row_columns(table, witness)
    _insert_row(setup, qtbl, row)

    # Become an anonymous session: clear the JWT claim GUC (auth.* → NULL) and
    # switch into the non-superuser runner so FORCE RLS + the policy decide
    # visibility (not a privileged connection role).
    setup.append("SELECT set_config('request.jwt.claim.sub', '', true);")
    setup.append(f"SET LOCAL ROLE {quote_ident(runner)};")

    leak_query = f"SELECT * FROM {qtbl};"
    return setup, leak_query, unpinned, null_fallback


# The GUC each auth.* builtin / NULL-stubbed custom helper reads (see
# `_AUTH_STUB` / `_custom_auth_stub`): set it to tenant A and the session
# identity resolves to A. A direct `current_setting('<guc>', …)` identity sets
# its own GUC instead.
_AUTH_IDENTITY_GUC = {
    "auth.uid": "request.jwt.claim.sub",
    "auth.role": "request.jwt.claim.role",
}
_DEFAULT_IDENTITY_GUC = "request.jwt.claim.sub"

# The type a builtin's stub casts its GUC string to (see `_AUTH_STUB`):
# `auth.uid()` → uuid, `auth.jwt()` → jsonb. This cast is the INNERMOST applied
# to the GUC, so the session-tenant A value written to that GUC must be of this
# type — even under an outer `auth.uid()::text` — or the stub raises
# (`'tenant_a'::uuid`) and the leak SELECT crashes before it can leak. Functions
# absent here (auth.role(), a NULL-stubbed custom helper, a direct
# current_setting) cast nothing internally, so the value type is decided by the
# policy's own cast (= the discriminator column type) — see `_identity_value_type`.
_AUTH_IDENTITY_VALUE_TYPE = {
    "auth.uid": "uuid",
    "auth.jwt": "jsonb",
}

# Distinct concrete tenant values per discriminator type-class. A is the
# session's tenant, B (≠ A) the leaking row's. text/exotic share the text pool
# (an exotic type is caveated in the header).
_TENANT_POOL_UUID = (
    "00000000-0000-0000-0000-0000000000a1",
    "00000000-0000-0000-0000-0000000000b2",
    "00000000-0000-0000-0000-0000000000c3",
)
_TENANT_POOL_INT = (1, 2, 3)
_TENANT_POOL_TEXT = ("tenant_a", "tenant_b", "tenant_c")
# jsonb session identities (e.g. auth.jwt()) are set best-effort (caveated);
# distinct valid-JSON literals so the stub's `::jsonb` cast succeeds.
_TENANT_POOL_JSONB = ('{"sub": "tenant_a"}', '{"sub": "tenant_b"}', '{"sub": "tenant_c"}')


def _tenant_pool(data_type: str) -> tuple[object, ...]:
    base = _base_type(data_type)
    if base == "uuid":
        return _TENANT_POOL_UUID
    if base in {"json", "jsonb"}:
        return _TENANT_POOL_JSONB
    if base in _INT_TYPES or base in _NUM_TYPES:
        return _TENANT_POOL_INT
    return _TENANT_POOL_TEXT  # text + best-effort for exotic (caveated)


def _session_a_value(identity_type: str, b_val: object) -> object:
    """A session-tenant A value of `identity_type`, distinct from the row's B.

    The session GUC is cast to `identity_type` by the auth stub (uuid for
    ``auth.uid()``, etc.), so A must be of that type — independent of the
    discriminator COLUMN type that B uses. When the two types coincide (a uuid
    column scoped by ``auth.uid()``), A is drawn from the same pool and forced
    ``!= B`` so the FIXED-policy repro returns zero rows. When they differ, any
    pool value is already distinct from B (a uuid never equals a text 'tenant_b'
    under the policy's typed comparison)."""
    pool = _tenant_pool(identity_type)
    return next((x for x in pool if x != b_val), pool[0])


def _tenant_b_value(data_type: str, pinned: object | None) -> object:
    """The leaking row's tenant B — a value of the discriminator's COLUMN type:
    the proof's pinned value when it fixed one (a hardcoded ``tenant = 'X'``),
    else a pool member. The session's tenant A is synthesized separately by
    ``_session_a_value`` (it follows the auth *identity* type, not the column)
    and forced distinct from B there."""
    pool = _tenant_pool(data_type)
    return pinned if pinned is not None else pool[1]


def _current_setting_guc(node: object) -> str | None:
    """The GUC name in a ``current_setting('<guc>'[, …])`` call, else None."""
    if not isinstance(node, FuncCall):
        return None
    _, bare = func_name_parts(node)
    if (bare or "").lower() != "current_setting":
        return None
    args = node.args or ()
    if not args:
        return None
    first = args[0]
    if isinstance(first, TypeCast):  # `'app.x'::text` → unwrap the cast
        first = first.arg
    if isinstance(first, A_Const) and isinstance(first.val, String):
        return str(first.val.sval)
    return None


def _identity_value_type(auth_sql: str) -> str | None:
    """The type a fixed stub cast forces the session-identity GUC string to, or
    ``None`` when the discriminator column type should decide it.

    Two cast layers sit between the GUC and the policy's ``column = identity``
    comparison: the auth STUB's internal cast (``auth.uid()`` →
    ``current_setting(...)::uuid`` — innermost, so it dominates) and the
    POLICY's own cast on the auth expression (``current_setting('x', true)::uuid``,
    ``auth.uid()::text``). When the stub casts (``auth.uid()`` → uuid,
    ``auth.jwt()`` → jsonb) the GUC value MUST be that type — a uuid even under
    an outer ``::text`` — or the stub raises before the leak SELECT. Otherwise
    (a direct ``current_setting(...)``, ``auth.role()``, a NULL-stubbed custom
    helper — all plain-text GUCs with no inner cast) the value must satisfy the
    policy's own cast, which is exactly the discriminator column type the
    equality compares to; return ``None`` so the caller uses it."""
    try:
        node = parse_sql(f"SELECT {auth_sql}")[0].stmt.targetList[0].val
    except Exception:  # pragma: no cover - canon SQL always re-parses
        node = None
    if _current_setting_guc(node) is not None:
        return None  # plain-text GUC; the policy's cast (= column type) decides
    qualified = _funccall_qualified(node) or ""
    return _AUTH_IDENTITY_VALUE_TYPE.get(qualified)


def _session_identity_setup(
    auth_sql: str, a_text: str
) -> tuple[list[str], str | None]:
    """Statement(s) making the session-identity auth value evaluate to tenant A.

    The auth.* builtins and the NULL-stubbed custom helpers all read a JWT-claim
    GUC, so the universal lever is to SET that GUC to A; a direct
    ``current_setting('<guc>', …)`` identity sets its own GUC. `a_text` is the
    A value rendered for `_identity_value_type(auth_sql)` (uuid/jsonb/text), so
    the stub's cast (e.g. ``::uuid``) succeeds. Returns ``(statements,
    caveat)`` — `caveat` is non-None for an unusual identity shape (e.g.
    ``auth.jwt()``) the repro sets best-effort."""
    try:
        node = parse_sql(f"SELECT {auth_sql}")[0].stmt.targetList[0].val
    except Exception:  # pragma: no cover - canon SQL always re-parses
        node = None
    guc = _current_setting_guc(node)
    caveat: str | None = None
    if guc is None:
        qualified = _funccall_qualified(node) or ""
        if qualified == "auth.jwt":
            caveat = (
                "the session identity is auth.jwt(); the repro sets "
                "request.jwt.claim.sub best-effort — adjust the claim if the "
                "policy reads a specific JWT field"
            )
        guc = _AUTH_IDENTITY_GUC.get(qualified, _DEFAULT_IDENTITY_GUC)
    return (
        [f"SELECT set_config({_sql_str(guc)}, {_sql_str(a_text)}, true);"],
        caveat,
    )


def _build_cross_tenant_statements(
    table: Table,
    policy: Policy,
    witness: dict[str, object],
    repro_table: str,
    auth_functions: set[str],
    session: tuple[str, str],
) -> tuple[list[str], str, list[str], list[str], str | None]:
    """(setup, leak_query, unpinned, null_columns, identity_caveat) for the
    cross-tenant reproduction. `session` is (discriminator column, session-auth
    SQL). The session is authenticated as tenant A; the inserted row's
    discriminator is tenant B (≠ A) — a *different* tenant's row — which the
    leaking policy nonetheless returns."""
    qtbl = quote_ident(repro_table)
    setup, runner = _common_setup(table, policy, repro_table, auth_functions)
    disc_col, auth_sql = session
    disc = _column_map(table).get(disc_col)
    disc_type = disc.data_type if disc is not None else "text"
    # B is the leaking row's discriminator — synthesized for the COLUMN type so
    # the INSERT is valid. A is the session's tenant — synthesized for the
    # IDENTITY type (what the auth stub casts the GUC to: uuid for auth.uid(),
    # text for current_setting(), …), so the stub's cast doesn't crash before
    # the leak SELECT. The two are kept distinct (same pool → forced !=; cross-
    # type → already !=) so a FIXED policy returns zero rows.
    b_val = _tenant_b_value(disc_type, witness.get(disc_col))
    a_val = _session_a_value(_identity_value_type(auth_sql) or disc_type, b_val)

    # The leaking row: discriminator = tenant B (≠ the session's A) plus the
    # witness's other characterizing columns. Reuse the anon row builder with
    # the discriminator pinned to B.
    row_witness = {k: v for k, v in witness.items() if k != disc_col}
    if disc is not None:
        row_witness[disc_col] = b_val
    row, unpinned, null_fallback = _row_columns(table, row_witness)
    _insert_row(setup, qtbl, row)

    # Become an authenticated session whose tenant is A, then drop into the
    # non-superuser runner so FORCE RLS + the policy decide visibility.
    id_stmts, id_caveat = _session_identity_setup(auth_sql, str(a_val))
    setup.extend(id_stmts)
    setup.append(f"SET LOCAL ROLE {quote_ident(runner)};")

    leak_query = f"SELECT * FROM {qtbl};"
    if disc is None:  # discriminator not in the throwaway table — flag it
        id_caveat = (
            f"discriminator column {disc_col} is not in the table's columns; "
            "the inserted row may not carry a distinct tenant — hand-edit it"
        )
    return setup, leak_query, unpinned, null_fallback, id_caveat


def _sql_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _witness_phrase(witness: dict[str, object] | None, mode: str = "anon") -> str:
    if mode == "cross-tenant":
        if witness is None:
            return (
                "a conditional cross-tenant leak — the proof could not isolate a "
                "single characterizing row, so the synthesized row may not trigger it"
            )
        if not witness:
            return "a row of any other tenant is readable"
        pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
        return f"a row of another tenant with {pairs} is readable"
    if witness is None:
        return (
            "a conditional anonymous-read leak — the proof could not isolate a "
            "single characterizing row, so the synthesized row may not trigger it"
        )
    if not witness:
        return "every row is anonymously readable (unconditional leak)"
    pairs = ", ".join(f"{k}={v!r}" for k, v in sorted(witness.items()))
    return f"a row with {pairs} is anonymously readable"


def _compute_stem(schema: str, table: str, policy: str) -> str:
    """A sanitized, policy-inclusive identifier for the artifact filenames and
    test function — ``public_docs_p``. Non-word runs collapse to ``_``."""
    return (
        re.sub(r"\W+", "_", f"{schema}_{table}_{policy}").strip("_").lower()
        or "repro"
    )


def _one_line(s: str) -> str:
    """Collapse whitespace (incl. newlines) to single spaces for display on a
    single-line ``--`` comment / docstring line — a newline would otherwise
    break out of the SQL header comment."""
    return re.sub(r"\s+", " ", s).strip()


def _doc_safe(s: str) -> str:
    """Escape a value for a triple-double-quoted Python docstring: neutralize
    backslashes and double quotes so an embedded triple-double-quote run (e.g. a
    policy literal containing adjacent quotes) can't terminate the docstring and
    make the generated test invalid Python."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_repro(
    table: Table,
    policy: Policy,
    witness: dict[str, object] | None,
    auth_functions: set[str] | None = None,
    *,
    stem: str | None = None,
    mode: str = "anon",
    session: tuple[str, str] | None = None,
) -> ReproArtifact:
    """Build the .sql + pytest reproduction for one leaking (table, policy).

    `witness` is verify's counterexample: a characterizing row, ``{}`` for an
    unconditional leak, or ``None`` for a conditional leak the prover could not
    pin to a single row (the emitted row is then best-effort and the header says
    so). `auth_functions` are the auth-context names (default: the SEC038 set) —
    schema-qualified custom helpers get a synthesized stub so the policy is still
    creatable. `stem` overrides the derived file/test identifier (``emit_repros``
    passes a de-duplicated one when two (table, policy) triples sanitize alike).

    `mode` selects the threat model the reproduction demonstrates. ``"anon"``
    (default): the final SELECT runs as an unauthenticated session. ``"cross-
    tenant"`` (requires `session` = the ``(discriminator column, session-auth
    SQL)`` from `cross_tenant_session_identity`): the session is authenticated as
    tenant A and the inserted row belongs to a *different* tenant B, which the
    leaking policy nonetheless returns.

    Requires `table.column_details` to be populated — `pgrls verify` always
    supplies it via live introspection. An empty `column_details` cannot
    produce a runnable reproduction (a column-referencing policy would emit a
    CREATE POLICY for a column the throwaway table lacks), so this raises rather
    than silently emit broken SQL; `verify` has no schema source that could
    yield an empty one.
    """
    if not table.column_details:
        raise ValueError(
            "build_repro requires the table's column_details (verify supplies "
            f"them via live introspection); {table.qualified_name} has none, so "
            "a runnable reproduction cannot be synthesized."
        )
    auth = set(auth_functions) if auth_functions is not None else set(DEFAULT_AUTH_FUNCTIONS)
    # Stub every schema-qualified function the policy references, not only those
    # in the anon set: a custom helper (e.g. auth.user_id) the user didn't pass
    # via --auth-function still appears in the CREATE POLICY and must exist in
    # the throwaway database, or it fails with UndefinedFunction.
    stub_auth = auth | set(_referenced_function_arities(policy.using_ast))
    # policy-inclusive so two leaking policies on one table don't collide on
    # filename or test-function name; sanitized to a valid identifier.
    if stem is None:
        stem = _compute_stem(table.schema, table.name, policy.name)
    repro_table = f"repro_{table.name}"

    if mode == "cross-tenant" and session is None:
        raise ValueError(
            "build_repro(mode='cross-tenant') requires session — the "
            "(discriminator, session-auth SQL) pair from "
            "cross_tenant_session_identity()."
        )
    is_xt = mode == "cross-tenant"
    id_caveat: str | None = None
    if is_xt:
        assert session is not None  # the guard above ensures this
        setup, leak_query, unpinned, null_fallback, id_caveat = (
            _build_cross_tenant_statements(
                table, policy, witness or {}, repro_table, stub_auth, session
            )
        )
    else:
        setup, leak_query, unpinned, null_fallback = _build_statements(
            table, policy, witness or {}, repro_table, stub_auth
        )

    kind = "cross-tenant" if is_xt else "anonymous-read"
    kind_article = "a" if is_xt else "an"  # "a cross-tenant" / "an anonymous-read"
    test_suffix = "cross_tenant_leak" if is_xt else "anon_leak"
    actor = "authenticated tenant-A" if is_xt else "anonymous"
    session_line = (
        (
            "-- The final SELECT runs as a non-superuser session authenticated as\n"
            "-- tenant A; the row(s) below belong to a DIFFERENT tenant — which RLS\n"
            "-- should have hidden. Runs in a throwaway database (rolled back).\n"
        )
        if is_xt
        else (
            "-- The final SELECT runs as an anonymous, non-superuser session and\n"
            "-- returns the row(s) below — which RLS should have hidden. Runs in a\n"
            "-- throwaway database (everything is rolled back).\n"
        )
    )

    custom_auth = _custom_auth_functions(stub_auth)
    caveats = (
        "-- Placeholder values are synthesized for columns the proof does not\n"
        "-- pin; a cross-table policy (referencing another table/subquery) may\n"
        "-- need edits.\n"
    )
    if witness is None:
        caveats += (
            "-- NOTE: this is a CONDITIONAL leak — the placeholder row may not\n"
            "-- satisfy the policy predicate; edit the INSERT to a row that does.\n"
        )
    if unpinned:
        cols = ", ".join(unpinned)
        caveats += (
            f"-- NOTE: column(s) {cols} were left symbolic by the proof (a\n"
            "-- don't-care) and use a placeholder. If the SELECT returns no rows\n"
            "-- they are load-bearing — edit the INSERT to a value that leaks.\n"
        )
    if null_fallback:
        ncols = ", ".join(null_fallback)
        caveats += (
            f"-- NOTE: NOT NULL column(s) {ncols} have an unrecognized type and\n"
            "-- use a NULL placeholder; if the type is a NOT NULL domain the INSERT\n"
            "-- will fail — edit it to a valid value.\n"
        )
    if custom_auth:
        stub_desc = (
            "stubbed to read the session tenant (the JWT-claim GUC set above)"
            if is_xt
            else "stubbed to return NULL"
        )
        caveats += (
            f"-- NOTE: custom auth function(s) {', '.join(custom_auth)} are\n"
            f"-- {stub_desc} (return type inferred from the policy comparison\n"
            "-- where possible); adjust it if CREATE POLICY type-errors.\n"
        )
    if id_caveat:
        caveats += f"-- NOTE: {id_caveat}.\n"
    header = (
        f"-- pgrls verify --emit-repro: {kind} leak reproduction\n"
        f"-- Table:  {table.qualified_name}\n"
        f"-- Policy: {policy.name}  USING ({_one_line(policy.using_sql or '')})\n"
        f"-- Leak:   {_witness_phrase(witness, mode)}\n"
        f"{session_line}"
        f"{caveats}"
    )
    sql = (
        header
        + "\nBEGIN;\n\n"
        + "\n".join(setup)
        + f"\n\n{leak_query}  -- ⇐ LEAK: returns the row\n\nROLLBACK;\n"
    )

    setup_repr = "[\n" + "".join(
        f"    {_py_str(s)},\n" for s in setup
    ) + "]"
    pytest_filename = f"test_{stem}.py"
    if witness is None:
        # A conditional leak: the synthesized placeholder row may not satisfy the
        # predicate, so the test can fail even though the leak is real. Don't
        # claim the crisp PASSES/FAILS contract (mirrors the .sql header caveat).
        assert_doc = (
            f"The test asserts the {actor} SELECT returns the row. NOTE: this is a\n"
            "CONDITIONAL leak (see the Leak line above) — the synthesized placeholder\n"
            "row may not satisfy the policy, so the test can fail until you hand-edit\n"
            "the INSERT to a leaking row. Everything is rolled back."
        )
    else:
        assert_doc = (
            f"The test asserts the {actor} SELECT returns the row — i.e. it PASSES\n"
            "while the leak exists and FAILS once the policy is fixed. Everything is\n"
            "rolled back."
        )
    pytest = f'''"""Reproduction of {kind_article} {kind} RLS leak proven by `pgrls verify`.

Table:  {_doc_safe(table.qualified_name)}
Policy: {_doc_safe(policy.name)}  USING ({_doc_safe(_one_line(policy.using_sql or ''))})
Leak:   {_doc_safe(_witness_phrase(witness, mode))}

Run against a throwaway Postgres:
    DATABASE_URL=postgresql://... pytest {pytest_filename}

{assert_doc}
"""
import os

import psycopg
import pytest

_SETUP = {setup_repr}

_LEAK_QUERY = {_py_str(leak_query)}


@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="set DATABASE_URL to a throwaway Postgres to run this reproduction",
)
def test_{stem}_{test_suffix}() -> None:
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            for stmt in _SETUP:
                cur.execute(stmt)
            cur.execute(_LEAK_QUERY)
            rows = cur.fetchall()
        conn.rollback()
    assert rows, (
        "{kind} leak did NOT reproduce (0 rows) — the policy may "
        "already be fixed, or the reproduction needs a hand-edit."
    )
'''
    return ReproArtifact(
        stem=stem,
        sql=sql,
        pytest=pytest,
        sql_filename=f"{stem}.sql",
        pytest_filename=pytest_filename,
    )


def _py_str(s: str) -> str:
    """Render a SQL statement as a valid Python string literal. ``repr`` always
    produces one (multi-line SQL becomes a single ``\\n``-escaped line), which
    is safe to paste into the generated pytest and runs identically."""
    return repr(s)


def emit_repros(
    schema: Schema,
    verification: Verification,
    auth_functions: set[str] | None = None,
    mode: str = "anon",
) -> list[ReproArtifact]:
    """One ReproArtifact per leaking (table, permissive policy) in the run.

    Re-joins the verification verdicts back to the schema's Table/Policy objects
    (which carry the column types + USING SQL the artifacts need).
    `auth_functions` mirrors what `build_verification` used so a custom auth
    helper referenced by a policy is stubbed in the reproduction. `mode` selects
    the threat model (must match the verification's): ``"cross-tenant"`` derives
    each leak's ``(discriminator, session identity)`` and emits a cross-tenant
    reproduction; ``"anon"`` (default) emits the anonymous-read reproduction.
    """
    tables = {t.qualified_name: t for t in schema.tables}
    artifacts: list[ReproArtifact] = []
    seen_stems: set[str] = set()
    for tv in verification.tables:
        if tv.verdict != "leak":
            continue
        table = tables.get(tv.qualified_name)
        if table is None:  # pragma: no cover - verification is built from schema
            continue
        policies = {p.name: p for p in table.policies}
        for proof in tv.proofs:
            if proof.verdict != "leak":
                continue
            policy = policies.get(proof.policy)
            if policy is None:  # pragma: no cover - proof names a real policy
                continue
            session: tuple[str, str] | None = None
            if mode == "cross-tenant":
                # The single scoping pair the prover verified — a LEAK always
                # has exactly one, so this is None only on a (defensive) schema
                # divergence, in which case we skip rather than emit a
                # mislabeled anon repro for a cross-tenant leak.
                session = cross_tenant_session_identity(
                    policy.using_ast, auth_functions
                )
                if session is None:  # pragma: no cover - leak guarantees a pair
                    continue
            stem = _compute_stem(table.schema, table.name, policy.name)
            if stem in seen_stems:
                # Distinct (schema, table, policy) triples can sanitize to the
                # same stem (e.g. "my-doc" and "my_doc"); disambiguate with a
                # deterministic suffix so neither artifact silently overwrites
                # the other when the CLI writes them to disk.
                digest = hashlib.sha1(
                    f"{table.schema}.{table.name}.{policy.name}".encode()
                ).hexdigest()[:8]
                stem = f"{stem}_{digest}"
            seen_stems.add(stem)
            artifacts.append(
                build_repro(
                    table,
                    policy,
                    proof.witness,
                    auth_functions,
                    stem=stem,
                    mode=mode,
                    session=session,
                )
            )
    return artifacts
