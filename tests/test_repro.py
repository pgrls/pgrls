"""Tests for `pgrls verify --emit-repro` — the leak-reproduction emitter."""
from __future__ import annotations

import ast as pyast

import psycopg
import pytest
from pglast import parse_sql

from pgrls.diff._z3_compare import cross_tenant_session_identity
from pgrls.model import Column, Policy, Schema, Table
from pgrls.repro import (
    _UUID_RE,
    _row_columns,
    _witness_literal,
    build_repro,
    emit_repros,
)
from pgrls.verify import build_verification


def _docker_available() -> bool:
    try:
        import docker  # noqa: PLC0415

        docker.from_env().ping()
        return True
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available for live reproduction"
)


def _ast(using: str):
    return parse_sql(f"SELECT 1 WHERE {using}")[0].stmt.whereClause


def _policy(
    using: str, *, name: str = "p", roles: tuple[str, ...] = ("authenticated",)
) -> Policy:
    return Policy(
        name=name, command="SELECT", permissive=True, roles=roles,
        using_sql=using, with_check_sql=None, using_ast=_ast(using), with_check_ast=None,
    )


def _col(name: str, data_type: str, nullable: bool = True) -> Column:
    return Column(name=name, data_type=data_type, is_nullable=nullable)


def _table(policy: Policy, *, columns: tuple[Column, ...]) -> Table:
    return Table(
        schema="public", name="docs", rls_enabled=True, force_rls=True,
        policies=(policy,), column_details=columns,
    )


_COLS = (
    _col("id", "bigint", nullable=False),
    _col("tenant_id", "uuid"),
    _col("is_public", "boolean", nullable=False),
    _col("body", "text", nullable=False),
)


# --- SQL artifact ----------------------------------------------------------


def test_sql_has_schema_policy_insert_and_anon_select() -> None:
    pol = _policy("auth.uid() IS NULL OR tenant_id = auth.uid()")
    art = build_repro(_table(pol, columns=_COLS), pol, {})
    sql = art.sql
    assert sql.startswith("-- pgrls verify --emit-repro")
    assert "BEGIN;" in sql and sql.rstrip().endswith("ROLLBACK;")
    # schema rebuilt from column_details, policy verbatim, anon SELECT
    assert "CREATE TABLE repro_docs" in sql
    # quote_ident emits safe lowercase names bare (valid SQL).
    assert "id bigint" in sql and "is_public boolean" in sql
    assert "USING (auth.uid() IS NULL OR tenant_id = auth.uid())" in sql
    assert "ALTER TABLE repro_docs FORCE ROW LEVEL SECURITY;" in sql
    assert "SELECT * FROM repro_docs;" in sql
    # NOT NULL columns get placeholders; nullable tenant_id omitted (→ NULL)
    assert "INSERT INTO repro_docs (id, is_public, body)" in sql


def test_characterizing_witness_pins_the_leak_column() -> None:
    pol = _policy("is_public OR tenant_id = auth.uid()")
    art = build_repro(_table(pol, columns=_COLS), pol, {"is_public": True})
    insert = art.sql.split("INSERT INTO repro_docs")[1].split(";")[0]
    # the witness value (is_public=True) is pinned, not a placeholder
    assert "is_public" in insert and "true" in insert


def test_non_public_role_is_created_nosuperuser_and_assumed() -> None:
    pol = _policy("true", roles=("authenticated",))
    sql = build_repro(_table(pol, columns=_COLS), pol, {}).sql
    # NOSUPERUSER so SET ROLE actually subjects the session to FORCE RLS.
    assert "CREATE ROLE authenticated NOLOGIN NOSUPERUSER NOBYPASSRLS" in sql
    assert "SET LOCAL ROLE authenticated;" in sql


def test_public_policy_runs_as_nonsuperuser_runner() -> None:
    # A PUBLIC policy must NOT run the leak SELECT as the (superuser) connection
    # role — that bypasses RLS and makes the repro unsound. It creates and
    # switches into a dedicated NOSUPERUSER runner.
    pol = _policy("true", roles=("public",))
    sql = build_repro(_table(pol, columns=_COLS), pol, {}).sql
    assert "CREATE ROLE pgrls_repro_runner NOLOGIN NOSUPERUSER NOBYPASSRLS" in sql
    assert "SET LOCAL ROLE pgrls_repro_runner;" in sql
    assert "GRANT USAGE ON SCHEMA auth TO PUBLIC;" in sql
    assert "TO PUBLIC" in sql


def test_uppercase_public_pseudo_role_is_not_a_named_role() -> None:
    # Live introspection renders the PUBLIC pseudo-role as the literal 'PUBLIC'
    # (introspect maps polroles OID 0 → 'PUBLIC'). The repro must treat it as
    # PUBLIC, not invent a spurious quoted "PUBLIC" application role: grant
    # TO PUBLIC + run as the dedicated pgrls_repro_runner.
    pol = _policy("auth.uid() IS NULL OR tenant_id = auth.uid()", roles=("PUBLIC",))
    sql = build_repro(_table(pol, columns=_COLS), pol, {}).sql
    assert 'CREATE ROLE "PUBLIC"' not in sql  # no spurious quoted role
    assert 'SET LOCAL ROLE "PUBLIC";' not in sql
    assert "CREATE ROLE pgrls_repro_runner NOLOGIN NOSUPERUSER NOBYPASSRLS" in sql
    assert "SET LOCAL ROLE pgrls_repro_runner;" in sql
    assert "GRANT SELECT ON repro_docs TO PUBLIC, pgrls_repro_runner;" in sql
    assert "FOR SELECT TO PUBLIC\n" in sql  # CREATE POLICY uses the PUBLIC keyword


def test_custom_auth_function_is_stubbed() -> None:
    # A policy using a custom auth helper → the repro stubs it (else CREATE
    # POLICY fails with UndefinedFunction) + flags the return-type caveat.
    pol = _policy("auth.user_id() IS NULL OR tenant_id = body", roles=("public",))
    art = build_repro(
        _table(pol, columns=_COLS), pol, {},
        auth_functions={"auth.uid", "auth.role", "auth.jwt", "current_setting", "auth.user_id"},
    )
    assert "CREATE OR REPLACE FUNCTION auth.user_id()" in art.sql
    assert "custom auth function(s) auth.user_id" in art.sql


def test_custom_auth_function_stubbed_without_explicit_flag() -> None:
    # R10 MED: the DEFAULT path (no --auth-function) must still stub a custom
    # helper the policy references — discovered from the USING AST — else the
    # generated CREATE POLICY fails with UndefinedFunction in the throwaway DB.
    pol = _policy("auth.user_id() IS NULL OR is_public", roles=("public",))
    art = build_repro(_table(pol, columns=_COLS), pol, {})  # no auth_functions
    assert "CREATE OR REPLACE FUNCTION auth.user_id()" in art.sql
    assert "custom auth function(s) auth.user_id" in art.sql
    # a catalog-schema function is never stubbed (it always exists)
    assert "CREATE OR REPLACE FUNCTION pg_catalog" not in art.sql


def test_custom_auth_stub_return_type_inferred() -> None:
    # R12 MED: the stub return type is inferred from the policy comparison so a
    # `tenant_id = auth.user_id()` (uuid) policy type-checks at CREATE POLICY
    # instead of failing "operator does not exist: uuid = text".
    cols = (
        _col("id", "bigint", nullable=False),
        _col("tenant_id", "uuid", nullable=False),
    )
    pol = _policy(
        "tenant_id = auth.user_id() OR auth.user_id() IS NULL", roles=("public",)
    )
    sql = build_repro(_table(pol, columns=cols), pol, {}).sql
    assert "CREATE OR REPLACE FUNCTION auth.user_id() RETURNS uuid" in sql
    assert "'')::uuid $$" in sql  # body cast to the inferred type


def test_custom_auth_stub_matches_call_arity() -> None:
    # R20 MED: a custom helper called WITH arguments needs a matching-arity stub
    # (anyelement params), else CREATE POLICY fails "function auth.has_access(uuid)
    # does not exist" — a zero-arg stub is insufficient.
    cols = (
        _col("id", "bigint", nullable=False),
        _col("tenant_id", "uuid", nullable=False),
    )
    pol = _policy(
        "auth.has_access(tenant_id) IS NULL OR auth.uid() IS NULL", roles=("public",)
    )
    sql = build_repro(_table(pol, columns=cols), pol, {}).sql
    assert "CREATE OR REPLACE FUNCTION auth.has_access(anyelement) RETURNS" in sql


def test_symbolic_text_witness_is_flagged() -> None:
    # R20 LOW: Z3's free-String placeholder ('!0!') for a don't-care TEXT column
    # is routed to a placeholder + flagged unpinned (not emitted verbatim as if
    # pinned). An empty string '' is preserved — it can be a load-bearing value.
    cols = (
        _col("id", "bigint", nullable=False),
        _col("note", "text", nullable=False),
    )
    table = _table(_policy("true"), columns=cols)
    _, unpinned, _ = _row_columns(table, {"note": "!0!"})
    assert "note" in unpinned
    _, unpinned_empty, _ = _row_columns(table, {"note": ""})
    assert "note" not in unpinned_empty  # '' kept verbatim, not flagged


def test_array_witness_falls_back_to_placeholder() -> None:
    # A non-array string witness for an array column must NOT be emitted as a
    # scalar literal — _base_type strips the '[]', so the text branch would
    # otherwise emit a malformed array literal that crashes the INSERT. It falls
    # back to the '{}' array placeholder and the column is flagged unpinned.
    assert _witness_literal("!0!", "text[]") is None
    assert _witness_literal("abc", "uuid[]") is None
    cols = (
        _col("id", "bigint", nullable=False),
        _col("tags", "text[]", nullable=False),
    )
    table = _table(_policy("true"), columns=cols)
    ordered, unpinned, _ = _row_columns(table, {"tags": "!0!"})
    assert "tags" in unpinned
    assert dict(ordered)["tags"] == "'{}'"  # the array placeholder, not '!0!'


def test_conditional_leak_header_caveat() -> None:
    # witness=None (conditional leak the prover couldn't pin) → no false
    # "unconditional" claim; a loud caveat that the row may not trigger it.
    pol = _policy("true", roles=("public",))
    art = build_repro(_table(pol, columns=_COLS), pol, None)
    assert "conditional anonymous-read leak" in art.sql
    assert "CONDITIONAL leak" in art.sql  # the INSERT caveat


def test_header_always_carries_cross_table_caveat() -> None:
    # Every generated .sql header notes that placeholders are synthesized and a
    # cross-table policy may need edits — unconditionally, even for a plain
    # characterized leak.
    pol = _policy("auth.uid() IS NULL OR tenant_id = auth.uid()")
    art = build_repro(_table(pol, columns=_COLS), pol, {})
    assert "cross-table" in art.sql
    assert "referencing another table/subquery" in art.sql


def test_placeholder_types() -> None:
    # NOT NULL columns of assorted types all get insertable literals.
    cols = (
        _col("a", "integer", nullable=False),
        _col("b", "boolean", nullable=False),
        _col("c", "uuid", nullable=False),
        _col("d", "jsonb", nullable=False),
        _col("e", "timestamptz", nullable=False),
        _col("f", "text", nullable=False),
    )
    pol = _policy("true")
    sql = build_repro(_table(pol, columns=cols), pol, {}).sql
    insert_line = next(ln for ln in sql.splitlines() if ln.startswith("INSERT INTO"))
    for tok in ("0", "false", "::uuid", "::jsonb", "now()", "''"):
        assert tok in insert_line, (tok, insert_line)


def test_symbolic_nontext_witness_falls_back_to_placeholder() -> None:
    # A Z3 don't-care value for a non-text column ('!0!') is not a valid
    # timestamptz/uuid literal — emitting '!0!'::timestamptz crashes the INSERT.
    # It must fall back to a placeholder, with a header caveat naming the column.
    cols = (
        _col("id", "bigint", nullable=False),
        _col("is_public", "boolean", nullable=False),
        _col("created_at", "timestamptz", nullable=False),
    )
    pol = _policy("is_public OR created_at <> created_at")
    art = build_repro(
        _table(pol, columns=cols), pol, {"is_public": True, "created_at": "!0!"}
    )
    insert = next(ln for ln in art.sql.splitlines() if ln.startswith("INSERT INTO"))
    assert "'!0!'" not in insert and "::timestamptz" not in insert
    assert "now()" in insert  # placeholder for the symbolic timestamptz column
    assert "true" in insert  # the real bool driver is still pinned
    assert "created_at" in art.sql and "left symbolic" in art.sql


def test_valid_typed_witness_is_preserved() -> None:
    # A witness value that IS valid for its non-text type (a real uuid from a
    # `col = 'uuid'` equality) is emitted verbatim, not replaced by a placeholder.
    cols = (_col("id", "bigint", nullable=False), _col("tenant_id", "uuid"))
    uid = "11111111-1111-1111-1111-111111111111"
    pol = _policy(f"tenant_id = '{uid}'")
    art = build_repro(_table(pol, columns=cols), pol, {"tenant_id": uid})
    insert = next(ln for ln in art.sql.splitlines() if ln.startswith("INSERT INTO"))
    assert f"'{uid}'::uuid" in insert
    assert "left symbolic" not in art.sql  # nothing was placeholdered


def test_generated_pytest_valid_with_triple_quote_in_policy_sql() -> None:
    # A policy whose SQL contains a `"""` run must not break the generated
    # pytest's docstring (would be invalid Python). _doc_safe neutralizes it.
    pol = Policy(
        name="p", command="SELECT", permissive=True, roles=("public",),
        using_sql='is_public OR body = \'a"""b\'',
        with_check_sql=None, using_ast=_ast("is_public"), with_check_ast=None,
    )
    art = build_repro(_table(pol, columns=_COLS), pol, {})
    pyast.parse(art.pytest)  # must parse as valid Python
    assert 'a\\"\\"\\"b' in art.pytest  # the run was escaped, not left raw


@pytest.mark.parametrize(
    "using",
    [
        "true",  # column-free
        "auth.uid() IS NULL OR tenant_id = auth.uid()",  # references a column
    ],
)
def test_build_repro_requires_column_details(using: str) -> None:
    # build_repro is only ever called with column_details populated (verify
    # sources its schema via live introspection, which always fills them; there
    # is no snapshot input path for verify). An empty column_details can't
    # produce a runnable reproduction — a column-referencing policy would emit a
    # CREATE POLICY for a column the throwaway table lacks (UndefinedColumn) — so
    # it raises rather than silently emit broken SQL, for BOTH the column-free
    # and the (common, inverted-auth) column-referencing shape.
    pol = _policy(using, roles=("public",))
    table = Table(
        schema="public", name="docs", rls_enabled=True, force_rls=True,
        policies=(pol,), column_details=(),
    )
    with pytest.raises(ValueError, match="column_details"):
        build_repro(table, pol, {})


def test_emit_repros_dedups_colliding_stems() -> None:
    # Two distinct tables whose names sanitize to the same stem ("my-doc" and
    # "my_doc") must get distinct filenames, not silently overwrite each other.
    t1 = Table(
        schema="public", name="my-doc", rls_enabled=True, force_rls=True,
        policies=(_policy("true", roles=("public",)),), column_details=_COLS,
    )
    t2 = Table(
        schema="public", name="my_doc", rls_enabled=True, force_rls=True,
        policies=(_policy("true", roles=("public",)),), column_details=_COLS,
    )
    schema = Schema(tables=(t1, t2))
    arts = emit_repros(schema, build_verification(schema))
    assert len(arts) == 2
    assert len({a.stem for a in arts}) == 2
    names = {a.sql_filename for a in arts} | {a.pytest_filename for a in arts}
    assert len(names) == 4  # 2 sql + 2 pytest, all distinct


def test_witness_column_absent_from_schema_is_dropped() -> None:
    # A witness column not in column_details can't be honored (it's never in the
    # throwaway CREATE TABLE); it must be dropped from the INSERT, not emitted as
    # a reference to a non-existent column (which would crash the reproduction).
    cols = (
        _col("id", "bigint", nullable=False),
        _col("is_public", "boolean", nullable=False),
    )
    pol = _policy("is_public AND extra_col")
    witness = {"is_public": True, "extra_col": True}
    table = _table(pol, columns=cols)
    insert = next(
        ln for ln in build_repro(table, pol, witness).sql.splitlines()
        if ln.startswith("INSERT INTO")
    )
    assert "extra_col" not in insert
    assert "is_public" in insert
    ordered, _, _ = _row_columns(table, witness)
    assert [n for n, _ in ordered] == ["id", "is_public"]  # extra_col dropped


def test_not_null_unrecognized_type_caveat() -> None:
    # A NOT NULL column of a type the placeholder map doesn't know (custom enum,
    # domain, …) gets a NULL placeholder; build_repro flags it (the INSERT fails
    # only for a NOT NULL domain, indistinguishable from the type name alone).
    cols = (
        _col("id", "bigint", nullable=False),
        _col("status", "order_status", nullable=False),  # custom enum-like type
    )
    pol = _policy("true", roles=("public",))
    table = _table(pol, columns=cols)
    art = build_repro(table, pol, {})
    insert = next(ln for ln in art.sql.splitlines() if ln.startswith("INSERT INTO"))
    assert "NULL" in insert  # status got a NULL placeholder
    assert "status" in art.sql and "unrecognized type" in art.sql
    _, _, null_fallback = _row_columns(table, {})
    assert null_fallback == ["status"]


def test_conditional_leak_pytest_docstring_caveat() -> None:
    # The pytest docstring must not claim the crisp "PASSES while the leak exists"
    # contract for a conditional leak (witness=None) — it carries the caveat.
    pol = _policy("true", roles=("public",))
    cond = build_repro(_table(pol, columns=_COLS), pol, None).pytest
    assert "CONDITIONAL leak" in cond and "hand-edit" in cond
    # a characterized leak keeps the crisp wording, no caveat
    plain = build_repro(_table(pol, columns=_COLS), pol, {"is_public": True}).pytest
    assert "PASSES" in plain and "CONDITIONAL leak" not in plain


# --- pytest artifact -------------------------------------------------------


def test_pytest_is_valid_python_and_unique() -> None:
    p1 = _policy("true", name="p_one")
    p2 = _policy("true", name="p_two")
    a1 = build_repro(_table(p1, columns=_COLS), p1, {})
    a2 = build_repro(_table(p2, columns=_COLS), p2, {})
    for art in (a1, a2):
        pyast.parse(art.pytest)  # parses
        assert "def test_" in art.pytest and "anon_leak" in art.pytest
        assert "DATABASE_URL" in art.pytest
    # two policies on one table → distinct filenames + stems
    assert a1.pytest_filename != a2.pytest_filename
    assert a1.sql_filename != a2.sql_filename
    assert a1.stem != a2.stem


# --- emit_repros (re-join schema + verification) ---------------------------


def test_emit_repros_only_for_leaks() -> None:
    leak = _table(_policy("true", name="leaky"), columns=_COLS)
    safe = Table(
        schema="public", name="safe", rls_enabled=True, force_rls=True,
        policies=(_policy("tenant_id = auth.uid()", name="scoped"),),
        column_details=_COLS,
    )
    schema = Schema(tables=(leak, safe))
    verification = build_verification(schema)
    artifacts = emit_repros(schema, verification)
    # only the leaking table yields a reproduction
    assert len(artifacts) == 1
    assert "docs" in artifacts[0].stem


def test_emit_repros_empty_when_no_leak() -> None:
    safe = Table(
        schema="public", name="safe", rls_enabled=True, force_rls=True,
        policies=(_policy("tenant_id = auth.uid()"),), column_details=_COLS,
    )
    schema = Schema(tables=(safe,))
    assert emit_repros(schema, build_verification(schema)) == []


# --- live reproduction (Docker) -------------------------------------------

_AUTH_STUB = (
    "CREATE SCHEMA IF NOT EXISTS auth;"
    "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS "
    "$$ SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid $$;"
)


@requires_docker
@pytest.mark.parametrize(
    "using,witness",
    [
        ("auth.uid() IS NULL OR tenant_id = auth.uid()", {}),
        ("is_public OR tenant_id = (select auth.uid())", {"is_public": True}),
    ],
)
def test_generated_sql_reproduces_the_leak_live(
    pg_url: str, using: str, witness: dict
) -> None:
    # Build the repro from a leaking policy, then RUN its SQL against a real
    # Postgres and confirm the anonymous SELECT returns the row. A non-autocommit
    # connection is required so SET LOCAL ROLE takes effect (else the SELECT runs
    # as the superuser, who bypasses RLS and would mask the test).
    pol = _policy(using)
    art = build_repro(_table(pol, columns=_COLS), pol, witness)
    setup = art.sql.split("BEGIN;", 1)[1].split("SELECT * FROM repro_docs;")[0]
    with psycopg.connect(pg_url) as conn:  # autocommit=False (default)
        with conn.cursor() as cur:
            cur.execute(setup)
            cur.execute("SELECT * FROM repro_docs;")
            rows = cur.fetchall()
        conn.rollback()
    assert rows, f"the generated reproduction did not leak for USING ({using})"


def _run_setup_and_select(pg_url: str, art) -> list:
    setup = art.sql.split("BEGIN;", 1)[1].split("SELECT * FROM repro_docs;")[0]
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(setup)
            cur.execute("SELECT * FROM repro_docs;")
            rows = cur.fetchall()
        conn.rollback()
    return rows


@requires_docker
def test_public_policy_repro_is_sound_not_a_bypass(pg_url: str) -> None:
    # The critical soundness check for PUBLIC policies: the repro must run as a
    # NON-superuser runner, so a LEAKING PUBLIC policy returns the row AND a
    # FIXED one (USING(false)) returns 0 rows. If it ran as the superuser
    # connection role it would bypass RLS and BOTH would return the row.
    leaky = _policy("auth.uid() IS NULL OR tenant_id = auth.uid()", roles=("public",))
    fixed = _policy("tenant_id = auth.uid()", roles=("public",))
    leak_rows = _run_setup_and_select(pg_url, build_repro(_table(leaky, columns=_COLS), leaky, {}))
    safe_rows = _run_setup_and_select(pg_url, build_repro(_table(fixed, columns=_COLS), fixed, {}))
    assert leak_rows, "PUBLIC leaking policy did not reproduce"
    assert not safe_rows, "PUBLIC fixed policy returned rows — the repro is bypassing RLS"


_TS_COLS = (
    _col("id", "bigint", nullable=False),
    _col("is_public", "boolean", nullable=False),
    _col("created_at", "timestamptz", nullable=False),
    _col("updated_at", "timestamptz", nullable=False),
)


@requires_docker
def test_symbolic_dontcare_witness_reproduces_via_pinned_driver_live(
    pg_url: str,
) -> None:
    # A witness shaped like a real Z3 decode: a pinned bool driver plus symbolic
    # ('!0!') timestamptz don't-cares. The repro must RUN (placeholders for the
    # symbolic values, not '!0!'::timestamptz which crashed the INSERT) AND
    # reproduce the leak via the pinned is_public=true disjunct.
    pol = _policy("is_public OR created_at <> updated_at", roles=("public",))
    art = build_repro(
        _table(pol, columns=_TS_COLS), pol,
        {"is_public": True, "created_at": "!0!", "updated_at": "!1!"},
    )
    rows = _run_setup_and_select(pg_url, art)
    assert rows, "pinned-driver leak with symbolic don't-cares did not reproduce"


@requires_docker
def test_real_prover_symbolic_witness_repro_runs_live(pg_url: str) -> None:
    # End-to-end through the real prover: the witness for this disjunctive leak
    # over timestamptz columns carries Z3-symbolic values. The generated repro
    # must RUN without a type-conversion crash (the pre-fix '!0!'::timestamptz
    # bug). Whether it reproduces depends on which disjunct Z3 pinned — the
    # header caveats the don't-care columns — so we assert only that it runs.
    pol = _policy("is_public OR created_at <> updated_at", roles=("public",))
    schema = Schema(tables=(_table(pol, columns=_TS_COLS),))
    arts = emit_repros(schema, build_verification(schema))
    assert arts
    _run_setup_and_select(pg_url, arts[0])  # must not raise a type error


@requires_docker
def test_default_path_custom_auth_repro_runs_live(pg_url: str) -> None:
    # R10 MED end-to-end: a custom auth helper NOT passed via --auth-function is
    # discovered from the AST and stubbed, so the generated CREATE POLICY runs
    # (no UndefinedFunction) and the leak reproduces (the anon stub → NULL makes
    # the `IS NULL` branch true).
    pol = _policy("auth.user_id() IS NULL OR is_public", roles=("public",))
    schema = Schema(tables=(_table(pol, columns=_COLS),))
    arts = emit_repros(schema, build_verification(schema))  # default auth set
    assert arts
    rows = _run_setup_and_select(pg_url, arts[0])
    assert rows, "default-path custom-auth repro did not run/reproduce"


@requires_docker
def test_custom_auth_typed_comparison_repro_runs_live(pg_url: str) -> None:
    # R12 MED end-to-end: a custom auth fn compared to a uuid column gets a
    # uuid-returning stub, so CREATE POLICY type-checks (no "operator does not
    # exist: uuid = text") and the leak reproduces via the IS NULL branch.
    cols = (
        _col("id", "bigint", nullable=False),
        _col("tenant_id", "uuid", nullable=False),
    )
    pol = _policy(
        "tenant_id = auth.user_id() OR auth.user_id() IS NULL", roles=("public",)
    )
    schema = Schema(tables=(_table(pol, columns=cols),))
    arts = emit_repros(schema, build_verification(schema))
    assert arts
    rows = _run_setup_and_select(pg_url, arts[0])
    assert rows, "typed custom-auth repro did not run/reproduce"


@requires_docker
def test_custom_auth_arg_taking_repro_runs_live(pg_url: str) -> None:
    # R20 MED end-to-end: an argument-taking custom helper gets an arity-matched
    # (anyelement) stub, so CREATE POLICY resolves auth.has_access(uuid) — no
    # "function does not exist" — and the leak reproduces via the IS NULL branch.
    cols = (
        _col("id", "bigint", nullable=False),
        _col("tenant_id", "uuid", nullable=False),
    )
    pol = _policy(
        "auth.has_access(tenant_id) IS NULL OR auth.uid() IS NULL", roles=("public",)
    )
    schema = Schema(tables=(_table(pol, columns=cols),))
    arts = emit_repros(schema, build_verification(schema))
    assert arts
    rows = _run_setup_and_select(pg_url, arts[0])
    assert rows, "arg-taking custom-auth repro did not run/reproduce"


@requires_docker
def test_array_witness_repro_runs_live(pg_url: str) -> None:
    # A NOT NULL array column whose witness is a Z3 don't-care string must not
    # crash the INSERT (a scalar string is a malformed array literal) — it gets
    # the '{}' placeholder. The leak reproduces via the pinned bool driver.
    cols = (
        _col("id", "bigint", nullable=False),
        _col("is_public", "boolean", nullable=False),
        _col("tags", "text[]", nullable=False),
    )
    pol = _policy("is_public OR id > 0", roles=("public",))
    art = build_repro(
        _table(pol, columns=cols), pol, {"is_public": True, "tags": "!0!"}
    )
    rows = _run_setup_and_select(pg_url, art)
    assert rows, "array-column repro did not run/reproduce"


@requires_docker
def test_non_public_runner_forced_non_bypass_live(pg_url: str) -> None:
    # A non-PUBLIC policy's runner is the policy's target role. If that role
    # pre-exists carrying BYPASSRLS, the IF NOT EXISTS create skips it — the
    # ALTER ROLE forces it NOSUPERUSER/NOBYPASSRLS so FORCE RLS applies and a
    # FIXED policy returns 0 rows (else the repro silently bypasses RLS and
    # falsely "reproduces" a leak against a correct policy).
    with psycopg.connect(pg_url, autocommit=True) as conn:
        conn.execute("DROP ROLE IF EXISTS app_user;")
        conn.execute("CREATE ROLE app_user NOLOGIN BYPASSRLS;")
    try:
        fixed = _policy("tenant_id = auth.uid()", roles=("app_user",))
        rows = _run_setup_and_select(
            pg_url, build_repro(_table(fixed, columns=_COLS), fixed, {})
        )
        assert not rows, "FIXED policy returned rows — runner bypassed RLS"
    finally:
        with psycopg.connect(pg_url, autocommit=True) as conn:
            conn.execute("DROP ROLE IF EXISTS app_user;")


# --- cross-tenant reproductions -------------------------------------------


def _xt(policy: Policy, witness: dict, *, columns: tuple[Column, ...] = _COLS):
    """Build a cross-tenant repro, deriving the session identity like the CLI."""
    table = _table(policy, columns=columns)
    session = cross_tenant_session_identity(policy.using_ast)
    return build_repro(table, policy, witness, stem="r", mode="cross-tenant", session=session)


def test_cross_tenant_sql_structure() -> None:
    art = _xt(_policy("tenant_id = auth.uid() OR is_public"), {"is_public": True})
    assert "cross-tenant leak reproduction" in art.sql
    assert "a row of another tenant with is_public=True is readable" in art.sql
    # the session is authenticated as tenant A via the JWT-claim GUC ...
    assert "set_config('request.jwt.claim.sub'" in art.sql
    assert "SET LOCAL ROLE" in art.sql
    # ... and the inserted row carries a (different) tenant_id + the bypass col
    assert "INSERT INTO repro_docs" in art.sql and "is_public" in art.sql
    assert "anonymous" not in art.sql  # not an anon repro
    assert "def test_r_cross_tenant_leak()" in art.pytest


def test_cross_tenant_current_setting_sets_that_guc() -> None:
    # A current_setting('<guc>') identity sets THAT guc, not request.jwt.claim.sub.
    art = _xt(
        _policy("tenant_id = current_setting('app.tenant_id', true)::uuid OR is_public"),
        {"is_public": True},
    )
    assert "set_config('app.tenant_id'" in art.sql
    assert "request.jwt.claim.sub" not in art.sql.split("BEGIN;", 1)[1].split(
        "set_config", 1
    )[0] or "set_config('app.tenant_id'" in art.sql


def test_cross_tenant_hardcoded_tenant_is_pinned_distinct() -> None:
    # A hardcoded `tenant = 'X'` bypass: the row is tenant X, the session is a
    # DIFFERENT tenant — both must appear and differ.
    tid = "00000000-0000-0000-0000-0000000000ff"
    art = _xt(
        _policy(f"tenant_id = auth.uid() OR tenant_id = '{tid}'"),
        {"tenant_id": tid},
    )
    insert = next(line for line in art.sql.splitlines() if line.startswith("INSERT"))
    setcfg = next(line for line in art.sql.splitlines() if "set_config" in line)
    assert tid in insert  # the row is the hardcoded leaking tenant
    assert tid not in setcfg  # the session is a different tenant


def test_cross_tenant_text_column_auth_uid_guc_is_a_uuid() -> None:
    # The session GUC the auth.uid() stub casts ::uuid must carry a UUID string
    # even when the discriminator COLUMN is text (a real `auth.uid()::text`
    # scoping shape). Synthesizing the session value from the text column type
    # ('tenant_a') made the stub's `'tenant_a'::uuid` cast crash before the leak
    # SELECT could run. The row's tenant_id (text 'tenant_b') still uses the
    # column type; only the session-identity value follows the uuid stub cast.
    cols = (
        _col("id", "bigint", nullable=False),
        _col("tenant_id", "text"),
        _col("is_public", "boolean", nullable=False),
        _col("body", "text", nullable=False),
    )
    art = _xt(
        _policy("tenant_id = auth.uid()::text OR is_public"),
        {"is_public": True},
        columns=cols,
    )
    setcfg = next(ln for ln in art.sql.splitlines() if "set_config" in ln)
    assert _UUID_RE.match(setcfg.split("'request.jwt.claim.sub', '")[1].split("'")[0])
    assert "'tenant_a'" not in setcfg  # NOT the text-pool value (would crash ::uuid)


def test_cross_tenant_pytest_is_valid_python() -> None:
    art = _xt(_policy("tenant_id = auth.uid() OR is_public"), {"is_public": True})
    pyast.parse(art.pytest)  # must be importable Python
    assert "cross-tenant RLS leak" in art.pytest
    assert "authenticated tenant-A" in art.pytest


def test_emit_repros_cross_tenant_mode() -> None:
    schema = Schema(
        tables=(_table(_policy("tenant_id = auth.uid() OR is_public"), columns=_COLS),)
    )
    v = build_verification(schema, mode="cross-tenant")
    arts = emit_repros(schema, v, mode="cross-tenant")
    assert len(arts) == 1
    assert "cross-tenant leak reproduction" in arts[0].sql


def test_emit_repros_default_mode_is_anon() -> None:
    # Regression: the default path still emits the anonymous-read repro.
    schema = Schema(
        tables=(_table(_policy("auth.uid() IS NULL OR tenant_id = auth.uid()"), columns=_COLS),)
    )
    arts = emit_repros(schema, build_verification(schema))
    assert len(arts) == 1
    assert "anonymous-read leak reproduction" in arts[0].sql


@requires_docker
@pytest.mark.parametrize(
    "using,witness",
    [
        ("tenant_id = auth.uid() OR is_public", {"is_public": True}),
        (
            "tenant_id = current_setting('app.tenant_id', true)::uuid OR is_public",
            {"is_public": True},
        ),
        (
            "tenant_id = auth.uid() OR tenant_id = '00000000-0000-0000-0000-0000000000ff'",
            {"tenant_id": "00000000-0000-0000-0000-0000000000ff"},
        ),
    ],
)
def test_cross_tenant_repro_reproduces_live(
    pg_url: str, using: str, witness: dict
) -> None:
    # RUN the cross-tenant repro against a real Postgres: authenticated as tenant
    # A, the SELECT must return the (tenant-B) row the policy should have hidden.
    rows = _run_setup_and_select(pg_url, _xt(_policy(using), witness))
    assert rows, f"the cross-tenant reproduction did not leak for USING ({using})"


@requires_docker
def test_cross_tenant_repro_row_is_a_different_tenant_live(pg_url: str) -> None:
    # The essence of the cross-tenant proof: the leaked row's tenant differs from
    # the session's own identity. Run the setup, then read both in the same txn.
    art = _xt(_policy("tenant_id = auth.uid() OR is_public"), {"is_public": True})
    setup = art.sql.split("BEGIN;", 1)[1].split("SELECT * FROM repro_docs;")[0]
    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(setup)
            cur.execute("SELECT tenant_id::text FROM repro_docs;")
            row_tenant = cur.fetchone()[0]
            cur.execute("SELECT current_setting('request.jwt.claim.sub', true);")
            session_tenant = cur.fetchone()[0]
        conn.rollback()
    assert row_tenant and session_tenant
    assert row_tenant != session_tenant, (
        "the reproduced row belongs to the SESSION's tenant — not a cross-tenant "
        "leak"
    )


@requires_docker
def test_cross_tenant_repro_is_sound_not_a_bypass(pg_url: str) -> None:
    # Soundness: the cross-tenant repro runs as a NOSUPERUSER/NOBYPASSRLS runner,
    # so a FIXED scoped policy returns 0 rows (the tenant-B row is correctly
    # hidden from the tenant-A session). If it ran as the superuser it would
    # bypass RLS and leak even the fixed policy. (`emit_repros` only emits for
    # leaks, so build the fixed-policy repro directly.)
    fixed = _policy("tenant_id = auth.uid()")
    session = cross_tenant_session_identity(fixed.using_ast)
    art = build_repro(
        _table(fixed, columns=_COLS), fixed, {}, stem="fx",
        mode="cross-tenant", session=session,
    )
    rows = _run_setup_and_select(pg_url, art)
    assert not rows, "FIXED scoped policy leaked cross-tenant — runner bypassed RLS"


_TEXT_DISC_COLS = (
    _col("id", "bigint", nullable=False),
    _col("tenant_id", "text"),
    _col("is_public", "boolean", nullable=False),
    _col("body", "text", nullable=False),
)


@requires_docker
def test_cross_tenant_text_column_auth_uid_repro_reproduces_live(pg_url: str) -> None:
    # A text tenant column scoped by `auth.uid()::text` (a real Supabase shape).
    # The auth.uid() stub casts the session GUC ::uuid, so the session-tenant A
    # value must be a UUID even though the COLUMN is text — synthesizing it from
    # the text column type ('tenant_a') crashed `'tenant_a'::uuid` before the
    # leak SELECT. The `OR is_public` row of a different tenant must come back.
    leaky = _policy("tenant_id = auth.uid()::text OR is_public", roles=("public",))
    rows = _run_setup_and_select(
        pg_url, _xt(leaky, {"is_public": True}, columns=_TEXT_DISC_COLS)
    )
    assert rows, "text-column auth.uid()::text cross-tenant leak did not reproduce"


@requires_docker
def test_cross_tenant_text_column_auth_uid_fixed_is_sound_live(pg_url: str) -> None:
    # The fixed counterpart of the above: a scoped `tenant_id = auth.uid()::text`
    # must return 0 rows (the tenant-B text row is hidden from the tenant-A uuid
    # session) — proving the repro is sound, not a bypass, for the mismatched
    # column/identity-type case the leak path exercises.
    fixed = _policy("tenant_id = auth.uid()::text", roles=("public",))
    session = cross_tenant_session_identity(fixed.using_ast)
    art = build_repro(
        _table(fixed, columns=_TEXT_DISC_COLS), fixed, {}, stem="fx",
        mode="cross-tenant", session=session,
    )
    rows = _run_setup_and_select(pg_url, art)
    assert not rows, "FIXED text-column auth.uid()::text leaked — repro is unsound"
