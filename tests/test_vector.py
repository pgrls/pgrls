"""`pgrls vector` — RAG retrieval-path leak probe.

The live cases run against **pgvector**, not the shared `postgres:16-alpine`
fixture, because the whole feature keys on a real `vector` column. The image is
resolved from ``PGRLS_TEST_PGVECTOR_IMAGE`` (default ``pgvector/pgvector:pg16``)
so CI can pin it per Postgres-version matrix leg, mirroring the shared
conftest's ``PGRLS_TEST_PG_IMAGE``. The container is module-scoped and started
here rather than in `conftest.py` so the other suites keep their image
untouched.

Each live test pins a specific failure mode an earlier design got wrong, so the
verdict can never silently regress to a false clear.
"""
from __future__ import annotations

import os
from collections.abc import Generator

import psycopg
import pytest

from pgrls.model import Column, SecdefFunction, Table
from pgrls.model import Schema as ModelSchema
from pgrls.vector import (
    VectorAudit,
    VectorResult,
    _arg_candidates,
    _synthesize_arg_tuples,
    _vector_columns,
    discover_paths,
    render_json,
    render_text,
    run_vector_audit,
    unanalyzed_secdef_languages,
)


def _docker_available() -> bool:
    try:
        import docker  # noqa: PLC0415

        docker.from_env().ping()
        return True
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available for the pgvector probe"
)

# Every function here is SQL SECURITY DEFINER over the same RLS-protected
# `sections` table; a static rule (SEC014) cannot tell the leaking ones from the
# safe ones — executing the path can.
_SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;
CREATE ROLE web_user NOLOGIN;
CREATE ROLE svc NOLOGIN;
GRANT USAGE ON SCHEMA public TO web_user, svc;

CREATE TABLE docs (id int PRIMARY KEY, owner_id text);
CREATE TABLE sections (
    id int PRIMARY KEY,
    document_id int REFERENCES docs(id),
    content text,
    embedding vector(3)
);
ALTER TABLE sections ENABLE ROW LEVEL SECURITY;
ALTER TABLE sections FORCE ROW LEVEL SECURITY;
CREATE POLICY p_web ON sections FOR SELECT TO web_user
  USING (document_id IN (SELECT id FROM docs WHERE owner_id = current_setting('app.uid', true)));
GRANT SELECT ON sections, docs TO web_user, svc;
INSERT INTO docs VALUES (1,'alice'),(2,'bob');
INSERT INTO sections VALUES
  (1,1,'ALICE TOP SECRET','[1,0,0]'),
  (2,2,'bob doc','[0,1,0]');

-- LEAK: cosine-distance threshold `<=> < t`. A permissive `0` threshold would
-- filter every row out (dist < 0 is empty); the probe must try both extremes.
CREATE FUNCTION match_l2(query_embedding vector(3), match_threshold float, match_count int)
RETURNS TABLE(id int, content text) LANGUAGE sql SECURITY DEFINER AS $$
  SELECT s.id, s.content FROM sections s
  WHERE s.embedding <=> query_embedding < match_threshold
  ORDER BY s.embedding <=> query_embedding LIMIT match_count $$;
GRANT EXECUTE ON FUNCTION match_l2 TO web_user, svc;

-- SAFE: re-applies the tenant filter in its own body.
CREATE FUNCTION match_safe(query_embedding vector(3), match_count int)
RETURNS TABLE(id int, content text) LANGUAGE sql SECURITY DEFINER AS $$
  SELECT s.id, s.content FROM sections s
  WHERE s.document_id IN (SELECT d.id FROM docs d WHERE d.owner_id = current_setting('app.uid', true))
  ORDER BY s.embedding <=> query_embedding LIMIT match_count $$;
GRANT EXECUTE ON FUNCTION match_safe TO web_user;

-- SAFE but TRANSFORMS content: a full-row EXCEPT would flag the caller's own
-- upper()'d row as "extra"; primary-key correlation must not.
CREATE FUNCTION match_transform(query_embedding vector(3), match_count int)
RETURNS TABLE(id int, content text) LANGUAGE sql SECURITY DEFINER AS $$
  SELECT s.id, upper(s.content) FROM sections s
  WHERE s.document_id IN (SELECT d.id FROM docs d WHERE d.owner_id = current_setting('app.uid', true))
  ORDER BY s.id LIMIT match_count $$;
GRANT EXECUTE ON FUNCTION match_transform TO web_user;

-- LEAK via RETURNS SETOF <relation>: columns come from the relation.
CREATE FUNCTION match_setof(query_embedding vector(3))
RETURNS SETOF sections LANGUAGE sql SECURITY DEFINER AS $$
  SELECT * FROM sections ORDER BY id $$;
GRANT EXECUTE ON FUNCTION match_setof TO web_user;

-- LEAK with a hardcoded LIMIT and no filter: truncation must never read as safe.
CREATE FUNCTION match_fixed(query_embedding vector(3))
RETURNS TABLE(id int, content text) LANGUAGE sql SECURITY DEFINER AS $$
  SELECT s.id, s.content FROM sections s ORDER BY s.id LIMIT 1 $$;
GRANT EXECUTE ON FUNCTION match_fixed TO web_user;

-- Non-SQL body: the parser can't read it, so it must be surfaced as a recall gap.
CREATE FUNCTION match_plpgsql(query_embedding vector(3))
RETURNS SETOF sections LANGUAGE plpgsql SECURITY DEFINER AS $$
  BEGIN RETURN QUERY SELECT * FROM sections; END $$;
GRANT EXECUTE ON FUNCTION match_plpgsql TO web_user;

-- SAFE but returns a DIFFERENT, ungated table's rows, reading `sections` only in
-- ORDER BY. Its `id` is not a `sections` key, so it must not be a false leak.
CREATE TABLE pub (id int PRIMARY KEY, content text);
INSERT INTO pub VALUES (999, 'public blurb');
GRANT SELECT ON pub TO web_user;
CREATE FUNCTION match_join(query_embedding vector(3), match_count int)
RETURNS TABLE(id int, content text) LANGUAGE sql SECURITY DEFINER AS $$
  SELECT p.id, p.content FROM pub p, sections s
  ORDER BY s.embedding <=> query_embedding LIMIT match_count $$;
GRANT EXECUTE ON FUNCTION match_join TO web_user;

-- A non-superuser login role that can introspect and become web_user, used to
-- prove the probe abstains when its 'all rows' baseline can't be trusted.
CREATE ROLE auditor LOGIN PASSWORD 'aud' NOSUPERUSER NOBYPASSRLS;
GRANT web_user TO auditor;
GRANT SELECT ON sections, docs, pub TO auditor;

-- LEAK with a char(n) PRIMARY KEY: the provenance re-read must compare the key
-- at its real type, not widen to text (which strips char(n) blank-padding).
CREATE TABLE sec_char (code char(12) PRIMARY KEY, owner_id text, content text, embedding vector(3));
ALTER TABLE sec_char ENABLE ROW LEVEL SECURITY;
ALTER TABLE sec_char FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sec_char FOR SELECT TO web_user
  USING (owner_id = current_setting('app.uid', true));
GRANT SELECT ON sec_char TO web_user;
INSERT INTO sec_char VALUES ('AL', 'alice', 'CHAR ALICE SECRET', '[1,0,0]'), ('BO', 'bob', 'bob', '[0,1,0]');
CREATE FUNCTION match_char(q vector(3), n int) RETURNS TABLE(code char(12), content text)
  LANGUAGE sql SECURITY DEFINER AS $$
    SELECT s.code, s.content FROM sec_char s ORDER BY s.embedding <=> q LIMIT n $$;
GRANT EXECUTE ON FUNCTION match_char TO web_user;

-- LEAK where the function returns a `json` column (no equality operator): the
-- leak query must not `DISTINCT` over it, or it errors and the path abstains.
CREATE TABLE sec_json (id int PRIMARY KEY, owner_id text, meta json, content text, embedding vector(3));
ALTER TABLE sec_json ENABLE ROW LEVEL SECURITY;
ALTER TABLE sec_json FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sec_json FOR SELECT TO web_user
  USING (owner_id = current_setting('app.uid', true));
GRANT SELECT ON sec_json TO web_user;
INSERT INTO sec_json VALUES (1, 'alice', '{"k":1}', 'JSON ALICE SECRET', '[1,0,0]'),
                            (2, 'bob', '{"k":2}', 'bob', '[0,1,0]');
CREATE FUNCTION match_json(q vector(3), n int) RETURNS TABLE(id int, meta json, content text)
  LANGUAGE sql SECURITY DEFINER AS $$
    SELECT s.id, s.meta, s.content FROM sec_json s ORDER BY s.embedding <=> q LIMIT n $$;
GRANT EXECUTE ON FUNCTION match_json TO web_user;

-- A permissive USING(true) policy for svc makes its direct read unfiltered.
CREATE POLICY p_svc ON sections FOR SELECT TO svc USING (true);

-- Canary for the SQL-injection test: a malicious --probe-role must not drop it.
CREATE TABLE canary (id int);

-- Mixed-case schema/table/function: identifiers must be quoted, not down-cased.
CREATE SCHEMA "App";
CREATE TABLE "App"."Sections" (id int PRIMARY KEY, "docId" int, content text, embedding vector(3));
ALTER TABLE "App"."Sections" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "App"."Sections" FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON "App"."Sections" FOR SELECT TO web_user
  USING ("docId" = (current_setting('app.uid_int', true))::int);
GRANT USAGE ON SCHEMA "App" TO web_user;
GRANT SELECT ON "App"."Sections" TO web_user;
INSERT INTO "App"."Sections" VALUES (1, 100, 'MIXEDCASE ALICE', '[1,0,0]'), (2, 200, 'mixed bob', '[0,1,0]');
CREATE FUNCTION "App"."matchLeaky"(q vector(3), n int)
RETURNS TABLE(id int, content text) LANGUAGE sql SECURITY DEFINER AS $$
  SELECT s.id, s.content FROM "App"."Sections" s ORDER BY s.embedding <=> q LIMIT n $$;
GRANT EXECUTE ON FUNCTION "App"."matchLeaky" TO web_user;
"""


@pytest.fixture(scope="module")
def pgvector_url() -> Generator[str, None, None]:
    from testcontainers.postgres import PostgresContainer  # noqa: PLC0415

    image = os.environ.get("PGRLS_TEST_PGVECTOR_IMAGE", "pgvector/pgvector:pg16")
    with PostgresContainer(
        image, username="postgres", password="postgres", dbname="postgres"
    ) as pg:
        url = pg.get_connection_url(driver=None)
        with psycopg.connect(url, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(_SCHEMA_SQL)
        yield url


# --- pure units (no database) ----------------------------------------------


def _tbl(*cols: tuple[str, str], rls: bool = True) -> Table:
    return Table(
        schema="public",
        name="sections",
        rls_enabled=rls,
        force_rls=True,
        policies=(),
        column_details=tuple(
            Column(name=n, data_type=t, is_nullable=True) for n, t in cols
        ),
    )


def test_vector_columns_captures_dimension() -> None:
    cols = _vector_columns(_tbl(("id", "integer"), ("embedding", "vector(1536)")))
    assert cols == [("embedding", 1536)]


def test_vector_columns_accepts_unconstrained_vector() -> None:
    assert _vector_columns(_tbl(("e", "vector"))) == [("e", None)]


def test_vector_columns_ignores_non_vector() -> None:
    assert _vector_columns(_tbl(("id", "integer"), ("body", "text"))) == []


def test_arg_candidates_vector_is_non_zero() -> None:
    # A zero vector makes cosine/inner-product distance NaN, and `NaN < t` is
    # false — which would silently filter every row out. Must be non-zero.
    got = _arg_candidates("vector", 3)
    assert got == ["'[1,0,0]'::vector(3)"]


def test_arg_candidates_unconstrained_vector_abstains() -> None:
    # Without a dimension the literal can't be sized correctly.
    assert _arg_candidates("vector", None) is None


def test_arg_candidates_threshold_tries_both_extremes() -> None:
    # A float threshold could gate either direction; both must be offered.
    assert _arg_candidates("double precision", None) == ["1000000000", "-1000000000"]


def test_arg_candidates_int_is_generous() -> None:
    assert _arg_candidates("integer", None) == ["1000"]


def test_arg_candidates_unknown_type_abstains() -> None:
    assert _arg_candidates("my_custom_enum", None) is None
    assert _arg_candidates("tsvector", 3) is None  # not an embeddings vector


def test_synthesize_tuples_spans_threshold_extremes() -> None:
    tuples = _synthesize_arg_tuples(["vector", "double precision", "integer"], 3)
    assert tuples == [
        "'[1,0,0]'::vector(3), 1000000000, 1000",
        "'[1,0,0]'::vector(3), -1000000000, 1000",
    ]


def test_synthesize_tuples_abstains_on_unknown() -> None:
    assert _synthesize_arg_tuples(["vector", "my_enum"], 3) is None


def test_synthesize_tuples_handles_no_args() -> None:
    assert _synthesize_arg_tuples([], None) == [""]


def test_discover_paths_links_secdef_function_to_embeddings_table() -> None:
    schema = ModelSchema(
        tables=(_tbl(("id", "integer"), ("embedding", "vector(3)")),),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.match_docs",
                body="SELECT id FROM sections",
                language="sql",
                search_path=None,
                signature="q vector, n integer",
                schema_name="public",
                function_name="match_docs",
                execute_roles=("authenticated",),
                owner_bypasses_rls=True,
            ),
        ),
    )
    [path] = discover_paths(schema)
    assert path.function == "public.match_docs"
    assert path.function_schema == "public" and path.function_name == "match_docs"
    assert path.table == "public.sections"
    assert path.table_schema == "public" and path.table_name == "sections"
    assert path.dimension == 3


def test_discover_paths_ignores_table_without_rls() -> None:
    schema = ModelSchema(
        tables=(_tbl(("embedding", "vector(3)"), rls=False),),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.m",
                body="SELECT id FROM sections",
                language="sql",
                search_path=None,
                signature="q vector",
                schema_name="public",
                function_name="m",
                execute_roles=("authenticated",),
                owner_bypasses_rls=True,
            ),
        ),
    )
    assert discover_paths(schema) == []


def test_unanalyzed_languages_reports_non_sql_only() -> None:
    def _fn(name: str, lang: str) -> SecdefFunction:
        return SecdefFunction(
            qualified_name=f"public.{name}",
            body="",
            language=lang,
            search_path=None,
            signature="q vector",
            schema_name="public",
            function_name=name,
            execute_roles=("authenticated",),
            owner_bypasses_rls=True,
        )

    schema = ModelSchema(
        tables=(),
        security_definer_functions=(
            _fn("a", "sql"),
            _fn("b", "plpgsql"),
            _fn("c", "plpython3u"),
        ),
    )
    assert unanalyzed_secdef_languages(schema) == {"plpgsql", "plpython3u"}


def test_render_text_reports_no_path_found() -> None:
    assert "No RAG retrieval path" in render_text(VectorAudit(()))


def test_render_text_no_isolated_label() -> None:
    # There is no isolation-proving verdict; a clean spot-check is NO LEAK.
    from pgrls.vector import _LABEL

    assert "isolated" not in _LABEL and set(_LABEL) == {"leak", "no_leak", "abstained"}


def test_render_json_is_valid_and_carries_evidence() -> None:
    import json

    from pgrls.vector import RetrievalPath

    audit = VectorAudit(
        (
            VectorResult(
                path=RetrievalPath(
                    table="public.t",
                    table_schema="public",
                    table_name="t",
                    embedding_column="e",
                    dimension=3,
                    function="public.f",
                    function_schema="public",
                    function_name="f",
                    signature="q vector",
                    execute_roles=("authenticated",),
                    owner_bypasses_rls=True,
                ),
                verdict="leak",
                detail="d",
                probe_role="authenticated",
                leaked_rows=("(id=1)",),
            ),
        ),
        unanalyzed_languages=("plpgsql",),
    )
    doc = json.loads(render_json(audit))
    assert doc["summary"]["leak"] == 1
    assert doc["paths"][0]["leaked_rows"] == ["(id=1)"]
    assert doc["unanalyzed_languages"] == ["plpgsql"]


# --- live probe (pgvector) --------------------------------------------------


@requires_docker
def test_leak_is_proven_and_safe_variant_is_not_flagged(pgvector_url: str) -> None:
    """The headline: SECDEF alone is not the finding, and the probe discriminates.

    Probed as `web_user` with bob's identity, the leaking distance-threshold
    function hands back alice's chunk; the tenant-refiltering one does not.
    """
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )

    by_fn = {(r.path.function, r.probe_role): r for r in audit.results}

    # finding #1: a `<=> < threshold` shape must not read as clean — try extremes.
    leaky = by_fn[("public.match_l2", "web_user")]
    assert leaky.verdict == "leak"
    assert any("ALICE TOP SECRET" in row for row in leaky.leaked_rows)
    assert not any("bob doc" in row for row in leaky.leaked_rows)

    # the safe, refiltering variant is NO LEAK — never a false leak, never PROVEN.
    assert by_fn[("public.match_safe", "web_user")].verdict == "no_leak"
    assert audit.has_leak


@requires_docker
def test_transformed_column_is_not_a_false_leak(pgvector_url: str) -> None:
    """finding #4: a safe function that upper()'s content it is allowed to
    return must not look like a leak. PK correlation, not full-row EXCEPT."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    r = next(x for x in audit.results if x.path.function == "public.match_transform")
    assert r.verdict == "no_leak", r.detail
    assert not r.leaked_rows


@requires_docker
def test_setof_relation_result_is_probed(pgvector_url: str) -> None:
    """finding #9: RETURNS SETOF <relation> is a real retrieval shape; its
    columns come from the relation, and it must be probed, not abstained."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    r = next(x for x in audit.results if x.path.function == "public.match_setof")
    assert r.verdict == "leak"
    assert any("ALICE TOP SECRET" in row for row in r.leaked_rows)


@requires_docker
def test_quoted_mixed_case_identifiers(pgvector_url: str) -> None:
    """finding #6: a camelCase schema/table/function must be quoted — an
    unquoted `::regclass` down-cases and aborts the whole run."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["App"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid_int": "200"}
        )
    assert audit.results, "the mixed-case path must be discovered, not skipped"
    r = audit.results[0]
    assert r.path.function == 'App."matchLeaky"' or r.path.function.endswith("matchLeaky")
    assert r.verdict == "leak"
    assert any("MIXEDCASE ALICE" in row for row in r.leaked_rows)


@requires_docker
def test_using_true_grantee_abstains(pgvector_url: str) -> None:
    """finding #3: a role with a USING(true) policy has an unfiltered baseline,
    so the differential is vacuous — abstain, never report a clean spot-check."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="svc", settings={"app.uid": "bob"}
        )
    r = next(x for x in audit.results if x.path.function == "public.match_l2")
    assert r.verdict == "abstained"
    assert "does not restrict" in r.detail


@requires_docker
def test_all_grantees_probed_when_no_probe_role(pgvector_url: str) -> None:
    """finding #3 (second half): auto-picking one grantee could pick the
    USING(true) role and exit 0. Every concrete grantee must be probed."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(conn, schema, settings={"app.uid": "bob"})
    roles = {
        r.probe_role for r in audit.results if r.path.function == "public.match_l2"
    }
    assert roles == {"web_user", "svc"}
    # the leak is surfaced regardless of which grantee sorts first
    assert audit.has_leak


@requires_docker
def test_malicious_probe_role_is_not_executed(pgvector_url: str) -> None:
    """finding #5: a --probe-role must be a quoted identifier, never executed as
    SQL. The canary table must survive the rolled-back probe."""
    from pgrls.introspect import introspect

    payload = "postgres; DROP TABLE public.canary; --"
    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        run_vector_audit(conn, schema, probe_role=payload, settings={"app.uid": "bob"})

    with psycopg.connect(pgvector_url, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_name='canary'"
        )
        row = cur.fetchone()
        assert row is not None and row[0] == 1, "the canary table was dropped!"


@requires_docker
def test_hardcoded_limit_leak_is_detected(pgvector_url: str) -> None:
    """finding #2: a function with a hardcoded small LIMIT still leaks; probed as
    the tenant the truncated row is denied to, it must read as a leak."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    r = next(x for x in audit.results if x.path.function == "public.match_fixed")
    assert r.verdict == "leak"
    assert any("ALICE TOP SECRET" in row for row in r.leaked_rows)


@requires_docker
def test_owner_probe_abstains(pgvector_url: str) -> None:
    """Soundness guard: probing as the RLS-exempt owner makes the direct read
    unfiltered, so a leaking path would look clean. Detect it and abstain."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="postgres", settings={"app.uid": "bob"}
        )
    assert audit.results
    assert all(r.verdict == "abstained" for r in audit.results)
    assert not audit.has_leak
    assert any("does not restrict" in r.detail for r in audit.results)


@requires_docker
def test_cross_relation_key_is_not_a_false_leak(pgvector_url: str) -> None:
    """A function that RETURNs a same-named key from a DIFFERENT (ungated) table,
    reading the embeddings table only in ORDER BY, denies nothing of this table's
    — provenance must drop it, so it reads no_leak, not a false leak."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    r = next(x for x in audit.results if x.path.function == "public.match_join")
    assert r.verdict == "no_leak", r.detail
    assert not r.leaked_rows


@requires_docker
def test_rls_subject_connection_abstains(pgvector_url: str) -> None:
    """Soundness: if pgrls is connected as an RLS-subject role, the 'all rows'
    baseline the differential rests on is itself filtered. It must abstain
    honestly — never silently exit 0 while a superuser run reports the leak."""
    from pgrls.introspect import introspect

    # Same host/port, but authenticate as the non-superuser `auditor`.
    auditor_url = pgvector_url.replace("postgres:postgres@", "auditor:aud@")
    with psycopg.connect(auditor_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    assert audit.results
    assert not audit.has_leak
    assert all(r.verdict == "abstained" for r in audit.results)
    assert any("subject to RLS" in r.detail for r in audit.results)


@requires_docker
def test_char_primary_key_leak_is_detected(pgvector_url: str) -> None:
    """A char(n) PK must survive the provenance re-read: widening the key to
    text strips its blank-padding, so a real leak would silently drop to
    no_leak. It must read leak."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    r = next(x for x in audit.results if x.path.function == "public.match_char")
    assert r.verdict == "leak", r.detail
    assert any("CHAR ALICE SECRET" in row for row in r.leaked_rows)


@requires_docker
def test_json_result_column_leak_is_detected(pgvector_url: str) -> None:
    """A function returning a `json` column (no equality operator) must not make
    the leak query's DISTINCT error out into an abstain — it must read leak."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    r = next(x for x in audit.results if x.path.function == "public.match_json")
    assert r.verdict == "leak", r.detail
    assert any("JSON ALICE SECRET" in row for row in r.leaked_rows)


@requires_docker
def test_plpgsql_recall_gap_is_surfaced(pgvector_url: str) -> None:
    """finding #8: a PL/pgSQL retrieval function yields no path (SQL-only
    parser). That recall gap must be reported, not silently a clean bill."""
    from pgrls.introspect import introspect

    with psycopg.connect(pgvector_url) as conn:
        schema = introspect(conn, ["public"])
        audit = run_vector_audit(
            conn, schema, probe_role="web_user", settings={"app.uid": "bob"}
        )
    assert "plpgsql" in audit.unanalyzed_languages
    assert not any("match_plpgsql" in r.path.function for r in audit.results)
    assert "not analyzed" in render_text(audit)
