"""Unit tests for VIEW004 — view through SECDEF function reading RLS table."""
from __future__ import annotations

import pytest

from pgrls.model import Schema, SecdefFunction, Table, View
from pgrls.rules.view004 import VIEW004


def _table(
    schema: str,
    name: str,
    *,
    rls: bool,
    force: bool = True,
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=(),
    )


def _view(
    schema: str = "public",
    name: str = "v",
    *,
    is_materialized: bool = False,
    security_invoker: bool = True,
    security_barrier: bool = False,
    references: tuple[tuple[str, str], ...] = (),
    security_definer_calls: tuple[str, ...] = (),
    definition: str = "SELECT 1",
) -> View:
    # `security_invoker=True` by default so VIEW004 fixtures can
    # focus on the SECDEF-call-from-view case without VIEW001
    # cross-firing semantics in the test schemas. (VIEW004 doesn't
    # actually read security_invoker, but the rule's spec carves
    # out distinct architectural ground from VIEW001.)
    return View(
        schema=schema,
        name=name,
        is_materialized=is_materialized,
        security_invoker=security_invoker,
        security_barrier=security_barrier,
        definition=definition,
        references=references,
        security_definer_calls=security_definer_calls,
    )


def _secdef(
    qname: str,
    body: str,
    *,
    language: str = "sql",
) -> SecdefFunction:
    return SecdefFunction(
        qualified_name=qname,
        body=body,
        language=language,
    )


def test_view004_fires_when_secdef_function_reads_rls_table() -> None:
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.read_secret",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_secret",
                "SELECT * FROM public.secret",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    v = violations[0]
    assert v.rule_id == "VIEW004"
    assert v.severity == "warning"
    assert v.location == "public.secret_view"
    assert "public.secret_view" in v.message
    assert "public.read_secret" in v.message
    assert "public.secret" in v.message
    assert "SECURITY DEFINER" in v.message


def test_view004_does_not_fire_when_secdef_function_reads_non_rls_table() -> None:
    schema = Schema(
        tables=(_table("public", "data", rls=False),),
        views=(
            _view(
                schema="public",
                name="data_view",
                security_definer_calls=("public.read_data",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_data",
                "SELECT * FROM public.data",
            ),
        ),
    )
    assert VIEW004().check(schema, options={}) == []


def test_view004_does_not_fire_for_invoker_function_reading_rls_table() -> None:
    # The view calls a function that reads an RLS-protected table, but
    # the function is NOT SECURITY DEFINER (so it's INVOKER, the
    # default). That's VIEW001 territory only — VIEW004 must stay
    # silent because there's no `security_definer_calls` entry.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=(),  # No SECDEF calls.
            ),
        ),
        # No SECDEF function registered — modeling the INVOKER case.
        security_definer_functions=(),
    )
    assert VIEW004().check(schema, options={}) == []


def test_view004_skips_unparseable_function_body_with_stderr_warning(
    capsys,
) -> None:
    # Per design spec: emit stderr warning + skip when pglast can't
    # parse the body. The rule must NOT fire for that function.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.cant_parse",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.cant_parse",
                "this is not valid SQL ::: $$ garbage",
            ),
        ),
    )
    out = VIEW004().check(schema, options={})
    assert out == []
    captured = capsys.readouterr()
    assert "pgrls: warning" in captured.err
    assert "public.cant_parse" in captured.err


def test_view004_skips_plpgsql_function_with_stderr_warning(capsys) -> None:
    # PL/pgSQL bodies start with DECLARE/BEGIN and are not parseable
    # as a top-level pglast statement. Skip explicitly with a
    # less-alarming "non-SQL language" warning so the user knows the
    # function wasn't analyzed.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.dynamic",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.dynamic",
                "DECLARE r RECORD; BEGIN RETURN; END;",
                language="plpgsql",
            ),
        ),
    )
    out = VIEW004().check(schema, options={})
    assert out == []
    captured = capsys.readouterr()
    assert "pgrls: warning" in captured.err
    assert "public.dynamic" in captured.err
    assert "plpgsql" in captured.err


def test_view004_allowlist_exempts_qualified_view_name() -> None:
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.read_secret",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_secret",
                "SELECT * FROM public.secret",
            ),
        ),
    )
    assert VIEW004().check(
        schema, options={"allowlist": ["public.secret_view"]}
    ) == []


def test_view004_bad_allowlist_type_raises_clearly() -> None:
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.read_secret",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_secret",
                "SELECT * FROM public.secret",
            ),
        ),
    )
    with pytest.raises(TypeError, match="allowlist"):
        VIEW004().check(
            schema, options={"allowlist": "public.secret_view"}  # type: ignore[arg-type]
        )


def test_view004_bare_name_allowlist_entry_raises_clearly() -> None:
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.read_secret",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_secret",
                "SELECT * FROM public.secret",
            ),
        ),
    )
    with pytest.raises(TypeError, match="VIEW004"):
        VIEW004().check(
            schema, options={"allowlist": ["secret_view"]}
        )


def test_view004_does_not_fire_when_no_rls_tables_anywhere() -> None:
    # Even if a view calls a SECDEF function reading some table,
    # VIEW004 has nothing to flag if none of the tables in scope
    # have RLS enabled.
    schema = Schema(
        tables=(_table("public", "data", rls=False),),
        views=(
            _view(
                schema="public",
                name="data_view",
                security_definer_calls=("public.read_data",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_data",
                "SELECT * FROM public.data",
            ),
        ),
    )
    assert VIEW004().check(schema, options={}) == []


def test_view004_does_not_fire_for_view_without_secdef_calls() -> None:
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=(),
            ),
        ),
        security_definer_functions=(),
    )
    assert VIEW004().check(schema, options={}) == []


def test_view004_message_joins_multiple_function_qnames_sorted() -> None:
    # A view that calls two SECDEF functions, each reading the same
    # RLS-protected table, fires once per view with both function
    # qnames in the message. Format mirrors VIEW001's comma-joined
    # sorted shape.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.fn_a", "public.fn_b"),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.fn_a",
                "SELECT * FROM public.secret",
            ),
            _secdef(
                "public.fn_b",
                "SELECT * FROM public.secret",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    msg = violations[0].message
    assert "public.fn_a, public.fn_b" in msg
    assert "public.secret" in msg


def test_view004_message_joins_multiple_leaked_tables_sorted() -> None:
    # A SECDEF function that reads from two RLS tables — both names
    # appear comma-joined, sorted.
    schema = Schema(
        tables=(
            _table("public", "alpha", rls=True),
            _table("public", "beta", rls=True),
        ),
        views=(
            _view(
                schema="public",
                name="multi_view",
                security_definer_calls=("public.read_both",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_both",
                "SELECT a.id, b.id FROM public.alpha a JOIN public.beta b ON a.id = b.id",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    msg = violations[0].message
    assert "public.alpha, public.beta" in msg


def test_view004_handles_multi_statement_function_body() -> None:
    # A SQL function body can contain multiple statements; VIEW004
    # must walk every parsed statement, not just the first.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.multi_stmt",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.multi_stmt",
                "SELECT 1; SELECT * FROM public.secret;",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    assert "public.secret" in violations[0].message


def test_view004_resolves_bare_table_name_in_function_body() -> None:
    # `pg_proc.prosrc` may emit either qualified (`public.secret`)
    # or bare (`secret`) names depending on how the function was
    # written. Both forms must resolve.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.read_secret",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_secret",
                "SELECT * FROM secret",  # bare, no schema prefix
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    assert "public.secret" in violations[0].message


def test_view004_bare_name_collision_reports_all_rls_candidates() -> None:
    # Two RLS-protected tables in different schemas share the same
    # bare name (`core.user` and `staging.user`). A SECDEF function
    # body that says `SELECT * FROM "user"` can't be unambiguously
    # attributed — the actual target depends on the search_path the
    # function ran with. VIEW004 over-reports rather than under-
    # attributes: emit BOTH qualified candidates so the operator sees
    # every RLS-protected table that could leak. Under-attribution in
    # a security check would let the operator dismiss the warning
    # while the other table is still vulnerable; over-attribution at
    # most produces a false positive the operator can allowlist.
    schema = Schema(
        tables=(
            _table("core", "user", rls=True),
            _table("staging", "user", rls=True),
        ),
        views=(
            _view(
                schema="public",
                name="vw",
                security_definer_calls=("public.read_user",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_user",
                "SELECT * FROM \"user\"",  # bare, ambiguous across schemas
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    msg = violations[0].message
    assert "core.user" in msg
    assert "staging.user" in msg


def test_view004_skips_secdef_function_with_empty_body() -> None:
    # A SECDEF function whose body parses to zero statements (empty,
    # whitespace, or comment-only) yields no range vars to inspect.
    # `pglast.parse_sql` returns an empty list — VIEW004 must skip it
    # cleanly (the `if not parsed: continue` guard) rather than index
    # into `parsed[0]`.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="secret_view",
                security_definer_calls=("public.empty_fn",),
            ),
        ),
        security_definer_functions=(
            _secdef("public.empty_fn", "  -- nothing here\n"),
        ),
    )
    assert VIEW004().check(schema, options={}) == []


def test_view004_does_not_fire_when_function_reads_no_table() -> None:
    # SECDEF function exists, view calls it, but the function body
    # doesn't read any table (e.g. a pure scalar computation).
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="vw",
                security_definer_calls=("public.now_ts",),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.now_ts",
                "SELECT now()",
            ),
        ),
    )
    assert VIEW004().check(schema, options={}) == []


def test_view004_skips_function_not_in_secdef_set() -> None:
    # A view's `security_definer_calls` references a function that's
    # not in `Schema.security_definer_functions` (e.g. lives in a
    # schema we didn't introspect). The rule must skip it cleanly,
    # not crash.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="vw",
                security_definer_calls=("private.read",),
            ),
        ),
        security_definer_functions=(),  # Not present.
    )
    assert VIEW004().check(schema, options={}) == []


def test_view004_fires_independently_per_offending_view() -> None:
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="bad_a",
                security_definer_calls=("public.read_secret",),
            ),
            _view(
                schema="public",
                name="bad_b",
                security_definer_calls=("public.read_secret",),
            ),
            _view(
                schema="public",
                name="good",
                security_definer_calls=(),
            ),
        ),
        security_definer_functions=(
            _secdef(
                "public.read_secret",
                "SELECT * FROM public.secret",
            ),
        ),
    )
    locations = sorted(v.location for v in VIEW004().check(schema, {}))
    assert locations == ["public.bad_a", "public.bad_b"]


def test_view004_does_not_fire_on_schema_with_no_views() -> None:
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(),
        security_definer_functions=(),
    )
    assert VIEW004().check(schema, options={}) == []


# ──────────────────────────────────────────────────────────────────
# Overload handling (snapshot v12+)
# ──────────────────────────────────────────────────────────────────


def test_view004_analyzes_every_overload_body_per_qname() -> None:
    # Snapshot v12+ captures one `SecdefFunction` entry per overload.
    # A previous dict-comprehension `{q: f for f in ...}` was last-
    # wins on duplicate qnames, so VIEW004 only analyzed the
    # lex-last overload's body. If two overloads share a qname and
    # only the NON-last overload reads an RLS table, the rule would
    # miss the leak. Pin the fix: walking every overload's body.
    #
    # In the v12 `ORDER BY qname, signature` order, `integer` sorts
    # before `text` — so `text` is the "last" overload. The leak is
    # in the `integer` (non-last) overload's body: pre-fix, VIEW004
    # would NOT flag this; post-fix, it must.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="leaky",
                security_definer_calls=("public.lookup",),
            ),
        ),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.lookup",
                # The (integer) overload reads the RLS-protected
                # table — the leak.
                body="SELECT * FROM public.secret",
                language="sql",
                signature="integer",
            ),
            SecdefFunction(
                qualified_name="public.lookup",
                # The (text) overload — the lex-last in v12 ordering
                # — reads nothing protected. Pre-fix this would
                # win the dict-comprehension last-wins and VIEW004
                # would silently report no leak.
                body="SELECT 1",
                language="sql",
                signature="text",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    assert violations[0].location == "public.leaky"
    assert "public.secret" in violations[0].message
    # Function name appears in the message (not the signature — the
    # rule reports per qualified name, the fixer per overload).
    assert "public.lookup" in violations[0].message


def test_view004_handles_overloads_with_different_languages(
    capsys,
) -> None:
    # One overload is `sql` (parseable), one is `plpgsql` (skipped
    # with stderr warning). The parseable one reads an RLS table —
    # VIEW004 must flag the leak from the SQL overload even though
    # the plpgsql one was skipped.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="leaky",
                security_definer_calls=("public.lookup",),
            ),
        ),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.lookup",
                body="SELECT * FROM public.secret",
                language="sql",
                signature="integer",
            ),
            SecdefFunction(
                qualified_name="public.lookup",
                body="BEGIN PERFORM 1; END",
                language="plpgsql",
                signature="text",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    assert violations[0].location == "public.leaky"
    # The plpgsql overload's stderr warning names the specific
    # overload so the operator knows which one wasn't analyzed.
    err = capsys.readouterr().err
    assert "public.lookup(text)" in err
    assert "plpgsql" in err


def test_view004_collapses_leaks_across_overloads_to_one_violation() -> None:
    # If multiple overloads of the same qname each leak (different
    # RLS tables, say), VIEW004 emits ONE violation per view —
    # collapsing the per-overload leaks into the leaked-tables CSV
    # in the message. The view-level granularity matches existing
    # behavior; the new per-overload analysis only widens what's
    # found.
    schema = Schema(
        tables=(
            _table("public", "secret_a", rls=True),
            _table("public", "secret_b", rls=True),
        ),
        views=(
            _view(
                schema="public",
                name="leaky",
                security_definer_calls=("public.lookup",),
            ),
        ),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.lookup",
                body="SELECT * FROM public.secret_a",
                language="sql",
                signature="integer",
            ),
            SecdefFunction(
                qualified_name="public.lookup",
                body="SELECT * FROM public.secret_b",
                language="sql",
                signature="text",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    # Both leaked tables appear in the message (sorted CSV).
    assert "public.secret_a" in violations[0].message
    assert "public.secret_b" in violations[0].message


def test_view004_unsignatured_pre_v12_overload_still_analyzed() -> None:
    # A pre-v12 snapshot has `signature=""` (the older introspection
    # didn't capture argument types). VIEW004 must still parse and
    # analyze the body — the missing signature only affects how the
    # stderr warning names the overload, not whether it's checked.
    schema = Schema(
        tables=(_table("public", "secret", rls=True),),
        views=(
            _view(
                schema="public",
                name="leaky",
                security_definer_calls=("public.lookup",),
            ),
        ),
        security_definer_functions=(
            SecdefFunction(
                qualified_name="public.lookup",
                body="SELECT * FROM public.secret",
                language="sql",
                signature="",
            ),
        ),
    )
    violations = VIEW004().check(schema, options={})
    assert len(violations) == 1
    assert "public.secret" in violations[0].message
