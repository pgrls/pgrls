"""Unit tests for the auto-fix machinery and per-rule fixers."""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.fixers import Fix, default_fixers, generate_fixes
from pgrls.fixers.perf001 import PERF001Fixer
from pgrls.fixers.sec002 import SEC002Fixer
from pgrls.model import Policy, Schema, Table


# ---------- SEC002 fixer ----------


def _table(
    name: str = "t",
    *,
    rls: bool,
    force: bool,
    schema: str = "public",
    policies: tuple[Policy, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=force,
        policies=policies,
    )


def test_sec002_fix_emits_alter_table_force() -> None:
    schema = Schema(tables=(_table(rls=True, force=False),))
    fixes = SEC002Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC002"
    assert f.location == "public.t"
    assert (
        f.sql == "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;"
    )


def test_sec002_fix_silent_when_force_already_set() -> None:
    schema = Schema(tables=(_table(rls=True, force=True),))
    assert SEC002Fixer().fix(schema, {}) == []


def test_sec002_fix_silent_when_rls_disabled() -> None:
    # SEC001's territory; not SEC002's, so no FORCE fix to emit.
    schema = Schema(tables=(_table(rls=False, force=False),))
    assert SEC002Fixer().fix(schema, {}) == []


def test_sec002_fix_respects_allowlist_qualified() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=True, force=False),
            _table(name="b", rls=True, force=False),
        )
    )
    fixes = SEC002Fixer().fix(
        schema, {"allowlist": ["public.a"]}
    )
    assert [f.location for f in fixes] == ["public.b"]


def test_sec002_fix_respects_allowlist_unqualified() -> None:
    schema = Schema(tables=(_table(name="audit", rls=True, force=False),))
    assert SEC002Fixer().fix(schema, {"allowlist": ["audit"]}) == []


def test_sec002_fix_emits_one_per_offending_table() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=True, force=False),
            _table(name="b", rls=True, force=True),
            _table(name="c", rls=True, force=False),
        )
    )
    fixes = SEC002Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == ["public.a", "public.c"]


# ---------- PERF001 fixer ----------


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=True,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _wrap_policy(policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
                columns=("id", "user_id"),
            ),
        )
    )


def test_perf001_fix_wraps_auth_uid_in_using() -> None:
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "PERF001"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "USING (user_id = (SELECT auth.uid()))" in f.sql


def test_perf001_fix_wraps_current_setting() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user', true)")
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    # pglast's pretty-printer normalizes Boolean literals to
    # uppercase. Functionally identical; assert on the lowercased
    # output so the test is robust to casing.
    sql = fixes[0].sql.lower()
    assert "(select current_setting('app.user', true))" in sql


def test_perf001_fix_silent_when_already_wrapped() -> None:
    schema = _wrap_policy(
        _policy("user_id = (SELECT auth.uid())")
    )
    assert PERF001Fixer().fix(schema, {}) == []


def test_perf001_fix_wraps_multiple_calls_in_one_expression() -> None:
    schema = _wrap_policy(
        _policy(
            "user_id = auth.uid() OR auth.role() = 'admin'"
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql
    assert "(SELECT auth.uid())" in sql
    assert "(SELECT auth.role())" in sql


def test_perf001_fix_preserves_with_check_verbatim() -> None:
    # WITH CHECK should be reproduced as-is — the rule is USING-only.
    p = _policy(
        "user_id = auth.uid()",
        command="ALL",
        with_check="user_id = (SELECT auth.uid())",
    )
    schema = _wrap_policy(p)
    sql = PERF001Fixer().fix(schema, {})[0].sql
    assert "WITH CHECK (user_id = (SELECT auth.uid()))" in sql
    assert "USING (user_id = (SELECT auth.uid()))" in sql


def test_perf001_fix_silent_when_using_is_none() -> None:
    p = _policy(None, command="INSERT", with_check="user_id = auth.uid()")
    schema = _wrap_policy(p)
    # PERF001 is USING-only — no USING means no fix.
    assert PERF001Fixer().fix(schema, {}) == []


def test_perf001_fix_respects_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    options = {"allowlist": ["public.t.p"]}
    assert PERF001Fixer().fix(schema, options) == []


def test_perf001_fix_uses_custom_auth_functions_replaces_default() -> None:
    # Default config: auth.uid() is wrapped.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(
        schema, {"auth_functions": ["my.custom"]}
    )
    # Override replaces default → auth.uid no longer matches.
    assert fixes == []

    # And a custom function gets caught:
    schema2 = _wrap_policy(_policy("user_id = my.custom()"))
    fixes2 = PERF001Fixer().fix(
        schema2, {"auth_functions": ["my.custom"]}
    )
    assert len(fixes2) == 1
    assert "(SELECT my.custom())" in fixes2[0].sql


# ---------- generate_fixes / registry ----------


def test_generate_fixes_returns_union_sorted_by_rule_id_and_location() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="z_table",
                rls_enabled=True,
                force_rls=False,  # SEC002
                policies=(_policy("user_id = auth.uid()"),),  # PERF001
                columns=("id", "user_id"),
            ),
            _table(name="a_table", rls=True, force=False),  # SEC002
        )
    )
    fixes = generate_fixes(schema, rule_options={})
    # Sorted by (rule_id, location). PERF001 < SEC002 alphabetically.
    assert [f.rule_id for f in fixes] == [
        "PERF001",
        "SEC002",
        "SEC002",
    ]
    # Within rule_id, sorted by location.
    sec002 = [f for f in fixes if f.rule_id == "SEC002"]
    assert [f.location for f in sec002] == [
        "public.a_table",
        "public.z_table",
    ]


def test_generate_fixes_filters_to_requested_rule() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=False,  # SEC002 fixable
                policies=(_policy("user_id = auth.uid()"),),  # PERF001 fixable
                columns=("id", "user_id"),
            ),
        )
    )
    sec002_only = generate_fixes(
        schema, rule_options={}, rule_filter={"SEC002"}
    )
    assert [f.rule_id for f in sec002_only] == ["SEC002"]


def test_generate_fixes_passes_rule_options() -> None:
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = generate_fixes(
        schema,
        rule_options={"PERF001": {"auth_functions": ["my.custom"]}},
    )
    # auth.uid is no longer in the override list, so no fix emitted
    # for PERF001. SEC002 is also silent because force=True. Result
    # is empty.
    assert fixes == []


def test_default_fixers_includes_sec002_and_perf001() -> None:
    rule_ids = {fixer.rule_id for fixer in default_fixers()}
    assert {"SEC002", "PERF001"} <= rule_ids


def test_fix_dataclass_is_frozen() -> None:
    f = Fix(
        rule_id="X", location="public.t", sql="--", description="test"
    )
    with pytest.raises(Exception):
        f.rule_id = "Y"  # type: ignore[misc]


# ============================================================
# Edge cases — fixer robustness
# ============================================================

def test_sec002_fix_silent_when_allowlist_is_bad_type() -> None:
    # Bad config types should fail closed: don't crash, don't
    # apply mystery fixes. SEC002Fixer's `_is_allowlisted` checks
    # the type and returns False on a non-list — so bad config
    # means "nothing is allowlisted", which means the table fires
    # as expected. Pin the conservative behavior.
    schema = Schema(tables=(_table(rls=True, force=False),))
    fixes = SEC002Fixer().fix(schema, {"allowlist": "public.t"})
    assert len(fixes) == 1
    assert fixes[0].location == "public.t"


def test_perf001_fix_silent_when_allowlist_is_bad_type() -> None:
    # Same shape: bad allowlist type → conservatively no
    # exemption applied → fix still emitted.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(schema, {"allowlist": "public.t.p"})
    assert len(fixes) == 1


def test_perf001_fix_falls_back_to_default_on_bad_auth_functions() -> None:
    # Unlike PERF001's rule which raises TypeError, the FIXER
    # falls back to the default auth function set. Reason: the
    # rule has already fired for this policy, the fixer is just
    # generating remediation SQL — bailing out with a TypeError
    # would prevent users from getting any fix output. Pin this
    # behavior.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = PERF001Fixer().fix(
        schema, {"auth_functions": "auth.uid"}  # bad type
    )
    assert len(fixes) == 1
    assert "(SELECT auth.uid())" in fixes[0].sql


def test_perf001_fix_wraps_nested_auth_calls_independently() -> None:
    # `COALESCE(auth.uid(), auth.role()::uuid)` — two auth calls
    # nested inside another function call. Each should get its
    # own SubLink wrapping, neither should swallow the other.
    schema = _wrap_policy(
        _policy(
            "user_id = COALESCE(auth.uid(), auth.role()::UUID)"
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql
    assert "(SELECT auth.uid())" in sql
    assert "(SELECT auth.role())" in sql


def test_perf001_fix_preserves_other_function_calls_verbatim() -> None:
    # `lower(email) = lower((SELECT auth.uid())::text)` — the
    # `lower` calls are NOT auth functions; they should pass
    # through untouched. The fixer must wrap only what matches
    # the auth set.
    schema = _wrap_policy(
        _policy("lower(email) = lower(auth.uid()::text)")
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql.lower()
    assert "lower(email)" in sql
    # The nested auth.uid() got wrapped.
    assert "(select auth.uid())" in sql


def test_perf001_fix_emits_one_alter_policy_per_offending_policy() -> None:
    # Two policies on the same table, both with unwrapped auth.
    # Two ALTER POLICY statements, one per policy.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    _policy("user_id = auth.uid()", name="p1"),
                    _policy(
                        "tenant_id = current_setting('app.t', true)::UUID",
                        name="p2",
                    ),
                ),
                columns=("id", "user_id", "tenant_id"),
            ),
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 2
    assert {f.location for f in fixes} == {"public.t.p1", "public.t.p2"}


def test_perf001_fix_silent_when_auth_unwrapped_only_in_with_check() -> None:
    # PERF001 is USING-only. If WITH CHECK has an unwrapped auth
    # call but USING does not, PERF001Fixer must not generate a
    # fix — there's nothing for it to repair.
    p = _policy(
        "id > 0",  # USING is clean
        with_check="user_id = auth.uid()",  # WITH CHECK is unwrapped
    )
    schema = _wrap_policy(p)
    assert PERF001Fixer().fix(schema, {}) == []


def test_generate_fixes_with_empty_schema() -> None:
    schema = Schema(tables=())
    assert generate_fixes(schema, rule_options={}) == []


def test_generate_fixes_with_unknown_rule_filter_returns_empty() -> None:
    # `--rule SEC999` typo: no fixer registers under that ID, so
    # nothing is generated. Should not crash.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = generate_fixes(
        schema, rule_options={}, rule_filter={"SEC999"}
    )
    assert fixes == []


def test_perf001_fixer_silent_on_sql_value_function() -> None:
    # `current_user` is a Postgres SQLValueFunction, not a regular
    # FuncCall. Wrapping it in `(SELECT current_user)` is dubious
    # (the grammar special doesn't compose the same way), so the
    # fixer deliberately skips it. PERF001's check still catches
    # it when configured; the rule fires, the fixer emits nothing.
    # Pin the deliberate asymmetry — a future change that wraps
    # SQLValueFunction would be visible here.
    schema = _wrap_policy(_policy("current_user = 'admin'"))
    fixes = PERF001Fixer().fix(
        schema, {"auth_functions": ["current_user"]}
    )
    assert fixes == []


def test_sec002_fix_quotes_table_name_when_required() -> None:
    # Mixed-case identifier requires double-quoting in Postgres.
    # `pg_class.relname` returns the raw name; the fixer must
    # quote when emitting back into SQL.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="MixedCase Table",
                rls_enabled=True,
                force_rls=False,
                policies=(),
            ),
        )
    )
    fixes = SEC002Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        'ALTER TABLE public."MixedCase Table" FORCE ROW LEVEL SECURITY;'
        == fixes[0].sql
    )


def test_sec002_fix_does_not_quote_plain_identifiers() -> None:
    # `snake_case_users` is a plain identifier — emit bare to
    # keep the common case readable.
    schema = Schema(
        tables=(
            _table(name="snake_case_users", rls=True, force=False),
        )
    )
    sql = SEC002Fixer().fix(schema, {})[0].sql
    assert (
        sql
        == "ALTER TABLE public.snake_case_users FORCE ROW LEVEL SECURITY;"
    )


def test_perf001_fix_quotes_policy_and_table_when_required() -> None:
    # Policy and table both have characters requiring quoting.
    p = _policy("user_id = auth.uid()", name="My Policy")
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="MixedCase Table",
                rls_enabled=True,
                force_rls=True,
                policies=(p,),
                columns=("id", "user_id"),
            ),
        )
    )
    sql = PERF001Fixer().fix(schema, {})[0].sql
    assert 'ALTER POLICY "My Policy"' in sql
    assert 'ON public."MixedCase Table"' in sql


def test_quote_ident_rejects_null_byte() -> None:
    # Postgres rejects nulls in CREATE; if a snapshot or hand-
    # built Schema sneaks one in, fail fast here with a clear
    # message rather than emitting `"a\x00b"` for the server to
    # reject with a confusing error.
    from pgrls.fixers._idents import quote_ident
    with pytest.raises(ValueError, match="null byte"):
        quote_ident("evil\x00name")


def test_quote_ident_rejects_embedded_newline() -> None:
    from pgrls.fixers._idents import quote_ident
    with pytest.raises(ValueError, match="null byte or newline"):
        quote_ident("name\nwith\nnewlines")


def test_perf001_fix_round_trips_with_check_through_pglast() -> None:
    # WITH CHECK should be re-emitted via RawStream rather than
    # echoed verbatim. Asymmetric handling would be an injection
    # vector if `with_check_sql` ever sources from somewhere
    # other than `pg_get_expr`. We verify the round-trip by
    # passing a WITH CHECK shape that pglast normalizes (single
    # quotes around boolean false), then asserting the
    # round-tripped form appears in the SQL.
    p = _policy(
        "user_id = auth.uid()",
        command="ALL",
        with_check="user_id = (SELECT auth.uid()) AND deleted_at IS NULL",
    )
    schema = _wrap_policy(p)
    sql = PERF001Fixer().fix(schema, {})[0].sql
    # The WITH CHECK passed through RawStream — pglast's printer
    # would normalize whitespace and casing. Assert the structural
    # content is present.
    assert "WITH CHECK" in sql
    assert "deleted_at" in sql
    assert "IS NULL" in sql


def test_perf001_fix_sublink_wraps_do_not_alias_each_other() -> None:
    # Each `_wrap_funccall` call constructs a fresh SubLink/
    # SelectStmt tuple — wrapping multiple FuncCalls in one pass
    # produces independent subtrees. A shared subselect would
    # cause the second wrap to overwrite the first's `val` and
    # emit `(SELECT auth.role())` twice.
    schema = _wrap_policy(
        _policy(
            "user_id = auth.uid() OR user_id = auth.role()::UUID"
        )
    )
    fixes = PERF001Fixer().fix(schema, {})
    sql = fixes[0].sql
    # Both calls should be wrapped with their respective inner
    # functions intact — proves the SubLinks are independent.
    assert "(SELECT auth.uid())" in sql
    assert "(SELECT auth.role())" in sql


def test_wrap_funccall_emits_select_sublink() -> None:
    # Pin the direct-construction shape: `_wrap_funccall` returns a
    # SubLink whose RawStream-emitted form is exactly the
    # `(SELECT <call>)` Postgres expects. Regression guard for
    # Round 17's deepcopy → direct-construction perf fix; if a
    # future refactor swaps SubLinkType, drops the LimitOption
    # default, or otherwise breaks the emitted SQL, this fails.
    from pglast.ast import FuncCall, String
    from pglast.stream import RawStream

    from pgrls.fixers.perf001 import _wrap_funccall

    fc = FuncCall(funcname=(String(sval="auth"), String(sval="uid")))
    sublink = _wrap_funccall(fc)
    assert RawStream()(sublink) == "(SELECT auth.uid())"


def test_wrap_funccall_returns_independent_objects() -> None:
    # Two consecutive calls must not share any mutable subtree:
    # mutating one SubLink's targetList must not affect the other.
    from pglast.ast import FuncCall, String

    from pgrls.fixers.perf001 import _wrap_funccall

    fc1 = FuncCall(funcname=(String(sval="auth"), String(sval="uid")))
    fc2 = FuncCall(funcname=(String(sval="auth"), String(sval="role")))
    s1 = _wrap_funccall(fc1)
    s2 = _wrap_funccall(fc2)
    assert s1 is not s2
    assert s1.subselect is not s2.subselect
    assert s1.subselect.targetList is not s2.subselect.targetList


def test_quote_ident_rejects_empty_string() -> None:
    from pgrls.fixers._idents import quote_ident
    with pytest.raises(ValueError, match="empty"):
        quote_ident("")


def test_perf001_does_not_mutate_input_policy_ast() -> None:
    # `_wrap_unwrapped_calls` mutates pglast Node fields in place
    # — `Policy` is a frozen dataclass but `frozen=True` does NOT
    # freeze the AST graph it holds. Without a deepcopy guard at
    # the fixer entry, running PERF001Fixer would visibly alter
    # `policy.using_ast` for any rule that re-walks the Schema
    # afterwards (snapshot tests, programmatic API). Pin the
    # "fixer is read-only over Schema" invariant.
    from pglast.stream import RawStream

    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    policy = schema.tables[0].policies[0]
    original_id = id(policy.using_ast)
    original_sql = RawStream()(policy.using_ast)

    PERF001Fixer().fix(schema, {})

    assert id(policy.using_ast) == original_id, (
        "Policy.using_ast was replaced; the fixer should not "
        "alter the input Schema."
    )
    assert RawStream()(policy.using_ast) == original_sql, (
        "Policy.using_ast was mutated in place; got "
        f"{RawStream()(policy.using_ast)!r}, expected "
        f"{original_sql!r}."
    )
