"""Unit tests for the auto-fix machinery and per-rule fixers."""
from __future__ import annotations

from typing import Any

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.fixers import (
    Fix,
    default_fixers,
    generate_fixes,
    render_fixes,
    render_migration,
)
from pgrls.fixers.hyg003 import HYG003Fixer
from pgrls.fixers.perf001 import PERF001Fixer
from pgrls.fixers.perf003 import PERF003Fixer
from pgrls.fixers.perf004 import PERF004Fixer
from pgrls.fixers.sec001 import SEC001Fixer
from pgrls.fixers.sec002 import SEC002Fixer
from pgrls.fixers.sec006 import SEC006Fixer
from pgrls.fixers.sec011 import SEC011Fixer
from pgrls.fixers.sec019 import SEC019Fixer
from pgrls.fixers.sec020 import SEC020Fixer
from pgrls.fixers.sec015 import SEC015Fixer
from pgrls.fixers.sec017 import SEC017Fixer
from pgrls.fixers.sec030 import SEC030Fixer
from pgrls.fixers.sec031 import SEC031Fixer
from pgrls.fixers.sec032 import SEC032Fixer
from pgrls.fixers.view001 import VIEW001Fixer
from pgrls.fixers.view002 import VIEW002Fixer
from pgrls.model import Column, Index, Policy, Schema, Table, View


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


# ---------- SEC001 fixer ----------


def test_sec001_fix_emits_alter_table_enable() -> None:
    schema = Schema(tables=(_table(rls=False, force=False),))
    fixes = SEC001Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC001"
    assert f.location == "public.t"
    assert f.sql == "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;"


def test_sec001_fix_silent_when_rls_already_enabled() -> None:
    # SEC002's territory (FORCE missing), not SEC001's.
    schema = Schema(tables=(_table(rls=True, force=False),))
    assert SEC001Fixer().fix(schema, {}) == []


def test_sec001_fix_respects_allowlist_qualified() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=False, force=False),
            _table(name="b", rls=False, force=False),
        )
    )
    fixes = SEC001Fixer().fix(schema, {"allowlist": ["public.a"]})
    assert [f.location for f in fixes] == ["public.b"]


def test_sec001_fix_respects_allowlist_unqualified() -> None:
    schema = Schema(
        tables=(_table(name="countries", rls=False, force=False),)
    )
    assert SEC001Fixer().fix(schema, {"allowlist": ["countries"]}) == []


def test_sec001_fix_emits_one_per_offending_table() -> None:
    schema = Schema(
        tables=(
            _table(name="a", rls=False, force=False),
            _table(name="b", rls=True, force=True),
            _table(name="c", rls=False, force=False),
        )
    )
    fixes = SEC001Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == ["public.a", "public.c"]


def test_sec001_fix_skips_partition_child() -> None:
    # SEC001 flags an RLS-less partition child, but the remediation
    # is a judgement call (parent vs each child) — the fixer skips
    # children and emits the single correct fix for the parent.
    parent = _table(name="events", rls=False, force=False)
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("public", "events"),
    )
    schema = Schema(tables=(parent, child))
    fixes = SEC001Fixer().fix(schema, {})
    assert [f.location for f in fixes] == ["public.events"]


def test_sec001_fix_skips_partition_child_with_unscanned_parent() -> None:
    # A partition child whose parent lives in a schema that was not
    # scanned: no in-scope parent exists to fix, and pgrls cannot
    # verify RLS coverage upstream. The fixer still skips the child
    # — widening `--schemas` or designing a child policy is a
    # judgement call, not a mechanical fix.
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(),
        partition_of=("private", "events"),  # 'private' not scanned
    )
    schema = Schema(tables=(child,))
    assert SEC001Fixer().fix(schema, {}) == []


def test_sec001_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC001's strict parser
    # (parse_table_ref_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = Schema(tables=(_table(rls=False, force=False),))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        SEC001Fixer().fix(schema, {"allowlist": "public.t"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        SEC001Fixer().fix(schema, {"allowlist": [" public.t "]})


def test_sec001_fix_quotes_table_name_when_required() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="MixedCase Table",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    fixes = SEC001Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        fixes[0].sql
        == 'ALTER TABLE public."MixedCase Table" '
        "ENABLE ROW LEVEL SECURITY;"
    )


def test_sec001_fix_description_warns_about_deny_all() -> None:
    # Enabling RLS with no policy makes the table deny-all for
    # non-owner roles — the description must surface that follow-up.
    schema = Schema(tables=(_table(rls=False, force=False),))
    [f] = SEC001Fixer().fix(schema, {})
    assert "public.t" in f.description
    assert "policy" in f.description


# ---------- VIEW001 fixer ----------


def _view(
    name: str = "v",
    *,
    schema: str = "public",
    is_materialized: bool = False,
    security_invoker: bool = False,
    security_barrier: bool = False,
    references: tuple[tuple[str, str], ...] = (),
    security_definer_calls: tuple[str, ...] = (),
    definition: str = "SELECT 1",
) -> View:
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


def test_view001_fix_emits_alter_view_set_security_invoker() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "VIEW001"
    assert f.location == "public.user_summary"
    assert "ALTER VIEW" in f.sql
    assert "public.user_summary" in f.sql
    assert "SET (security_invoker = true)" in f.sql
    assert (
        f.sql
        == "ALTER VIEW public.user_summary "
        "SET (security_invoker = true);"
    )


def test_view001_fix_silent_when_security_invoker_already_true() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_silent_when_referenced_table_has_no_rls() -> None:
    # No RLS-protected reference → nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=False, force=False),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_silent_on_materialized_view() -> None:
    # Matviews are VIEW003's domain — VIEW001 must skip them and so
    # must its fixer. `ALTER VIEW … SET (security_invoker = true)`
    # would also be invalid syntax against a matview.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                is_materialized=True,
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_respects_qualified_allowlist() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(
        schema, {"allowlist": ["public.user_summary"]}
    )
    assert fixes == []


def test_view001_fix_description_mentions_view_and_leaked_tables() -> None:
    schema = Schema(
        tables=(
            _table(name="users", rls=True, force=True),
            _table(name="invoices", rls=True, force=True),
        ),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(
                    ("public", "users"),
                    ("public", "invoices"),
                ),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert len(fixes) == 1
    desc = fixes[0].description
    assert "public.user_summary" in desc
    assert "public.invoices" in desc
    assert "public.users" in desc


def test_view001_fix_silent_when_view_has_no_references() -> None:
    # A constant-only view has nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="constant_view",
                security_invoker=False,
                references=(),
            ),
        ),
    )
    assert VIEW001Fixer().fix(schema, {}) == []


def test_view001_fix_emits_one_per_offending_view() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="bad_a",
                security_invoker=False,
                references=(("public", "users"),),
            ),
            _view(
                name="bad_b",
                security_invoker=False,
                references=(("public", "users"),),
            ),
            _view(
                name="good",
                security_invoker=True,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.bad_a",
        "public.bad_b",
    ]


def test_view001_fix_quotes_view_name_when_required() -> None:
    # Mixed-case identifier requires double-quoting in Postgres.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="MixedCase Summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW001Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        fixes[0].sql
        == 'ALTER VIEW public."MixedCase Summary" '
        "SET (security_invoker = true);"
    )


def test_view001_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with VIEW001's strict parser
    # (parse_qualified_view_allowlist), so a malformed allowlist
    # raises TypeError — `pgrls fix` surfaces it as a ToolError,
    # exactly as `pgrls lint` rejects the same config.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=False,
                references=(("public", "users"),),
            ),
        ),
    )
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW001Fixer().fix(
            schema, {"allowlist": "public.user_summary"}
        )
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW001Fixer().fix(
            schema, {"allowlist": [" public.user_summary "]}
        )


# ---------- VIEW002 fixer ----------


def test_view002_fix_emits_alter_view_set_security_barrier() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "VIEW002"
    assert f.location == "public.user_summary"
    assert "ALTER VIEW" in f.sql
    assert "public.user_summary" in f.sql
    assert "SET (security_barrier = true)" in f.sql
    assert (
        f.sql
        == "ALTER VIEW public.user_summary "
        "SET (security_barrier = true);"
    )


def test_view002_fix_silent_when_security_barrier_already_true() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=True,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_silent_when_referenced_table_has_no_rls() -> None:
    # No RLS-protected reference → nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=False, force=False),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_silent_on_materialized_view() -> None:
    # Matviews are VIEW003's domain — VIEW002 must skip them.
    # `ALTER VIEW … SET (security_barrier = true)` would also be
    # invalid syntax against a matview.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                is_materialized=True,
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_respects_qualified_allowlist() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(
        schema, {"allowlist": ["public.user_summary"]}
    )
    assert fixes == []


def test_view002_fix_description_mentions_view_and_leaked_tables() -> None:
    schema = Schema(
        tables=(
            _table(name="users", rls=True, force=True),
            _table(name="invoices", rls=True, force=True),
        ),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(
                    ("public", "users"),
                    ("public", "invoices"),
                ),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert len(fixes) == 1
    desc = fixes[0].description
    assert "public.user_summary" in desc
    assert "public.invoices" in desc
    assert "public.users" in desc


def test_view002_fix_silent_when_view_has_no_references() -> None:
    # A constant-only view has nothing to leak → no fix.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="constant_view",
                security_invoker=True,
                security_barrier=False,
                references=(),
            ),
        ),
    )
    assert VIEW002Fixer().fix(schema, {}) == []


def test_view002_fix_emits_one_per_offending_view() -> None:
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="bad_a",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
            _view(
                name="bad_b",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
            _view(
                name="good",
                security_invoker=True,
                security_barrier=True,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.bad_a",
        "public.bad_b",
    ]


def test_view002_fix_quotes_view_name_when_required() -> None:
    # Mixed-case identifier requires double-quoting in Postgres.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="MixedCase Summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    fixes = VIEW002Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert (
        fixes[0].sql
        == 'ALTER VIEW public."MixedCase Summary" '
        "SET (security_barrier = true);"
    )


def test_view002_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with VIEW002's strict parser
    # (parse_qualified_view_allowlist), so a malformed allowlist
    # raises TypeError — `pgrls fix` surfaces it as a ToolError,
    # exactly as `pgrls lint` rejects the same config.
    schema = Schema(
        tables=(_table(name="users", rls=True, force=True),),
        views=(
            _view(
                name="user_summary",
                security_invoker=True,
                security_barrier=False,
                references=(("public", "users"),),
            ),
        ),
    )
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW002Fixer().fix(
            schema, {"allowlist": "public.user_summary"}
        )
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        VIEW002Fixer().fix(
            schema, {"allowlist": [" public.user_summary "]}
        )


# ---------- PERF001 fixer ----------


def _policy(
    using: str | None = None,
    *,
    name: str = "p",
    command: str = "SELECT",
    with_check: str | None = None,
    permissive: bool = True,
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
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
                # Index the candidate policy columns so the PERF003
                # fixer stays silent here — PERF003 is exercised in
                # its own section, not incidentally via _wrap_policy.
                indexes=(
                    _idx("id", name="t_id_idx"),
                    _idx("user_id", name="t_user_id_idx"),
                ),
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


def test_perf001_fix_emits_only_using_not_unchanged_with_check() -> None:
    # PERF001 rewrites only USING, so it must emit ONLY the USING clause.
    # Re-emitting the unchanged WITH CHECK (an `ALTER POLICY` replaces the
    # whole clause) would clobber — and silently revert — a WITH CHECK fix
    # another fixer makes on the same policy in one migration (SEC020's
    # mirror, SEC011's strip). Matches SEC011/SEC019's minimal-diff rule.
    p = _policy(
        "user_id = auth.uid()",
        command="ALL",
        with_check="user_id = (SELECT auth.uid())",
    )
    schema = _wrap_policy(p)
    fix = PERF001Fixer().fix(schema, {})[0]
    assert "USING (user_id = (SELECT auth.uid()))" in fix.sql
    assert "WITH CHECK" not in fix.sql
    assert fix.clauses == frozenset({"using"})


def test_perf001_fix_silent_when_using_is_none() -> None:
    p = _policy(None, command="INSERT", with_check="user_id = auth.uid()")
    schema = _wrap_policy(p)
    # PERF001 is USING-only — no USING means no fix.
    assert PERF001Fixer().fix(schema, {}) == []


def test_perf001_fix_wraps_auth_call_on_sublink_testexpr() -> None:
    # Regression (audit finding #11): `auth.uid() IN (SELECT ...)`
    # puts the unwrapped auth call on the SubLink's `testexpr` (the
    # IN-LHS), not inside the subselect. PERF001's RULE fires on it
    # (find_func_calls(exclude_sublinks=True) walks testexpr — see
    # tests/rules/test_perf001.py::test_perf001_fires_on_unwrapped_auth_on_in_lhs),
    # so the fixer MUST rewrite it too or it leaves a reported
    # violation unfixed. The subselect itself stays untouched.
    schema = _wrap_policy(
        _policy("auth.uid() IN (SELECT id FROM trusted_admins)")
    )
    fixes = PERF001Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql
    # The testexpr call is now wrapped …
    assert "(SELECT auth.uid()) IN (SELECT id FROM trusted_admins)" in sql
    # … and the wrap is applied exactly once (no double-wrapping of
    # the subselect or the testexpr).
    assert sql.count("SELECT auth.uid()") == 1


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


# ---------- SEC006 fixer ----------


def test_sec006_fix_emits_with_check_mirroring_using() -> None:
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    fixes = SEC006Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC006"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "WITH CHECK (user_id = 1)" in f.sql
    # The fix writes the WITH CHECK clause; it must declare so the
    # anti-clobber guard keeps a single writer per (policy, clause).
    assert f.clauses == frozenset({"with_check"})


def test_sec006_fix_silent_when_with_check_already_present() -> None:
    p = _policy("user_id = 1", command="ALL", with_check="user_id = 1")
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_strips_or_true_before_mirroring_into_with_check() -> None:
    # Regression (audit finding #4): a USING with a constant-true
    # disjunct (`user_id = 1 OR true`) must NOT be mirrored verbatim
    # into the new WITH CHECK — that would create a constant-true
    # write check admitting EVERY write, the wide-open write side
    # SEC006 exists to close. SEC011 (same `pgrls fix` pass) only
    # rewrites USING, never the WITH CHECK SEC006 just emitted, so a
    # single pass would otherwise leave the write side open. The
    # disjunct is stripped before mirroring.
    schema = _wrap_policy(_policy("user_id = 1 OR true", command="ALL"))
    fixes = SEC006Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql
    assert "WITH CHECK (user_id = 1)" in sql
    # The constant-true bypass must be gone — no always-true write check.
    assert "TRUE" not in sql
    assert "true" not in sql


def test_sec006_fix_keeps_real_disjuncts_when_stripping_or_true() -> None:
    # `a OR b OR true` → keep `a OR b`; only the literal-true disjunct
    # is removed, the real predicate is preserved (not over-narrowed).
    schema = _wrap_policy(
        _policy("user_id = 1 OR user_id = 2 OR true", command="ALL")
    )
    sql = SEC006Fixer().fix(schema, {})[0].sql
    assert "WITH CHECK (user_id = 1 OR user_id = 2)" in sql
    assert "TRUE" not in sql


def test_sec006_fix_declines_when_using_is_only_constant_true() -> None:
    # `true OR true` collapses to nothing once the trues are stripped
    # — there is no real predicate to mirror, so the fixer must NOT
    # emit a constant-true WITH CHECK. It declines and leaves the
    # SEC006 finding for the operator (the conservative choice).
    schema = _wrap_policy(_policy("true OR true", command="ALL"))
    assert SEC006Fixer().fix(schema, {}) == []


def test_sec006_fix_declines_when_using_is_bare_true() -> None:
    # A bare `USING (true)` write check would mirror to a constant-true
    # WITH CHECK — never emit one. Decline; the finding stays.
    schema = _wrap_policy(_policy("true", command="ALL"))
    assert SEC006Fixer().fix(schema, {}) == []


def test_sec006_fix_silent_on_select_policy() -> None:
    # SELECT is not a write command — WITH CHECK does not apply.
    schema = _wrap_policy(_policy("user_id = 1", command="SELECT"))
    assert SEC006Fixer().fix(schema, {}) == []


def test_sec006_fix_fires_on_for_update_policy() -> None:
    schema = _wrap_policy(_policy("user_id = 1", command="UPDATE"))
    fixes = SEC006Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert "WITH CHECK (user_id = 1)" in fixes[0].sql


def test_sec006_fix_skips_insert_policy_with_no_using() -> None:
    # A FOR INSERT policy has no USING to mirror — Postgres forbids
    # `FOR INSERT … USING`. SEC006 fires, but the fixer cannot
    # mechanically derive a WITH CHECK, so it skips.
    p = _policy(None, command="INSERT")
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_skips_write_policy_with_no_using() -> None:
    # A FOR UPDATE / FOR ALL policy can omit USING too — there is
    # then no predicate to copy into WITH CHECK.
    p = _policy(None, command="UPDATE")
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_skips_restrictive_policy() -> None:
    # A restrictive write-side policy with no WITH CHECK is a dead
    # policy; SEC006's remediation there ("express the intended
    # predicate, or remove the policy") needs human intent, so the
    # fixer skips it — only permissive write policies are fixed.
    p = _policy("user_id = 1", command="ALL", permissive=False)
    assert SEC006Fixer().fix(_wrap_policy(p), {}) == []


def test_sec006_fix_respects_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    assert SEC006Fixer().fix(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec006_fix_emits_one_per_offending_policy() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy("user_id = 1", name="bad_a", command="ALL"),
                    _policy(
                        "user_id = 1",
                        name="ok",
                        command="ALL",
                        with_check="user_id = 1",
                    ),
                    _policy(
                        "user_id = 2", name="bad_b", command="UPDATE"
                    ),
                ),
            ),
        )
    )
    fixes = SEC006Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.bad_a",
        "public.t.bad_b",
    ]


def test_sec006_fix_quotes_policy_and_table_when_required() -> None:
    p = _policy("user_id = 1", name="My Policy", command="ALL")
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
    sql = SEC006Fixer().fix(schema, {})[0].sql
    assert 'ALTER POLICY "My Policy"' in sql
    assert 'ON public."MixedCase Table"' in sql


def test_sec006_fix_round_trips_using_through_pglast() -> None:
    # The USING predicate is re-emitted via RawStream, not echoed
    # verbatim. Feed a non-canonical form (no spaces around `=`)
    # and assert pglast's normalized spacing appears — a verbatim
    # echo of the raw `using_sql` would keep `user_id=1`.
    schema = _wrap_policy(_policy("user_id=1", command="ALL"))
    sql = SEC006Fixer().fix(schema, {})[0].sql
    assert "WITH CHECK (user_id = 1)" in sql


def test_sec006_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC006's strict parser
    # (parse_policy_id_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        SEC006Fixer().fix(schema, {"allowlist": "public.t.p"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        SEC006Fixer().fix(schema, {"allowlist": [" public.t.p "]})


# ---------- SEC019 fixer ----------


def test_sec019_fix_adds_missing_ok_to_one_arg_current_setting() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    fixes = SEC019Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC019"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    # pglast normalizes the boolean to uppercase; the rewrite is
    # semantically `current_setting(..., true)`.
    assert "current_setting('app.user', TRUE)" in f.sql


def test_sec019_fix_silent_when_already_two_arg() -> None:
    # `current_setting('x', true)` is already in the safe form;
    # SEC019 the rule stays silent, and so does the fixer.
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user', true)")
    )
    assert SEC019Fixer().fix(schema, {}) == []


def test_sec019_fix_silent_when_no_current_setting() -> None:
    schema = _wrap_policy(_policy("user_id = 1"))
    assert SEC019Fixer().fix(schema, {}) == []


def test_sec019_fix_handles_pg_catalog_qualified_form() -> None:
    # Matches SEC019's detection — both bare and pg_catalog-
    # qualified `current_setting` calls get the rewrite.
    schema = _wrap_policy(
        _policy("user_id = pg_catalog.current_setting('app.user')")
    )
    sql = SEC019Fixer().fix(schema, {})[0].sql
    assert "pg_catalog.current_setting('app.user', TRUE)" in sql


def test_sec019_fix_rewrites_call_in_with_check() -> None:
    # WITH CHECK side also gets rewritten; SEC019 fires on either
    # clause, so the fixer covers both.
    p = _policy(
        "user_id = 1",
        command="ALL",
        with_check="user_id = current_setting('app.user')",
    )
    sql = SEC019Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "WITH CHECK (user_id = current_setting('app.user', TRUE))" in sql
    # USING is unchanged, so it must NOT appear in the ALTER:
    # the fixer emits only the changed clause(s).
    assert "USING (" not in sql


def test_sec019_fix_emits_only_changed_clauses() -> None:
    # USING has the one-arg form; WITH CHECK already has two args.
    # The fixer rewrites USING and emits an ALTER POLICY with
    # USING only — leaving WITH CHECK alone for a minimal diff.
    p = _policy(
        "user_id = current_setting('app.user')",
        command="ALL",
        with_check="user_id = current_setting('app.user', true)",
    )
    sql = SEC019Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "USING (user_id = current_setting('app.user', TRUE))" in sql
    assert "WITH CHECK" not in sql


def test_sec019_fix_emits_both_clauses_when_both_have_one_arg() -> None:
    # Both sides have the one-arg form — both get rewritten and
    # both appear in the ALTER POLICY.
    p = _policy(
        "user_id = current_setting('app.user')",
        command="ALL",
        with_check="user_id = current_setting('app.user')",
    )
    sql = SEC019Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "USING (user_id = current_setting('app.user', TRUE))" in sql
    assert "WITH CHECK (user_id = current_setting('app.user', TRUE))" in sql


def test_sec019_fix_rewrites_call_wrapped_in_subselect() -> None:
    # PERF001's wrapped form `(SELECT current_setting('x'))` — the
    # inner call is still one-arg, so SEC019 fires and the fixer
    # walks into the SubLink.
    schema = _wrap_policy(
        _policy("user_id = (SELECT current_setting('app.user'))")
    )
    sql = SEC019Fixer().fix(schema, {})[0].sql
    assert "(SELECT current_setting('app.user', TRUE))" in sql


def test_sec019_fix_respects_allowlist() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    assert SEC019Fixer().fix(
        schema, {"allowlist": ["public.t.p"]}
    ) == []


def test_sec019_fix_emits_one_per_offending_policy() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy(
                        "user_id = current_setting('app.user')",
                        name="bad_a",
                    ),
                    _policy(
                        "user_id = current_setting('app.user', true)",
                        name="ok",
                    ),
                    _policy(
                        "user_id = current_setting('app.team')",
                        name="bad_b",
                    ),
                ),
            ),
        )
    )
    fixes = SEC019Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.bad_a",
        "public.t.bad_b",
    ]


def test_sec019_fix_does_not_mutate_input_schema() -> None:
    # PERF001's fixer deepcopies the AST before mutating; SEC019
    # must do the same so the rule's view of the policy isn't
    # silently rewritten as a side effect of `pgrls fix`.
    p = _policy("user_id = current_setting('app.user')")
    schema = _wrap_policy(p)
    SEC019Fixer().fix(schema, {})
    # The original AST still renders as the one-arg form.
    from pglast.stream import RawStream
    assert "TRUE" not in RawStream()(p.using_ast)


def test_sec019_fix_description_explains_the_tradeoff() -> None:
    # SEC019 is info severity precisely because the choice
    # between the two overloads is judgement; the description
    # must spell out that the rewrite picks the quiet-NULL side
    # and point at the allowlist for users who wanted the loud
    # raise.
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    [f] = SEC019Fixer().fix(schema, {})
    assert "missing_ok" in f.description
    assert "[lint.rules.SEC019]" in f.description


def test_sec019_fix_raises_on_malformed_allowlist() -> None:
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC019Fixer().fix(schema, {"allowlist": "public.t.p"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC019Fixer().fix(schema, {"allowlist": [" public.t.p "]})


def test_sec019_and_perf001_both_fire_on_unwrapped_one_arg_current_setting() -> None:
    # PERF001 (wrap auth calls in `(SELECT …)`) and SEC019 (add the
    # `, true` second argument) both target the same shape — an
    # unwrapped one-arg `current_setting` — and run independently.
    # Each fixer, called on its OWN, emits an `ALTER POLICY` for the
    # policy: PERF001 wraps but leaves the arity at one; SEC019 adds the
    # missing_ok argument but leaves the call unwrapped. This pins each
    # fixer's individual output. The orchestrator no longer lets both
    # land in one migration (they'd clobber on the shared USING clause):
    # `generate_fixes` keeps one writer per (policy, clause) — see
    # `test_generate_fixes_suppresses_clobbering_clause_rewrites` — and
    # the suppressed fixer re-fires on the next `pgrls fix` run.
    schema = _wrap_policy(
        _policy("user_id = current_setting('app.user')")
    )
    perf_fixes = PERF001Fixer().fix(schema, {})
    sec_fixes = SEC019Fixer().fix(schema, {})

    assert len(perf_fixes) == 1
    assert len(sec_fixes) == 1
    assert perf_fixes[0].location == sec_fixes[0].location == "public.t.p"

    # PERF001's ALTER wraps in `(SELECT …)` but keeps the one-arg
    # call — SEC019 still re-fires on its output.
    assert "(SELECT current_setting('app.user'))" in perf_fixes[0].sql
    assert ", TRUE)" not in perf_fixes[0].sql

    # SEC019's ALTER adds the second argument but leaves the call
    # unwrapped — PERF001 still re-fires on its output.
    assert "current_setting('app.user', TRUE)" in sec_fixes[0].sql
    assert "(SELECT" not in sec_fixes[0].sql


# ---------- SEC020 fixer ----------


def test_sec020_fix_replaces_constant_true_with_check() -> None:
    schema = _wrap_policy(
        _policy("user_id = 1", command="ALL", with_check="true")
    )
    fixes = SEC020Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC020"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "WITH CHECK (user_id = 1)" in f.sql


def test_sec020_fix_silent_when_with_check_is_a_real_predicate() -> None:
    # WITH CHECK already mirrors a real predicate — nothing to fix.
    p = _policy("user_id = 1", command="ALL", with_check="user_id = 1")
    assert SEC020Fixer().fix(_wrap_policy(p), {}) == []


def test_sec020_fix_strips_or_true_before_mirroring_into_with_check() -> None:
    # Regression (audit finding #4): SEC020 replaces a constant-true
    # WITH CHECK with the USING predicate. If USING itself carries a
    # constant-true disjunct (`user_id = 1 OR true`), mirroring it
    # verbatim just swaps one always-true WITH CHECK for another —
    # the write side stays wide open, the exact thing SEC020 flags.
    # The disjunct must be stripped before mirroring.
    schema = _wrap_policy(
        _policy("user_id = 1 OR true", command="ALL", with_check="true")
    )
    fixes = SEC020Fixer().fix(schema, {})
    assert len(fixes) == 1
    sql = fixes[0].sql
    assert "WITH CHECK (user_id = 1)" in sql
    assert "TRUE" not in sql
    assert "true" not in sql


def test_sec020_fix_declines_when_using_collapses_to_constant_true() -> None:
    # `true OR true` is not a bare literal-true (so SEC020's rule
    # fires) but collapses to nothing once stripped. The fixer must
    # NOT emit a constant-true WITH CHECK — it declines and leaves
    # the finding.
    schema = _wrap_policy(
        _policy("true OR true", command="ALL", with_check="true")
    )
    assert SEC020Fixer().fix(schema, {}) == []


def test_sec020_fix_silent_when_with_check_absent() -> None:
    # A missing WITH CHECK is SEC006's surface, not SEC020's.
    schema = _wrap_policy(_policy("user_id = 1", command="ALL"))
    assert SEC020Fixer().fix(schema, {}) == []


def test_sec020_fix_silent_when_using_is_constant_true() -> None:
    # USING (true) is a fully-open policy — SEC008's concern. With
    # no real read predicate there is no asymmetry to remediate.
    p = _policy("true", command="ALL", with_check="true")
    assert SEC020Fixer().fix(_wrap_policy(p), {}) == []


def test_sec020_fix_silent_when_using_absent() -> None:
    # A FOR INSERT policy has no USING to mirror into WITH CHECK.
    p = _policy(None, command="INSERT", with_check="true")
    assert SEC020Fixer().fix(_wrap_policy(p), {}) == []


def test_sec020_fix_fires_on_for_update_policy() -> None:
    schema = _wrap_policy(
        _policy("user_id = 1", command="UPDATE", with_check="true")
    )
    fixes = SEC020Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert "WITH CHECK (user_id = 1)" in fixes[0].sql


def test_sec020_fix_fixes_restrictive_policy() -> None:
    # Unlike the SEC006 fixer, SEC020's fixes restrictive policies
    # too: a restrictive policy's WITH CHECK (true) is a no-op
    # write check (restrictive AND true), and mirroring USING turns
    # it into a real constraint — a meaningful, correct fix.
    p = _policy(
        "user_id = 1", command="ALL", with_check="true", permissive=False
    )
    fixes = SEC020Fixer().fix(_wrap_policy(p), {})
    assert len(fixes) == 1
    assert "WITH CHECK (user_id = 1)" in fixes[0].sql


def test_sec020_fix_respects_allowlist() -> None:
    schema = _wrap_policy(
        _policy("user_id = 1", command="ALL", with_check="true")
    )
    assert SEC020Fixer().fix(schema, {"allowlist": ["public.t.p"]}) == []


def test_sec020_fix_emits_one_per_offending_policy() -> None:
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                columns=("id", "user_id"),
                policies=(
                    _policy(
                        "user_id = 1",
                        name="bad_a",
                        command="ALL",
                        with_check="true",
                    ),
                    _policy(
                        "user_id = 1",
                        name="ok",
                        command="ALL",
                        with_check="user_id = 1",
                    ),
                    _policy(
                        "user_id = 2",
                        name="bad_b",
                        command="UPDATE",
                        with_check="true",
                    ),
                ),
            ),
        )
    )
    fixes = SEC020Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.bad_a",
        "public.t.bad_b",
    ]


def test_sec020_fix_quotes_policy_and_table_when_required() -> None:
    p = _policy(
        "user_id = 1", name="My Policy", command="ALL", with_check="true"
    )
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
    sql = SEC020Fixer().fix(schema, {})[0].sql
    assert 'ALTER POLICY "My Policy"' in sql
    assert 'ON public."MixedCase Table"' in sql


def test_sec020_fix_round_trips_using_through_pglast() -> None:
    # The USING predicate is re-emitted via RawStream, not echoed
    # verbatim — a non-canonical `user_id=1` comes back normalized.
    schema = _wrap_policy(
        _policy("user_id=1", command="ALL", with_check="true")
    )
    sql = SEC020Fixer().fix(schema, {})[0].sql
    assert "WITH CHECK (user_id = 1)" in sql


def test_sec020_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC020's strict parser, so a
    # malformed allowlist raises TypeError — `pgrls fix` surfaces
    # it as a ToolError, exactly as `pgrls lint` rejects it.
    schema = _wrap_policy(
        _policy("user_id = 1", command="ALL", with_check="true")
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC020Fixer().fix(schema, {"allowlist": "public.t.p"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC020Fixer().fix(schema, {"allowlist": [" public.t.p "]})


# ---------- HYG003 fixer ----------


def _dup_table(
    *policies: Policy, name: str = "t", schema: str = "public"
) -> Schema:
    """A single RLS-forced table holding `policies` — HYG003 setup."""
    return Schema(
        tables=(
            Table(
                schema=schema,
                name=name,
                rls_enabled=True,
                force_rls=True,
                policies=policies,
            ),
        )
    )


def test_hyg003_fix_emits_drop_policy_for_duplicate() -> None:
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "HYG003"
    # Name-sorted first ('p_a') is kept; 'p_b' is the redundant drop.
    assert f.location == "public.t.p_b"
    assert f.sql == "DROP POLICY p_b ON public.t;"


def test_hyg003_fix_keeps_name_sorted_first_policy() -> None:
    # Input order is reversed — the fixer still keeps the
    # name-sorted-first policy and drops the other, so output is
    # deterministic regardless of how the snapshot ordered policies.
    schema = _dup_table(
        _policy("user_id = 1", name="z_policy"),
        _policy("user_id = 1", name="a_policy"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert [f.location for f in fixes] == ["public.t.z_policy"]


def test_hyg003_fix_silent_on_distinct_policies() -> None:
    # Different USING text → different signature → not duplicates.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 2", name="p_b"),
    )
    assert HYG003Fixer().fix(schema, {}) == []


def test_hyg003_fix_silent_on_policies_differing_only_by_command() -> None:
    # Same predicate, different command — a FOR SELECT and a FOR
    # UPDATE policy are not duplicates even with identical USING.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a", command="SELECT"),
        _policy("user_id = 1", name="p_b", command="UPDATE"),
    )
    assert HYG003Fixer().fix(schema, {}) == []


def test_hyg003_fix_silent_on_single_policy() -> None:
    # Nothing to dedupe — one policy is never its own duplicate.
    assert HYG003Fixer().fix(_wrap_policy(_policy("user_id = 1")), {}) == []


def test_hyg003_fix_emits_one_drop_per_redundant_copy() -> None:
    # Three identical policies — keep one, drop the other two.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
        _policy("user_id = 1", name="p_c"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.p_b",
        "public.t.p_c",
    ]


def test_hyg003_fix_handles_multiple_duplicate_groups() -> None:
    # Two independent duplicate groups on one table — each
    # contributes one DROP for its redundant copy.
    schema = _dup_table(
        _policy("user_id = 1", name="a1"),
        _policy("user_id = 1", name="a2"),
        _policy("tenant_id = 9", name="b1"),
        _policy("tenant_id = 9", name="b2"),
    )
    fixes = HYG003Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.a2",
        "public.t.b2",
    ]


def test_hyg003_fix_respects_allowlist() -> None:
    # The redundant policy's qualified ID is allowlisted — keeping
    # the duplicate is intentional, so no DROP is emitted.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
    )
    assert (
        HYG003Fixer().fix(schema, {"allowlist": ["public.t.p_b"]}) == []
    )


def test_hyg003_fix_quotes_policy_and_table_when_required() -> None:
    # Mixed-case / spaced identifiers must be double-quoted in the
    # emitted DROP POLICY statement.
    schema = _dup_table(
        _policy("user_id = 1", name="a policy"),
        _policy("user_id = 1", name="z policy"),
        name="MixedCase Table",
    )
    sql = HYG003Fixer().fix(schema, {})[0].sql
    assert sql == 'DROP POLICY "z policy" ON public."MixedCase Table";'


def test_hyg003_fix_description_names_the_original() -> None:
    # The description must name both the dropped duplicate and the
    # surviving original so a reviewer can confirm the pairing.
    schema = _dup_table(
        _policy("user_id = 1", name="keeper"),
        _policy("user_id = 1", name="redundant"),
    )
    [f] = HYG003Fixer().fix(schema, {})
    assert f.location == "public.t.redundant"
    assert "keeper" in f.description
    assert "redundant" in f.description


def test_hyg003_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with HYG003's strict parser
    # (parse_policy_id_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = _dup_table(
        _policy("user_id = 1", name="p_a"),
        _policy("user_id = 1", name="p_b"),
    )
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        HYG003Fixer().fix(schema, {"allowlist": "public.t.p_b"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        HYG003Fixer().fix(schema, {"allowlist": [" public.t.p_b "]})


# ---------- SEC030 fixer ----------


def _sec030_table(
    *,
    name: str = "documents",
    schema: str = "public",
    rls: bool = True,
    policies: tuple[Policy, ...] = (),
    column_details: tuple[Column, ...] = (
        Column(name="id", data_type="uuid", is_nullable=False),
        Column(name="tenant_id", data_type="integer", is_nullable=True),
        Column(name="owner_id", data_type="uuid", is_nullable=False),
    ),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=True,
        policies=policies,
        columns=tuple(c.name for c in column_details),
        column_details=column_details,
    )


def _scoping_policy(
    column: str = "tenant_id",
    *,
    name: str = "tenant_scope",
    auth: str = "current_setting('app.tenant')::int",
) -> Policy:
    return _policy(f"{column} = {auth}", name=name)


def test_sec030_fix_emits_alter_column_set_not_null() -> None:
    schema = Schema(
        tables=(_sec030_table(policies=(_scoping_policy(),)),),
    )
    fixes = SEC030Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC030"
    assert f.location == "public.documents.tenant_id"
    assert f.sql == (
        "ALTER TABLE public.documents "
        "ALTER COLUMN tenant_id SET NOT NULL;"
    )


def test_sec030_fix_silent_when_discriminator_already_not_null() -> None:
    # SEC030 itself doesn't fire when the column is NOT NULL; the
    # fixer mirrors.
    schema = Schema(
        tables=(
            _sec030_table(
                policies=(_scoping_policy(),),
                column_details=(
                    Column(name="id", data_type="uuid", is_nullable=False),
                    Column(
                        name="tenant_id",
                        data_type="integer",
                        is_nullable=False,
                    ),
                ),
            ),
        ),
    )
    assert SEC030Fixer().fix(schema, {}) == []


def test_sec030_fix_silent_when_rls_disabled() -> None:
    # SEC030's domain is policy-driven scoping — RLS off, no fix.
    schema = Schema(
        tables=(
            _sec030_table(rls=False, policies=(_scoping_policy(),)),
        ),
    )
    assert SEC030Fixer().fix(schema, {}) == []


def test_sec030_fix_silent_when_column_details_missing() -> None:
    # Pre-v5 snapshots have no column_details — the rule and fixer
    # can't tell nullable from NOT NULL, so both abstain.
    table = Table(
        schema="public",
        name="documents",
        rls_enabled=True,
        force_rls=True,
        policies=(_scoping_policy(),),
        columns=("id", "tenant_id"),
        # column_details intentionally omitted (defaults to ())
    )
    schema = Schema(tables=(table,))
    assert SEC030Fixer().fix(schema, {}) == []


def test_sec030_fix_emits_one_per_nullable_scoping_column() -> None:
    # A table whose policies scope by TWO different nullable columns
    # gets TWO Fix entries — each ALTER COLUMN is independent.
    p1 = _scoping_policy("tenant_id", name="tenant")
    p2 = _scoping_policy(
        "owner_id",
        name="owner",
        auth="(SELECT auth.uid())",
    )
    schema = Schema(
        tables=(
            _sec030_table(
                policies=(p1, p2),
                column_details=(
                    Column(name="id", data_type="uuid", is_nullable=False),
                    Column(
                        name="tenant_id",
                        data_type="integer",
                        is_nullable=True,
                    ),
                    Column(
                        name="owner_id",
                        data_type="uuid",
                        is_nullable=True,
                    ),
                ),
            ),
        ),
    )
    fixes = SEC030Fixer().fix(schema, {})
    assert sorted(f.sql for f in fixes) == [
        "ALTER TABLE public.documents "
        "ALTER COLUMN owner_id SET NOT NULL;",
        "ALTER TABLE public.documents "
        "ALTER COLUMN tenant_id SET NOT NULL;",
    ]


def test_sec030_fix_respects_allowlist_qualified() -> None:
    a = _sec030_table(name="a", policies=(_scoping_policy(),))
    b = _sec030_table(name="b", policies=(_scoping_policy(),))
    schema = Schema(tables=(a, b))
    fixes = SEC030Fixer().fix(
        schema, {"allowlist": ["public.a"]}
    )
    assert [f.location for f in fixes] == ["public.b.tenant_id"]


def test_sec030_fix_respects_allowlist_unqualified() -> None:
    schema = Schema(
        tables=(
            _sec030_table(
                name="snapshot_events",
                policies=(_scoping_policy(),),
            ),
        ),
    )
    assert (
        SEC030Fixer().fix(
            schema, {"allowlist": ["snapshot_events"]}
        )
        == []
    )


def test_sec030_fix_quotes_mixed_case_column() -> None:
    # Postgres identifiers like `TenantId` need double-quoting in
    # ALTER COLUMN, otherwise the server lowercases and rejects.
    table = _sec030_table(
        column_details=(
            Column(name="id", data_type="uuid", is_nullable=False),
            Column(
                name="TenantId",
                data_type="integer",
                is_nullable=True,
            ),
        ),
    )
    policy = _scoping_policy(
        column='"TenantId"',  # quoted in policy SQL
        name="tenant",
    )
    table = Table(
        schema=table.schema,
        name=table.name,
        rls_enabled=table.rls_enabled,
        force_rls=table.force_rls,
        policies=(policy,),
        columns=table.columns,
        column_details=table.column_details,
    )
    schema = Schema(tables=(table,))
    fixes = SEC030Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert fixes[0].sql == (
        'ALTER TABLE public.documents '
        'ALTER COLUMN "TenantId" SET NOT NULL;'
    )


def test_sec030_fix_description_warns_about_backfilling_nulls() -> None:
    # The description MUST surface the runtime-failure risk
    # prominently — emitting the ALTER without warning would
    # silently lead operators into `--apply` errors.
    schema = Schema(
        tables=(_sec030_table(policies=(_scoping_policy(),)),),
    )
    [f] = SEC030Fixer().fix(schema, {})
    desc = f.description
    assert "BACKFILL" in desc  # all-caps emphasis
    assert "null values" in desc.lower() or "NULL" in desc
    # The UPDATE recipe must appear so operators don't have to
    # invent the backfill statement themselves.
    assert "UPDATE public.documents" in desc
    assert "IS NULL" in desc
    # The all-or-nothing batch-rollback consequence MUST be named —
    # operators reading the rendered SQL stream won't otherwise
    # connect "one ALTER fails" to "every other fix rolls back".
    assert "ROLLS BACK THE ENTIRE BATCH" in desc
    # The escape hatch (--output FILE to materialize) must be
    # surfaced too, so operators have a clear safer path.
    assert "--output" in desc
    # The allowlist alternative is named.
    assert "[lint.rules.SEC030]" in desc


def test_sec030_fix_raises_on_malformed_allowlist() -> None:
    schema = Schema(
        tables=(_sec030_table(policies=(_scoping_policy(),)),),
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC030Fixer().fix(schema, {"allowlist": "public.documents"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC030Fixer().fix(
            schema, {"allowlist": [" public.documents "]}
        )


# ---------- SEC031 fixer ----------


def test_sec031_fix_emits_drop_policy_for_restrictive_true() -> None:
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    fixes = SEC031Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC031"
    assert f.location == "public.t.floor"
    assert f.sql == "DROP POLICY floor ON public.t;"


def test_sec031_fix_silent_on_permissive_true() -> None:
    # Permissive USING (true) is SEC008's territory (admits every row);
    # dropping it would CHANGE access, so the SEC031 fixer skips it.
    schema = _dup_table(_policy("true", name="open", permissive=True))
    assert SEC031Fixer().fix(schema, {}) == []


def test_sec031_fix_silent_on_restrictive_with_real_predicate() -> None:
    # A restrictive policy with a real USING is a genuine floor — keep it.
    schema = _dup_table(
        _policy("tenant_id = 1", name="floor", permissive=False)
    )
    assert SEC031Fixer().fix(schema, {}) == []


def test_sec031_fix_silent_when_using_absent() -> None:
    # No USING clause → nothing constant-true to drop.
    schema = _dup_table(
        _policy(None, name="floor", command="INSERT", permissive=False)
    )
    assert SEC031Fixer().fix(schema, {}) == []


def test_sec031_fix_silent_when_with_check_is_a_real_predicate() -> None:
    # USING (true) is a no-op read floor, but a real WITH CHECK is a
    # load-bearing write floor (restrictive WITH CHECK AND-combines for
    # writes). Dropping the policy would let through writes the floor
    # rejected — a behavior change — so the fixer ABSTAINS even though
    # SEC031 the rule still fires on the no-op USING.
    schema = _dup_table(
        _policy(
            "true",
            name="write_floor",
            command="ALL",
            with_check="tenant_id = 1",
            permissive=False,
        )
    )
    assert SEC031Fixer().fix(schema, {}) == []


def test_sec031_fix_drops_when_with_check_is_also_constant_true() -> None:
    # Both USING and WITH CHECK are constant-true → the policy is
    # genuinely inert on the read AND write sides → the drop is
    # behavior-preserving, so the fixer emits it.
    schema = _dup_table(
        _policy(
            "true",
            name="floor",
            command="ALL",
            with_check="true",
            permissive=False,
        )
    )
    fixes = SEC031Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert fixes[0].sql == "DROP POLICY floor ON public.t;"


def test_sec031_fix_respects_allowlist() -> None:
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    assert (
        SEC031Fixer().fix(schema, {"allowlist": ["public.t.floor"]}) == []
    )


def test_sec031_fix_emits_one_per_offending_policy() -> None:
    schema = _dup_table(
        _policy("true", name="floor_a", permissive=False),
        _policy("tenant_id = 1", name="real", permissive=False),
        _policy("true", name="floor_b", permissive=False),
    )
    fixes = SEC031Fixer().fix(schema, {})
    assert sorted(f.location for f in fixes) == [
        "public.t.floor_a",
        "public.t.floor_b",
    ]


def test_sec031_fix_quotes_policy_and_table_when_required() -> None:
    schema = _dup_table(
        _policy("true", name="my floor", permissive=False),
        name="MixedCase Table",
    )
    sql = SEC031Fixer().fix(schema, {})[0].sql
    assert sql == 'DROP POLICY "my floor" ON public."MixedCase Table";'


def test_sec031_fix_description_explains_noop_and_alternative() -> None:
    # The fixer DROPs, but SEC031's other remedy (a real predicate)
    # needs human intent — the description must point at it.
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    [f] = SEC031Fixer().fix(schema, {})
    assert "floor" in f.description  # names the dropped policy
    assert "public.t" in f.description  # and its qualified table
    assert "no-op" in f.description
    assert "predicate" in f.description


def test_sec031_fix_raises_on_malformed_allowlist() -> None:
    schema = _dup_table(_policy("true", name="floor", permissive=False))
    with pytest.raises(TypeError, match="allowlist"):
        SEC031Fixer().fix(schema, {"allowlist": "public.t.floor"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC031Fixer().fix(schema, {"allowlist": [" public.t.floor "]})


# ---------- SEC015 fixer ----------


def _secdef(
    qname: str,
    *,
    signature: str = "",
    search_path: str | None = None,
    body: str = "SELECT 1",
    language: str = "sql",
    schema_name: str | None = None,
    function_name: str | None = None,
) -> Any:
    from pgrls.model import SecdefFunction

    # Mirror introspection: schema_name / function_name are captured
    # separately (v14+). Default to splitting on the LAST dot so the
    # common single-dot `schema.func` case matches; tests exercising a
    # dotted schema / function name pass them explicitly.
    s, _, f = qname.rpartition(".")
    return SecdefFunction(
        qualified_name=qname,
        body=body,
        language=language,
        search_path=search_path,
        signature=signature,
        schema_name=s if schema_name is None else schema_name,
        function_name=f if function_name is None else function_name,
    )


def test_sec015_fix_emits_minimal_safe_path_when_search_path_unset() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.read_secret", signature="integer"),
        ),
    )
    fixes = SEC015Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC015"
    assert f.sql == (
        "ALTER FUNCTION public.read_secret(integer) "
        "SET search_path = pg_catalog, pg_temp;"
    )


def test_sec015_fix_appends_pg_temp_when_path_set_but_unsafe() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "public.lookup",
                signature="text",
                search_path="pg_catalog, public",
            ),
        ),
    )
    [f] = SEC015Fixer().fix(schema, {})
    assert f.sql == (
        "ALTER FUNCTION public.lookup(text) "
        "SET search_path = pg_catalog, public, pg_temp;"
    )


def test_sec015_fix_strips_inner_pg_temp_and_repins_last() -> None:
    # pg_temp earlier in the path is searched first (Postgres uses
    # first-occurrence order); a trailing duplicate is irrelevant.
    # The fix strips the inner pg_temp so it appears exactly once,
    # at the end.
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "public.f",
                signature="integer",
                search_path="pg_temp, public, audit",
            ),
        ),
    )
    [f] = SEC015Fixer().fix(schema, {})
    assert f.sql == (
        "ALTER FUNCTION public.f(integer) "
        "SET search_path = public, audit, pg_temp;"
    )


def test_sec015_fix_silent_when_path_already_safe() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "public.safe_fn",
                signature="integer",
                search_path="pg_catalog, public, pg_temp",
            ),
        ),
    )
    assert SEC015Fixer().fix(schema, {}) == []


def test_sec015_fix_abstains_on_empty_signature_from_pre_v12_snapshot() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.legacy", signature=""),
        ),
    )
    assert SEC015Fixer().fix(schema, {}) == []


def test_sec015_fix_abstains_on_quoted_comma_search_path() -> None:
    # The naive comma-split tokenizer can't safely rewrite a path
    # containing both `"` and `,`. Abstain rather than emit a wrong
    # rewrite.
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "public.f",
                signature="integer",
                search_path='"weird, schema", public',
            ),
        ),
    )
    assert SEC015Fixer().fix(schema, {}) == []


def test_sec015_fix_abstains_on_injection_in_search_path_token() -> None:
    # A snapshot is a trust boundary: a tampered proconfig value with a
    # statement-terminating token must NOT be spliced verbatim into the
    # emitted `ALTER FUNCTION … SET search_path = …`. The fixer abstains
    # (the SEC015 finding still fires for the operator); no DDL is built
    # from the poisoned token.
    for poisoned in (
        "public; DROP TABLE secrets; --",  # bare token w/ terminator
        "public, evil; DROP TABLE t",      # second token unsafe
        "public-- comment",                 # bare token w/ comment
    ):
        schema = Schema(
            security_definer_functions=(
                _secdef(
                    "public.f",
                    signature="integer",
                    search_path=poisoned,
                ),
            ),
        )
        assert SEC015Fixer().fix(schema, {}) == [], poisoned


def test_sec015_fix_rewrites_quoted_identifier_without_comma() -> None:
    # A single double-quoted schema (no comma) is a benign token — the
    # surrounding quotes neutralize any interior punctuation — so the
    # fixer still rewrites it, pinning pg_temp last.
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "public.f",
                signature="integer",
                search_path='"My Schema"',
            ),
        ),
    )
    [f] = SEC015Fixer().fix(schema, {})
    assert 'SET search_path = "My Schema", pg_temp;' in f.sql


def test_sec015_fix_emits_per_overload() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.f", signature="integer"),
            _secdef("public.f", signature="text"),
        ),
    )
    fixes = SEC015Fixer().fix(schema, {})
    assert sorted(f.sql for f in fixes) == [
        "ALTER FUNCTION public.f(integer) "
        "SET search_path = pg_catalog, pg_temp;",
        "ALTER FUNCTION public.f(text) "
        "SET search_path = pg_catalog, pg_temp;",
    ]


def test_sec015_fix_respects_allowlist() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.f", signature="integer"),
            _secdef("audit.g", signature="text"),
        ),
    )
    fixes = SEC015Fixer().fix(schema, {"allowlist": ["public.f"]})
    assert [f.location for f in fixes] == ["audit.g(text)"]


def test_sec015_fix_allowlist_silences_every_overload() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.f", signature="integer"),
            _secdef("public.f", signature="text"),
        ),
    )
    assert SEC015Fixer().fix(
        schema, {"allowlist": ["public.f"]}
    ) == []


def test_sec015_fix_quotes_mixed_case_function_name() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.FastEq", signature="integer"),
        ),
    )
    [f] = SEC015Fixer().fix(schema, {})
    assert f.sql == (
        'ALTER FUNCTION public."FastEq"(integer) '
        "SET search_path = pg_catalog, pg_temp;"
    )


def test_sec015_fix_description_names_overload_and_alternative() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("audit.redact", signature="text"),
        ),
    )
    [f] = SEC015Fixer().fix(schema, {})
    assert "audit.redact(text)" in f.description
    assert "[lint.rules.SEC015]" in f.description
    assert "fully-qualifies" in f.description


def test_sec015_fix_raises_on_malformed_allowlist() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.f", signature="integer"),
        ),
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC015Fixer().fix(schema, {"allowlist": "public.f"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC015Fixer().fix(schema, {"allowlist": [" public.f "]})


# ---------- SEC017 fixer ----------


def _leakproof(
    qname: str,
    signature: str = "",
    *,
    schema_name: str | None = None,
    function_name: str | None = None,
) -> Any:
    """Local helper for SEC017Fixer tests. Inlined LeakproofFunction
    constructor — duplicating the shape rather than importing the
    one from `tests/rules/test_sec017.py` to keep the fixer-test
    file self-contained (test_fixers.py never imports across the
    `tests/rules/` directory). schema_name / function_name default to
    splitting on the LAST dot (the common `schema.func` case); the
    dotted-name regression tests pass them explicitly."""
    from pgrls.model import LeakproofFunction

    s, _, f = qname.rpartition(".")
    return LeakproofFunction(
        qualified_name=qname,
        signature=signature,
        schema_name=s if schema_name is None else schema_name,
        function_name=f if function_name is None else function_name,
    )


def test_sec017_fix_emits_alter_function_not_leakproof() -> None:
    schema = Schema(
        leakproof_functions=(_leakproof("public.fast_eq", "integer"),),
    )
    fixes = SEC017Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC017"
    assert f.location == "public.fast_eq(integer)"
    assert f.sql == (
        "ALTER FUNCTION public.fast_eq(integer) NOT LEAKPROOF;"
    )


def test_sec017_fix_emits_one_fix_per_overload() -> None:
    # Snapshot v12+ captures one entry per overload, and each
    # overload needs its own ALTER FUNCTION — distinct from how
    # SEC017's rule reports per qualified name. Pinning the
    # per-overload-fix contract.
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.fast_eq", "integer"),
            _leakproof("public.fast_eq", "text"),
        ),
    )
    fixes = SEC017Fixer().fix(schema, {})
    assert sorted(f.sql for f in fixes) == [
        "ALTER FUNCTION public.fast_eq(integer) NOT LEAKPROOF;",
        "ALTER FUNCTION public.fast_eq(text) NOT LEAKPROOF;",
    ]


def test_sec017_fix_abstains_on_empty_signature_from_pre_v12_snapshot() -> None:
    # A LeakproofFunction loaded from a pre-v12 snapshot has
    # signature="" (the older introspection didn't capture it).
    # Emitting `ALTER FUNCTION name() NOT LEAKPROOF` would target
    # the zero-arg overload, wrong for every function with args.
    # The fixer abstains — the operator re-snapshots to populate
    # signatures, then re-runs `pgrls fix`.
    schema = Schema(
        leakproof_functions=(_leakproof("public.fast_eq", ""),),
    )
    assert SEC017Fixer().fix(schema, {}) == []


def test_sec017_fix_mixed_pre_v12_and_v12_only_emits_for_v12_entries() -> None:
    # A schema mixing pre-v12 (signature="") and v12+ (signature
    # populated) entries — only the v12+ entries get a Fix.
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.legacy", ""),
            _leakproof("public.fresh", "integer"),
        ),
    )
    fixes = SEC017Fixer().fix(schema, {})
    assert [f.location for f in fixes] == ["public.fresh(integer)"]


def test_sec017_fix_respects_allowlist_qualified() -> None:
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.fast_eq", "integer"),
            _leakproof("audit.redact", "text"),
        ),
    )
    fixes = SEC017Fixer().fix(
        schema, {"allowlist": ["public.fast_eq"]}
    )
    assert [f.location for f in fixes] == ["audit.redact(text)"]


def test_sec017_fix_allowlist_silences_every_overload() -> None:
    # The allowlist key is the qualified name (matches SEC017's
    # rule semantics) — silencing `public.fast_eq` skips both
    # the (integer) and (text) overloads even though they are
    # separate entries.
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.fast_eq", "integer"),
            _leakproof("public.fast_eq", "text"),
        ),
    )
    assert SEC017Fixer().fix(
        schema, {"allowlist": ["public.fast_eq"]}
    ) == []


def test_sec017_fix_description_names_overload_and_alternative() -> None:
    # The description must name the specific overload (so the
    # operator sees what's being fixed) and surface SEC017's other
    # remedy (audit + allowlist).
    schema = Schema(
        leakproof_functions=(_leakproof("audit.redact", "text"),),
    )
    [f] = SEC017Fixer().fix(schema, {})
    assert "audit.redact(text)" in f.description
    assert "allowlist" in f.description.lower()
    assert "[lint.rules.SEC017]" in f.description


def test_sec017_fix_raises_on_malformed_allowlist() -> None:
    schema = Schema(
        leakproof_functions=(_leakproof("public.fast_eq", "integer"),),
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC017Fixer().fix(schema, {"allowlist": "public.fast_eq"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC017Fixer().fix(
            schema, {"allowlist": [" public.fast_eq "]}
        )


def test_sec017_fix_quotes_mixed_case_function_name() -> None:
    # `qualified_name` arrives raw from introspection (no Postgres-
    # style quoting). A mixed-case function name or one matching
    # a reserved keyword must be quoted in the emitted SQL or psql
    # rejects the statement. Route through `quote_qualified` like
    # SEC031 / SEC011 / SEC001 already do.
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.FastEq", "integer"),
        ),
    )
    [f] = SEC017Fixer().fix(schema, {})
    assert f.sql == (
        'ALTER FUNCTION public."FastEq"(integer) NOT LEAKPROOF;'
    )


def test_sec017_fix_quotes_reserved_keyword_schema() -> None:
    schema = Schema(
        leakproof_functions=(
            _leakproof("order.fast_eq", "integer"),
        ),
    )
    [f] = SEC017Fixer().fix(schema, {})
    assert f.sql == (
        'ALTER FUNCTION "order".fast_eq(integer) NOT LEAKPROOF;'
    )


# ---------- SEC032 fixer ----------


def test_sec032_fix_emits_alter_table_enable() -> None:
    schema = Schema(
        tables=(
            _table(rls=False, force=False, policies=(_policy("user_id = auth.uid()"),)),
        )
    )
    fixes = SEC032Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC032"
    assert f.location == "public.t"
    # SAME DDL as SEC001's fix — the difference is the prior state
    # (RLS-off + has policies vs RLS-off + empty). Enabling RLS
    # activates the dormant policies in one statement.
    assert f.sql == "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;"


def test_sec032_fix_silent_when_rls_already_enabled() -> None:
    # SEC032 fires only when RLS is off; the fixer mirrors.
    schema = Schema(
        tables=(_table(rls=True, force=False, policies=(_policy("true"),)),)
    )
    assert SEC032Fixer().fix(schema, {}) == []


def test_sec032_fix_silent_when_no_policies() -> None:
    # RLS off + no policies is SEC001's domain — SEC032 cedes the
    # case explicitly. The fixer must not double-emit.
    schema = Schema(tables=(_table(rls=False, force=False),))
    assert SEC032Fixer().fix(schema, {}) == []


def test_sec032_fix_respects_allowlist_qualified() -> None:
    pol = (_policy("user_id = auth.uid()"),)
    schema = Schema(
        tables=(
            _table(name="a", rls=False, force=False, policies=pol),
            _table(name="b", rls=False, force=False, policies=pol),
        )
    )
    fixes = SEC032Fixer().fix(schema, {"allowlist": ["public.a"]})
    assert [f.location for f in fixes] == ["public.b"]


def test_sec032_fix_respects_allowlist_unqualified() -> None:
    schema = Schema(
        tables=(
            _table(
                name="snapshot",
                rls=False,
                force=False,
                policies=(_policy("user_id = auth.uid()"),),
            ),
        )
    )
    assert SEC032Fixer().fix(schema, {"allowlist": ["snapshot"]}) == []


def test_sec032_fix_skips_partition_child_covered_by_ancestor() -> None:
    # SEC032 itself skips a child whose ancestor already has RLS:
    # the child's dormant policies are dead weight, not a security
    # hole, because parent-routed queries apply the parent's policies.
    # The fixer mirrors — flipping RLS on the child alone could
    # surprise direct-on-child queries.
    parent = _table(
        name="events",
        rls=True,
        force=False,
        policies=(_policy("tenant_id = 1"),),
    )
    child = Table(
        schema="public",
        name="events_2026",
        rls_enabled=False,
        force_rls=False,
        policies=(_policy("tenant_id = 1", name="child_p"),),
        partition_of=("public", "events"),
    )
    schema = Schema(tables=(parent, child))
    # Parent has RLS so SEC032 cedes the child to "covered by
    # ancestor"; only the parent has nothing for SEC032 to do
    # (it's already RLS-on). Expected: NO fixes.
    assert SEC032Fixer().fix(schema, {}) == []


def test_sec032_fix_description_explains_policy_count() -> None:
    schema = Schema(
        tables=(
            _table(
                rls=False,
                force=False,
                policies=(
                    _policy("user_id = auth.uid()", name="a"),
                    _policy("user_id = auth.uid()", name="b", command="INSERT"),
                ),
            ),
        )
    )
    [f] = SEC032Fixer().fix(schema, {})
    assert "public.t" in f.description
    assert "2" in f.description  # policy count
    assert "dormant" in f.description.lower()


def test_sec032_fix_raises_on_malformed_allowlist() -> None:
    schema = Schema(
        tables=(
            _table(
                rls=False, force=False,
                policies=(_policy("user_id = auth.uid()"),),
            ),
        )
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC032Fixer().fix(schema, {"allowlist": "public.t"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC032Fixer().fix(schema, {"allowlist": [" public.t "]})


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
                # `user_id` indexed so PERF003 stays silent — this
                # test pins generate_fixes' union/sort, not PERF003.
                indexes=(_idx("user_id", name="z_user_id_idx"),),
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


def test_generate_fixes_suppresses_clobbering_clause_rewrites() -> None:
    # CRITICAL regression: SEC011 (strip `OR true`), SEC019 (add
    # missing_ok), and PERF001 (SELECT-wrap) all rewrite the SAME USING
    # clause. Emitted together in one migration, SEC019 / PERF001 — which
    # build their ALTER from the ORIGINAL predicate — silently revert
    # SEC011's `OR true` security strip (the last ALTER wins). generate_fixes
    # now keeps only ONE writer per (policy, clause): the security-narrowing
    # SEC011 strip. The migration must not revive `OR true`.
    schema = _wrap_policy(
        _policy(
            "user_id = current_setting('app.t') OR true",
            command="SELECT",
        )
    )
    fixes = generate_fixes(schema, rule_options={})
    clause_rewrites = [
        f for f in fixes if f.rule_id in {"PERF001", "SEC011", "SEC019"}
    ]
    assert [f.rule_id for f in clause_rewrites] == ["SEC011"]
    sec011 = clause_rewrites[0]
    assert "USING (user_id = current_setting('app.t'))" in sec011.sql
    # No `OR true` / `OR TRUE` revived anywhere in the emitted migration.
    assert "TRUE" not in "\n".join(f.sql for f in fixes).upper()


def test_suppress_clobbering_clause_rewrites_keeps_one_writer_per_clause() -> None:
    # Unit-level coverage of the orchestrator's per-clause keeper logic.
    from pgrls.fixers import _suppress_clobbering_clause_rewrites as suppress

    def _f(rule_id: str, clauses: set[str]) -> Fix:
        return Fix(rule_id, "public.t.p", f"-- {rule_id}", "d",
                   clauses=frozenset(clauses))

    # Same clause (USING): the security-narrowing SEC011 wins; SEC019 and
    # PERF001 are dropped (defer to the next run).
    kept = suppress([_f("PERF001", {"using"}), _f("SEC011", {"using"}),
                     _f("SEC019", {"using"})])
    assert [f.rule_id for f in kept] == ["SEC011"]

    # Different clauses don't contest — both survive (no false suppression).
    kept = suppress([_f("SEC011", {"using"}), _f("SEC019", {"with_check"})])
    assert {f.rule_id for f in kept} == {"SEC011", "SEC019"}

    # A non-clause fix (ALTER TABLE etc., empty clauses) is never touched.
    alter = Fix("SEC002", "public.t", "ALTER TABLE ...", "d")
    kept = suppress([alter, _f("SEC011", {"using"}), _f("SEC019", {"using"})])
    assert alter in kept and [f.rule_id for f in kept if f.clauses] == ["SEC011"]

    # A multi-clause non-keeper is dropped WHOLE when it loses any clause
    # (its other clause re-fires next run).
    kept = suppress([_f("SEC011", {"using"}),
                     _f("SEC019", {"using", "with_check"})])
    assert [f.rule_id for f in kept] == ["SEC011"]


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


def test_generate_fixes_suppresses_alter_on_hyg003_dropped_policy() -> None:
    # Regression (audit findings #3 + #10): two duplicate policies
    # (HYG003) whose shared predicate also trips PERF001. Naively
    # sorting by (rule_id, location) put `HYG003 DROP p_b` BEFORE
    # `PERF001 ALTER p_b`, so the emitted migration ran an ALTER on a
    # policy that had just been dropped — a runtime failure mid-
    # script. generate_fixes must SUPPRESS the ALTER targeting any
    # policy HYG003 will drop, leaving a runnable sequence. The
    # surviving twin (`p_a`) still gets its ALTER, so no remediation
    # is lost.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    _policy("user_id = auth.uid()", name="p_a"),
                    _policy("user_id = auth.uid()", name="p_b"),
                ),
                columns=("id", "user_id"),
                indexes=(_idx("user_id", name="t_user_id_idx"),),
            ),
        )
    )
    fixes = generate_fixes(schema, rule_options={})
    pairs = [(f.rule_id, f.location) for f in fixes]
    # The redundant duplicate is dropped …
    assert ("HYG003", "public.t.p_b") in pairs
    # … the surviving twin is wrapped by PERF001 …
    assert ("PERF001", "public.t.p_a") in pairs
    # … and crucially NO ALTER targets the dropped policy.
    assert ("PERF001", "public.t.p_b") not in pairs

    # The emitted sequence must be runnable: every ALTER POLICY must
    # name a policy that is NOT dropped earlier in the script.
    dropped = {
        f.location for f in fixes if f.sql.startswith("DROP POLICY")
    }
    altered = {
        f.location for f in fixes if f.sql.startswith("ALTER POLICY")
    }
    assert dropped.isdisjoint(altered)


def test_generate_fixes_suppresses_alter_when_three_duplicates() -> None:
    # Three identical policies: HYG003 keeps `p_a`, drops `p_b` and
    # `p_c`. Only the survivor may carry an ALTER; both drops must be
    # ALTER-free so the migration runs.
    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(
                    _policy("user_id = auth.uid()", name="p_a"),
                    _policy("user_id = auth.uid()", name="p_b"),
                    _policy("user_id = auth.uid()", name="p_c"),
                ),
                columns=("id", "user_id"),
                indexes=(_idx("user_id", name="t_user_id_idx"),),
            ),
        )
    )
    fixes = generate_fixes(schema, rule_options={})
    pairs = {(f.rule_id, f.location) for f in fixes}
    assert ("HYG003", "public.t.p_b") in pairs
    assert ("HYG003", "public.t.p_c") in pairs
    assert ("PERF001", "public.t.p_a") in pairs
    # No ALTER on either dropped policy.
    assert ("PERF001", "public.t.p_b") not in pairs
    assert ("PERF001", "public.t.p_c") not in pairs


def test_generate_fixes_keeps_alter_when_no_duplicate_dropped() -> None:
    # Sanity: with no HYG003 drop, the suppression is inert — a lone
    # PERF001-tripping policy still gets its ALTER.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    fixes = generate_fixes(schema, rule_options={})
    assert [(f.rule_id, f.location) for f in fixes] == [
        ("PERF001", "public.t.p"),
    ]


# ---------- SEC011 fixer ----------


def test_sec011_fix_strips_or_true_and_unwraps() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    fixes = SEC011Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "SEC011"
    assert f.location == "public.t.p"
    assert "ALTER POLICY p ON public.t" in f.sql
    assert "USING (user_id = 1)" in f.sql
    # The bypass disjunct is gone — no literal true in any case.
    assert "TRUE" not in f.sql
    assert "true" not in f.sql


def test_sec011_fix_keeps_remaining_disjuncts_when_three_args() -> None:
    # `a OR b OR true` keeps `a OR b` (no unwrap — two real args).
    schema = _wrap_policy(_policy("user_id = 1 OR user_id = 2 OR true"))
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "USING (user_id = 1 OR user_id = 2)" in sql
    assert "TRUE" not in sql


def test_sec011_fix_strips_true_on_left_side() -> None:
    schema = _wrap_policy(_policy("true OR user_id = 1"))
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "USING (user_id = 1)" in sql
    assert "TRUE" not in sql


def test_sec011_fix_strips_or_true_nested_in_and() -> None:
    # `a AND (b OR true)` → `a AND b`. The inner OR unwraps; the
    # AND is left with its two real conjuncts.
    schema = _wrap_policy(
        _policy("user_id = 1 AND (user_id = 2 OR true)", command="ALL")
    )
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "user_id = 1 AND user_id = 2" in sql
    assert "TRUE" not in sql


def test_sec011_fix_rewrites_with_check_side() -> None:
    p = _policy(
        "user_id = 1",
        command="ALL",
        with_check="user_id = 2 OR true",
    )
    sql = SEC011Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "WITH CHECK (user_id = 2)" in sql
    # USING was clean, so it must not appear in the minimal-diff ALTER.
    assert "USING (" not in sql


def test_sec011_fix_emits_only_changed_clauses() -> None:
    # USING has the bypass; WITH CHECK is already clean → only USING
    # is re-emitted.
    p = _policy(
        "user_id = 1 OR true",
        command="ALL",
        with_check="user_id = 1",
    )
    sql = SEC011Fixer().fix(_wrap_policy(p), {})[0].sql
    assert "USING (user_id = 1)" in sql
    assert "WITH CHECK" not in sql


def test_sec011_fix_silent_when_no_or_true() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR user_id = 2"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_leaves_or_true_inside_subquery_where() -> None:
    # The SEC011 *rule* deliberately does not descend into a
    # subquery's own WHERE (an `OR true` there is the subquery's
    # predicate, not the policy admitting every row — e.g. the
    # legitimate `EXISTS (SELECT 1 ... WHERE flag OR true)` shape).
    # The fixer must mirror that scope exactly: rewriting the
    # subquery would mutate a policy `pgrls lint` calls clean and
    # trip `pgrls fix --check` on zero violations.
    schema = _wrap_policy(
        _policy(
            "user_id IN (SELECT member_id FROM public.acl "
            "WHERE active OR true)"
        )
    )
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_strips_top_level_or_true_around_a_sublink() -> None:
    # The opposite of the above: the `OR true` is at the policy's
    # top level (not inside the subquery), so it IS stripped. The
    # surviving SubLink comparison is left intact.
    schema = _wrap_policy(
        _policy("user_id IN (SELECT member_id FROM public.acl) OR true")
    )
    sql = SEC011Fixer().fix(schema, {})[0].sql
    assert "SELECT member_id FROM public.acl" in sql
    assert "TRUE" not in sql


def test_sec011_fix_skips_or_true_under_not() -> None:
    # `NOT (a OR true)` is deny-all (NOT of always-true). Stripping
    # the `OR true` would leave `NOT a`, which BROADENS the policy —
    # a security regression. The fixer must not touch an OR-true in
    # non-monotone (negated) position; the SEC011 finding stays for
    # human review.
    schema = _wrap_policy(_policy("NOT (user_id = 1 OR true)"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_negated_or_true_inside_and() -> None:
    # `id = 1 AND NOT (user_id = 2 OR true)` — the AND chain is
    # monotone, but the OR-true sits under a NOT, so it must be left
    # alone. No clause changes ⇒ no fix.
    schema = _wrap_policy(
        _policy("id = 1 AND NOT (user_id = 2 OR true)", command="ALL")
    )
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_or_true_under_is_false_test() -> None:
    # `(a OR true) IS FALSE` ≡ `true IS FALSE` ≡ deny-all. Stripping
    # to `a IS FALSE` would BROADEN access. A `BooleanTest` is not a
    # BoolExpr, so `_strip_or_true` stops at it — the OR-true under
    # the IS FALSE test is non-monotone and left untouched.
    schema = _wrap_policy(_policy("(user_id = 1 OR true) IS FALSE"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_or_true_under_negating_comparison() -> None:
    # `(a OR true) = false` ≡ `true = false` ≡ deny-all. Rewriting
    # to `a = false` would change the truth value and broaden access.
    # The comparison (A_Expr) is non-monotone in its operand, so the
    # fixer leaves it alone.
    schema = _wrap_policy(_policy("(user_id = 1 OR true) = false"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_skips_vacuous_true_or_true() -> None:
    # `true OR true` has no real predicate to keep once the trues
    # are stripped — the fixer leaves it for human review rather
    # than emit an empty `USING ()`.
    schema = _wrap_policy(_policy("true OR true"))
    assert SEC011Fixer().fix(schema, {}) == []


def test_sec011_fix_respects_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    assert (
        SEC011Fixer().fix(schema, {"allowlist": ["public.t.p"]}) == []
    )


def test_sec011_fix_does_not_mutate_input_schema() -> None:
    p = _policy("user_id = 1 OR true")
    schema = _wrap_policy(p)
    SEC011Fixer().fix(schema, {})
    # The original AST still renders with the OR-true intact.
    from pglast.stream import RawStream

    rendered = RawStream()(p.using_ast)
    assert "TRUE" in rendered or "true" in rendered


def test_sec011_fix_description_explains_bypass_and_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    [f] = SEC011Fixer().fix(schema, {})
    assert "OR true" in f.description
    assert "[lint.rules.SEC011]" in f.description


def test_sec011_fix_raises_on_malformed_allowlist() -> None:
    schema = _wrap_policy(_policy("user_id = 1 OR true"))
    with pytest.raises(TypeError, match="allowlist"):
        SEC011Fixer().fix(schema, {"allowlist": "public.t.p"})


def test_strip_constant_true_for_mirror_behaviour() -> None:
    # The SEC006/SEC020 fixers reuse this helper (audit finding #4) to
    # avoid mirroring a constant-true USING into a wide-open WITH
    # CHECK. Pin its contract directly.
    from pglast.stream import RawStream

    from pgrls.fixers.sec011 import strip_constant_true_for_mirror

    def strip(sql: str) -> str | None:
        out = strip_constant_true_for_mirror(parse_expr(sql))
        return None if out is None else RawStream()(out)

    # None input → None.
    assert strip_constant_true_for_mirror(None) is None
    # Constant-true disjunct removed; real predicate kept.
    assert strip("user_id = 1 OR true") == "user_id = 1"
    # A clean predicate is returned unchanged.
    assert strip("user_id = 1") == "user_id = 1"
    # Trivially-true predicates → None (caller must not mirror them).
    assert strip("true") is None
    assert strip("true OR true") is None


def test_default_fixers_registers_every_shipping_fixer() -> None:
    rule_ids = {fixer.rule_id for fixer in default_fixers()}
    assert {
        "SEC001",
        "SEC002",
        "SEC006",
        "SEC011",
        "SEC019",
        "SEC020",
        "SEC031",
        "PERF001",
        "PERF003",
        "HYG003",
        "VIEW001",
        "VIEW002",
    } <= rule_ids


def test_fix_dataclass_is_frozen() -> None:
    import dataclasses

    f = Fix(
        rule_id="X", location="public.t", sql="--", description="test"
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.rule_id = "Y"  # type: ignore[misc]


# ============================================================
# Edge cases — fixer robustness
# ============================================================

def test_sec002_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with SEC002's strict parser
    # (parse_table_ref_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = Schema(tables=(_table(rls=True, force=False),))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        SEC002Fixer().fix(schema, {"allowlist": "public.t"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        SEC002Fixer().fix(schema, {"allowlist": [" public.t "]})


def test_perf001_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with PERF001's strict parser
    # (parse_policy_id_allowlist), so a malformed allowlist raises
    # TypeError — `pgrls fix` surfaces it as a ToolError, exactly
    # as `pgrls lint` rejects the same config.
    schema = _wrap_policy(_policy("user_id = auth.uid()"))
    # Bad type — not a list.
    with pytest.raises(TypeError, match="allowlist"):
        PERF001Fixer().fix(schema, {"allowlist": "public.t.p"})
    # Malformed entry — surrounding whitespace.
    with pytest.raises(TypeError, match="allowlist"):
        PERF001Fixer().fix(schema, {"allowlist": [" public.t.p "]})


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
    with pytest.raises(ValueError, match="control character"):
        quote_ident("evil\x00name")


def test_quote_ident_rejects_embedded_newline() -> None:
    from pgrls.fixers._idents import quote_ident
    with pytest.raises(ValueError, match="control character"):
        quote_ident("name\nwith\nnewlines")


def test_perf001_fix_never_emits_with_check_even_with_content() -> None:
    # PERF001 never changes WITH CHECK, so it must not re-emit it even when
    # the WITH CHECK carries non-trivial content. Re-emitting it would
    # clobber a sibling fixer's WITH CHECK rewrite in the same migration
    # (the critical clobber bug). PERF001 also no longer round-trips WITH
    # CHECK, so it presents no WITH CHECK injection surface at all.
    p = _policy(
        "user_id = auth.uid()",
        command="ALL",
        with_check="user_id = (SELECT auth.uid()) AND deleted_at IS NULL",
    )
    schema = _wrap_policy(p)
    sql = PERF001Fixer().fix(schema, {})[0].sql
    assert "USING (user_id = (SELECT auth.uid()))" in sql
    assert "WITH CHECK" not in sql
    assert "deleted_at" not in sql


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
    # the deepcopy → direct-construction perf fix; if a future
    # refactor swaps SubLinkType, drops the LimitOption default,
    # or otherwise breaks the emitted SQL, this fails.
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


def test_quote_ident_quotes_reserved_keywords() -> None:
    # A table named "select" or a policy named "order" must be
    # quoted at emission time, otherwise pgrls's fixer SQL is a
    # syntax error on the server. An earlier regex-only check
    # treated reserved words as plain identifiers because they
    # match `[a-z_][a-z0-9_]*`.
    from pgrls.fixers._idents import quote_ident

    for kw in ("select", "from", "where", "table", "user", "order"):
        out = quote_ident(kw)
        assert out == f'"{kw}"', (
            f"reserved keyword {kw!r} must be quoted, got {out!r}"
        )


def test_quote_ident_keyword_check_is_case_insensitive() -> None:
    # Postgres parses identifiers case-insensitively before
    # quoting. `SELECT` / `Select` / `select` all collide with the
    # reserved token. A user with a `"Select"` table (mixed case)
    # gets quoting either way (mixed case alone forces it), but
    # pin the case-folded path explicitly.
    from pgrls.fixers._idents import quote_ident

    assert quote_ident("SELECT") == '"SELECT"'
    assert quote_ident("Select") == '"Select"'


def test_quote_ident_rejects_tab_character() -> None:
    # An earlier change rejected null/newline; tab is the same
    # hazard. Pin the wider control-char check so the defense is
    # uniform.
    from pgrls.fixers._idents import quote_ident

    with pytest.raises(ValueError, match="control character"):
        quote_ident("weird\tname")


def test_quote_ident_rejects_all_c0_controls() -> None:
    from pgrls.fixers._idents import quote_ident

    for codepoint in list(range(0x20)) + [0x7f]:
        ch = chr(codepoint)
        with pytest.raises(ValueError, match="control character"):
            quote_ident(f"x{ch}y")


def test_quote_ident_quotes_non_ascii() -> None:
    # ASCII-only regex is the gate; pin so a future swap to
    # str.isidentifier() (which accepts Unicode letters) doesn't
    # silently emit non-ASCII bare on locale-dependent servers.
    from pgrls.fixers._idents import quote_ident

    assert quote_ident("café") == '"café"'
    assert quote_ident("über") == '"über"'


def test_perf001_fixer_default_auth_functions_matches_rule_default() -> None:
    # Pin "the fixer fixes exactly what the rule reports" by
    # asserting both modules consume the same default set. Two
    # parallel constants (the previous shape) would silently drift
    # when a future change adds, e.g., `app.current_user_id` to
    # the rule's defaults but not the fixer's — the user would
    # see the lint flag the call but `pgrls fix` wouldn't generate
    # a fix.
    from pgrls.fixers import perf001 as fixer_mod
    from pgrls.rules import perf001 as rule_mod

    assert (
        fixer_mod._DEFAULT_AUTH_FUNCTIONS
        is rule_mod._DEFAULT_AUTH_FUNCTIONS
    ), (
        "Fixer must import the rule's _DEFAULT_AUTH_FUNCTIONS, "
        "not maintain its own copy."
    )


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


# ---------- render_fixes / render_migration ----------


def _mk_fix(
    rule_id: str = "SEC002",
    location: str = "public.t",
    sql: str = "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;",
    description: str = "Enable FORCE row level security on public.t.",
) -> Fix:
    return Fix(
        rule_id=rule_id,
        location=location,
        sql=sql,
        description=description,
    )


def test_render_fixes_emits_comment_and_sql_per_fix() -> None:
    out = render_fixes([_mk_fix()])
    assert (
        "-- [SEC002] Enable FORCE row level security on public.t."
        in out
    )
    assert "ALTER TABLE public.t FORCE ROW LEVEL SECURITY;" in out


def test_render_fixes_separates_blocks_with_a_blank_line() -> None:
    out = render_fixes(
        [
            _mk_fix(rule_id="SEC001", sql="A;"),
            _mk_fix(rule_id="SEC002", sql="B;"),
        ]
    )
    # Block N's SQL, blank line, block N+1's comment.
    assert "A;\n\n-- [SEC002]" in out


def test_render_fixes_empty_is_empty_string() -> None:
    assert render_fixes([]) == ""


def test_render_fixes_has_no_trailing_newline() -> None:
    # The caller adds the final newline (click.echo / render_migration).
    assert not render_fixes([_mk_fix()]).endswith("\n")


def test_render_migration_header_names_pgrls_version() -> None:
    out = render_migration([_mk_fix()], tool_version="9.9.9")
    assert "generated by pgrls 9.9.9" in out


def test_render_migration_header_states_fix_count() -> None:
    one = render_migration([_mk_fix()], tool_version="1.0")
    assert "1 fix." in one
    two = render_migration(
        [_mk_fix(rule_id="SEC001"), _mk_fix(rule_id="SEC002")],
        tool_version="1.0",
    )
    assert "2 fixes." in two


def test_render_migration_embeds_the_render_fixes_body() -> None:
    fixes = [_mk_fix()]
    out = render_migration(fixes, tool_version="1.0")
    assert render_fixes(fixes) in out


def test_render_migration_is_deterministic() -> None:
    # No timestamp — regenerating against the same fixes yields a
    # byte-identical file (clean diffs for a committed migration).
    fixes = [_mk_fix()]
    a = render_migration(fixes, tool_version="1.0")
    b = render_migration(fixes, tool_version="1.0")
    assert a == b


def test_render_migration_ends_with_exactly_one_newline() -> None:
    out = render_migration([_mk_fix()], tool_version="1.0")
    assert out.endswith("\n")
    assert not out.endswith("\n\n")


def test_render_migration_header_lines_are_sql_comments() -> None:
    # The header must be `--` comments so the whole file is valid
    # SQL that `psql -f` runs as-is.
    out = render_migration([_mk_fix()], tool_version="1.0")
    header = out.split("\n\n", 1)[0]
    assert all(
        line.startswith("--") for line in header.splitlines()
    )


def test_render_migration_handles_empty_fixes() -> None:
    # `render_migration` is a public function. The CLI guards
    # against calling it with no fixes (it reports "no auto-fixable
    # violations" and writes nothing), but a programmatic caller
    # may still pass an empty list — pin that it returns the header
    # alone, reports "0 fixes", and does not crash.
    out = render_migration([], tool_version="1.0")
    assert "0 fixes." in out
    assert out.endswith("\n")


# ---------- PERF003 fixer ----------


def _idx(*columns: str, name: str = "i") -> Index:
    return Index(
        name=name,
        access_method="btree",
        columns=columns,
        is_unique=False,
        is_partial=False,
    )


def _perf_table(
    *policies: Policy,
    name: str = "t",
    schema: str = "public",
    rls: bool = True,
    indexes: tuple[Index, ...] = (),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=True,
        policies=policies,
        indexes=indexes,
        columns=("id", "tenant_id", "owner"),
    )


def test_perf003_fix_emits_create_index_for_unindexed_column() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('app.t', true)", name="p"),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "PERF003"
    assert f.sql == "CREATE INDEX ON public.t (tenant_id);"
    assert f.location == "public.t (tenant_id)"


def test_perf003_fix_silent_when_column_has_leading_index() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('app.t', true)"),
        indexes=(_idx("tenant_id"),),
    ),))
    assert PERF003Fixer().fix(schema, {}) == []


def test_perf003_fix_silent_when_rls_disabled() -> None:
    # PERF003's domain is policy-driven filtering — RLS off, no fix.
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('app.t', true)"),
        rls=False,
    ),))
    assert PERF003Fixer().fix(schema, {}) == []


def test_perf003_fix_silent_when_rls_enabled_but_no_policies() -> None:
    # RLS on but no policies — nothing filters through a predicate,
    # so there is no column to index. Mirrors the rule: the
    # per-policy loop is empty and no Fix is emitted.
    schema = Schema(tables=(_perf_table(),))
    assert PERF003Fixer().fix(schema, {}) == []


def test_perf003_fix_emits_per_table_for_same_column_on_two_tables() -> None:
    # The same unindexed column on two tables is two separate
    # findings — the fixer keys fixes on (table, column), so it
    # emits one CREATE INDEX per table, not a single dedup'd one.
    pred = "tenant_id = current_setting('app.t', true)"
    schema = Schema(tables=(
        _perf_table(_policy(pred), name="a"),
        _perf_table(_policy(pred), name="b"),
    ))
    fixes = PERF003Fixer().fix(schema, {})
    assert sorted(f.sql for f in fixes) == [
        "CREATE INDEX ON public.a (tenant_id);",
        "CREATE INDEX ON public.b (tenant_id);",
    ]


def test_perf003_fix_dedupes_column_across_policies() -> None:
    # Two policies filter the same unindexed column — the rule fires
    # twice but one index resolves both, so the fixer emits one Fix.
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('app.t', true)", name="read"
        ),
        _policy(
            "tenant_id = current_setting('app.t', true)",
            name="write",
            command="ALL",
            with_check="tenant_id = current_setting('app.t', true)",
        ),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert [f.sql for f in fixes] == [
        "CREATE INDEX ON public.t (tenant_id);"
    ]


def test_perf003_fix_emits_one_index_per_unindexed_column() -> None:
    # A composite predicate over two unindexed columns → two indexes.
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('a', true) "
            "AND owner = current_setting('u', true)"
        ),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert sorted(f.sql for f in fixes) == [
        "CREATE INDEX ON public.t (owner);",
        "CREATE INDEX ON public.t (tenant_id);",
    ]


def test_perf003_fix_skips_the_already_indexed_column() -> None:
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('a', true) "
            "AND owner = current_setting('u', true)"
        ),
        indexes=(_idx("tenant_id"),),
    ),))
    fixes = PERF003Fixer().fix(schema, {})
    assert [f.sql for f in fixes] == ["CREATE INDEX ON public.t (owner);"]


def test_perf003_fix_respects_allowlist() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('a', true)", name="p"),
    ),))
    assert PERF003Fixer().fix(
        schema, {"allowlist": ["public.t.p"]}
    ) == []


def test_perf003_fix_indexes_column_kept_in_scope_by_a_live_policy() -> None:
    # `tenant_id` is referenced by an allowlisted policy AND a
    # non-allowlisted one — the live policy keeps it in scope, so
    # the index is still emitted.
    schema = Schema(tables=(_perf_table(
        _policy(
            "tenant_id = current_setting('a', true)", name="exempt"
        ),
        _policy(
            "tenant_id = current_setting('a', true)", name="active"
        ),
    ),))
    fixes = PERF003Fixer().fix(
        schema, {"allowlist": ["public.t.exempt"]}
    )
    assert [f.sql for f in fixes] == [
        "CREATE INDEX ON public.t (tenant_id);"
    ]


def test_perf003_fix_quotes_table_name_when_required() -> None:
    schema = Schema(tables=(
        Table(
            schema="public",
            name="MixedCase",
            rls_enabled=True,
            force_rls=True,
            columns=("id", "tenant_id"),
            policies=(
                _policy("tenant_id = current_setting('a', true)"),
            ),
            indexes=(),
        ),
    ))
    sql = PERF003Fixer().fix(schema, {})[0].sql
    assert sql == 'CREATE INDEX ON public."MixedCase" (tenant_id);'


def test_perf003_fix_description_flags_lock_and_concurrently() -> None:
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('a', true)"),
    ),))
    [f] = PERF003Fixer().fix(schema, {})
    assert "CONCURRENTLY" in f.description
    assert "tenant_id" in f.description


def test_perf003_fix_raises_on_malformed_allowlist() -> None:
    # The fixer validates with PERF003's strict parser
    # (parse_policy_id_allowlist) — a malformed allowlist raises,
    # surfaced by the `fix` CLI exactly as `pgrls lint` rejects it.
    schema = Schema(tables=(_perf_table(
        _policy("tenant_id = current_setting('a', true)", name="p"),
    ),))
    with pytest.raises(TypeError, match="allowlist"):
        PERF003Fixer().fix(schema, {"allowlist": "public.t.p"})
    with pytest.raises(TypeError, match="allowlist"):
        PERF003Fixer().fix(schema, {"allowlist": [" public.t.p "]})


# ---------- PERF004 fixer ----------


def _perf004_table(
    *policies: Policy,
    name: str = "users",
    schema: str = "public",
    rls: bool = True,
    indexes: tuple[Index, ...] = (
        _idx("email", name="users_email_idx"),
    ),
    columns: tuple[str, ...] = ("id", "email", "name"),
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=rls,
        force_rls=True,
        policies=policies,
        indexes=indexes,
        columns=columns,
    )


def test_perf004_fix_emits_expression_index_for_single_func_wrap() -> None:
    # Canonical case: `lower(email) = X` against an existing
    # plain `email` index → CREATE INDEX on `lower(email)`.
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.email')", name="p"),
    ),))
    fixes = PERF004Fixer().fix(schema, {})
    assert len(fixes) == 1
    f = fixes[0]
    assert f.rule_id == "PERF004"
    assert f.sql.startswith("CREATE INDEX IF NOT EXISTS pgrls_idx_")
    assert f.sql.endswith(" ON public.users (lower(email));")
    assert "lower(email)" in f.location


def test_perf004_fix_silent_when_no_plain_index_on_column() -> None:
    # No plain index on `email` → PERF003 fires for the un-indexed
    # column, not PERF004. The fixer mirrors and stays silent.
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.email')"),
        indexes=(),
    ),))
    assert PERF004Fixer().fix(schema, {}) == []


def test_perf004_fix_silent_when_rls_disabled() -> None:
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.email')"),
        rls=False,
    ),))
    assert PERF004Fixer().fix(schema, {}) == []


def test_perf004_fix_silent_when_predicate_uses_bare_column() -> None:
    # `email = X` already uses the plain index; PERF004 doesn't fire.
    schema = Schema(tables=(_perf004_table(
        _policy("email = current_setting('app.email')"),
    ),))
    assert PERF004Fixer().fix(schema, {}) == []


def test_perf004_fix_silent_when_func_wraps_value_side() -> None:
    # PERF004 itself stays silent when the function wraps the VALUE
    # (`email = lower(current_setting(...))`) — the column is bare,
    # the plain index is usable. The fixer mirrors.
    schema = Schema(tables=(_perf004_table(
        _policy("email = lower(current_setting('app.email'))"),
    ),))
    assert PERF004Fixer().fix(schema, {}) == []


def test_perf004_fix_emits_outermost_funccall_for_nested_wrap() -> None:
    # `lower(upper(email))` — the planner needs an index matching
    # the full predicate expression, not the inner `upper`. The
    # fixer emits the outermost FuncCall.
    schema = Schema(tables=(_perf004_table(
        _policy("lower(upper(email)) = current_setting('app.x')"),
    ),))
    fixes = PERF004Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert fixes[0].sql.startswith("CREATE INDEX IF NOT EXISTS pgrls_idx_")
    assert fixes[0].sql.endswith(
        " ON public.users (lower(upper(email)));"
    )


def test_perf004_fix_dedupes_expression_across_policies() -> None:
    # Two policies wrapping the same column in the same expression
    # → one CREATE INDEX, not two duplicates.
    pred = "lower(email) = current_setting('app.email')"
    schema = Schema(tables=(_perf004_table(
        _policy(pred, name="read"),
        _policy(pred, name="write", command="ALL", with_check=pred),
    ),))
    fixes = PERF004Fixer().fix(schema, {})
    assert len(fixes) == 1
    assert fixes[0].sql.endswith(" ON public.users (lower(email));")


def test_perf004_fix_emits_separate_index_per_distinct_expression() -> None:
    # `lower(email)` and `upper(email)` are different expressions →
    # the planner needs distinct indexes for each.
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.l')", name="lo"),
        _policy("upper(email) = current_setting('app.u')", name="up"),
    ),))
    fixes = PERF004Fixer().fix(schema, {})
    suffixes = sorted(f.sql.split(" ON ", 1)[1] for f in fixes)
    assert suffixes == [
        "public.users (lower(email));",
        "public.users (upper(email));",
    ]
    assert all(
        f.sql.startswith("CREATE INDEX IF NOT EXISTS pgrls_idx_")
        for f in fixes
    )


def test_perf004_fix_respects_allowlist() -> None:
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.x')", name="p"),
    ),))
    assert (
        PERF004Fixer().fix(
            schema, {"allowlist": ["public.users.p"]}
        )
        == []
    )


def test_perf004_fix_description_flags_lock_concurrently_and_alternative() -> None:
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.x')"),
    ),))
    [f] = PERF004Fixer().fix(schema, {})
    # CONCURRENTLY is the production-safe alternative, named.
    assert "CONCURRENTLY" in f.description
    # The other remedy (rewrite predicate to bare column) is also
    # surfaced so the operator doesn't think the index is the only
    # path.
    assert "bare column" in f.description
    # The actual expression text appears in the description so the
    # operator sees what's being indexed without reading SQL.
    assert "lower(email)" in f.description


def test_perf004_fix_suppressed_when_funccall_nested_in_value_expr() -> None:
    # Regression (round-7): the flagged FuncCall is a STRICT SUB-EXPRESSION
    # of the comparison operand (wrapped in COALESCE / concat / CASE). An
    # index on just the inner FuncCall can never serve the predicate, so
    # the fixer must suppress and defer to the human — never emit a useless
    # index. (The RULE still flags the function-wrapped column; only the
    # auto-fix is withheld.)
    for pred in (
        "coalesce(lower(email), '') = current_setting('app.e')",
        "lower(email) || upper(email) = current_setting('app.e')",
        "(CASE WHEN id > 0 THEN lower(email) END) = current_setting('app.e')",
    ):
        schema = Schema(tables=(_perf004_table(_policy(pred, name="p")),))
        assert PERF004Fixer().fix(schema, {}) == [], pred


def test_perf004_fix_index_is_named_and_idempotent() -> None:
    # Regression (round-7): the emitted CREATE INDEX is named
    # (deterministic) and IF NOT EXISTS, so a second `pgrls fix` run is
    # byte-identical and re-applying the migration is a no-op — no
    # duplicate-index accumulation.
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.e')", name="p"),
    ),))
    first = PERF004Fixer().fix(schema, {})
    second = PERF004Fixer().fix(schema, {})
    assert len(first) == 1
    assert "CREATE INDEX IF NOT EXISTS pgrls_idx_" in first[0].sql
    assert [f.sql for f in first] == [f.sql for f in second]


def test_perf004_fix_raises_on_malformed_allowlist() -> None:
    schema = Schema(tables=(_perf004_table(
        _policy("lower(email) = current_setting('app.x')", name="p"),
    ),))
    with pytest.raises(TypeError, match="allowlist"):
        PERF004Fixer().fix(schema, {"allowlist": "public.users.p"})
    with pytest.raises(TypeError, match="allowlist"):
        PERF004Fixer().fix(schema, {"allowlist": [" public.users.p "]})


# ---------- SEC015 / SEC017: dotted schema/function names ----------
#
# Regression for the qualified-name split bug. `qualified_name` is
# `nspname || '.' || proname` from introspection — ambiguous once
# either component contains a dot. The old fixers did
# `qualified_name.partition(".")`, so a function `f` in schema `a.b`
# (qualified_name `a.b.f`) was split to schema `a`, function `b.f`,
# emitting `ALTER FUNCTION a."b.f"(…)` — wrong object. The fix carries
# schema_name / function_name as separate model fields (snapshot v14+);
# these tests pin that the emitted ALTER FUNCTION targets the right
# object and that the fixer abstains when the fields are absent.


def test_sec015_fix_targets_correct_object_when_schema_name_has_dot() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "a.b.f",
                signature="integer",
                schema_name="a.b",
                function_name="f",
            ),
        ),
    )
    [fix] = SEC015Fixer().fix(schema, {})
    assert fix.sql == (
        'ALTER FUNCTION "a.b".f(integer) '
        "SET search_path = pg_catalog, pg_temp;"
    )
    # The old buggy split would have produced this wrong target.
    assert 'a."b.f"' not in fix.sql


def test_sec015_fix_targets_correct_object_when_function_name_has_dot() -> None:
    # rpartition-killer: function `a.b` in schema `s` (qname `s.a.b`).
    # Only the separate fields get this right.
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "s.a.b",
                signature="integer",
                schema_name="s",
                function_name="a.b",
            ),
        ),
    )
    [fix] = SEC015Fixer().fix(schema, {})
    assert fix.sql == (
        'ALTER FUNCTION s."a.b"(integer) '
        "SET search_path = pg_catalog, pg_temp;"
    )


def test_sec015_fix_abstains_when_schema_function_fields_missing() -> None:
    # Pre-v14 snapshot: no schema_name/function_name. Abstain rather
    # than split the ambiguous qualified_name into a wrong target.
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "a.b.f",
                signature="integer",
                schema_name="",
                function_name="",
            ),
        ),
    )
    assert SEC015Fixer().fix(schema, {}) == []


def test_sec017_fix_targets_correct_object_when_schema_name_has_dot() -> None:
    schema = Schema(
        leakproof_functions=(
            _leakproof(
                "a.b.f",
                "integer",
                schema_name="a.b",
                function_name="f",
            ),
        ),
    )
    [fix] = SEC017Fixer().fix(schema, {})
    assert fix.sql == 'ALTER FUNCTION "a.b".f(integer) NOT LEAKPROOF;'
    assert 'a."b.f"' not in fix.sql


def test_sec017_fix_targets_correct_object_when_function_name_has_dot() -> None:
    schema = Schema(
        leakproof_functions=(
            _leakproof(
                "s.a.b",
                "integer",
                schema_name="s",
                function_name="a.b",
            ),
        ),
    )
    [fix] = SEC017Fixer().fix(schema, {})
    assert fix.sql == 'ALTER FUNCTION s."a.b"(integer) NOT LEAKPROOF;'


def test_sec017_fix_abstains_when_schema_function_fields_missing() -> None:
    schema = Schema(
        leakproof_functions=(
            _leakproof(
                "a.b.f",
                "integer",
                schema_name="",
                function_name="",
            ),
        ),
    )
    assert SEC017Fixer().fix(schema, {}) == []
