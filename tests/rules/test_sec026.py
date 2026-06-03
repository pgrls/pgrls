"""Unit tests for SEC026 — policy predicate uses pattern matching
against an auth-context value.

SEC026 (warning) fires when a policy's USING or WITH CHECK
expression combines a pattern operator (LIKE / ILIKE / SIMILAR TO /
POSIX regex `~` / `~*` / `!~` / `!~*`) with an auth-context
function call (`current_setting`, `auth.uid`, `current_user`, ...)
on either operand. Pattern wildcards in an attacker-controllable
value make the isolation predicate degenerate.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec026 import SEC026


def _policy(
    *,
    name: str = "p",
    using: str | None = None,
    with_check: str | None = None,
) -> Policy:
    return Policy(
        name=name,
        command="ALL",
        permissive=True,
        roles=("PUBLIC",),
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _table(
    *policies: Policy,
    schema: str = "public",
    name: str = "documents",
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=True,
        force_rls=True,
        policies=policies,
        columns=("id", "tenant_id", "user_email", "pattern"),
    )


# --- firing --------------------------------------------------------------


def test_sec026_fires_on_like_against_current_setting() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email LIKE current_setting('app.email')"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.rule_id == "SEC026"
    assert v.severity == "warning"
    assert v.location == "public.documents.p"
    assert "pattern operator" in v.message
    assert "allowlist" in v.message
    # Positive operator → the exposure framing.
    assert "exposing every row" in v.message
    assert "DENY every row" not in v.message


def test_sec026_negated_operator_message_says_deny_not_expose() -> None:
    # R12 #3: `NOT LIKE` / `!~` still fire (a wildcard GUC corrupts a
    # deny-list predicate), but a wildcard there makes the predicate
    # FALSE for every row — it DENIES all access, the opposite of the
    # positive operators' exposure. The message must say so, not claim
    # "exposing every row".
    for using in (
        "user_email NOT LIKE current_setting('app.blocked')",
        "user_email !~ current_setting('app.blocked')",
    ):
        schema = Schema(tables=(_table(_policy(using=using)),))
        [v] = SEC026().check(schema, options={})
        assert "DENY every row" in v.message, using
        assert "silently hiding all data" in v.message, using
        assert "exposing every row" not in v.message, using


def test_sec026_fires_on_ilike_against_current_setting() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email ILIKE current_setting('app.email')"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_similar_to_against_current_setting() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "user_email SIMILAR TO current_setting('app.email')"
                    )
                ),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_posix_regex_match_against_current_setting() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email ~ current_setting('app.pattern')"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_case_insensitive_regex_against_current_setting() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="user_email ~* current_setting('app.pattern')"
                ),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_negated_regex_against_current_setting() -> None:
    # `!~` (negated regex) is still pattern matching — a malicious
    # GUC value can flip what "no match" means.
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email !~ current_setting('app.deny')"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_when_auth_call_is_on_left_side() -> None:
    # Symmetric vulnerability — the auth value as the pattern
    # source is equally dangerous.
    schema = Schema(
        tables=(
            _table(
                _policy(using="current_setting('app.email') LIKE user_email"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_current_user_pattern_comparison() -> None:
    # The role-identity SQLValueFunctions count as auth context
    # too — a `current_user ILIKE column` predicate has the same
    # shape-dependent isolation flaw.
    schema = Schema(
        tables=(
            _table(
                _policy(using="current_user ILIKE user_email"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_auth_uid_pattern_comparison() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email LIKE auth.uid()"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_with_check_side_too() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="tenant_id = 1",
                    with_check=(
                        "user_email LIKE current_setting('app.email')"
                    ),
                )
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_deparser_emitted_tilde_tilde_operator() -> None:
    # Postgres's `pg_get_expr` deparses literal `LIKE` to `~~`, and
    # pglast parses `~~` as `AEXPR_OP` (not `AEXPR_LIKE`). SEC026
    # matches by operator name rather than by kind so the deparsed
    # form trips the rule the same way as the literal-`LIKE`
    # source — pins the round-trip behaviour the combined-fixture
    # test depends on.
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email ~~ current_setting('app.email')"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_not_like_operator() -> None:
    # NOT LIKE deparsed as `!~~` — also pattern matching, also
    # vulnerable to wildcard-shape auth values.
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email NOT LIKE current_setting('app.email')"),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_when_auth_call_is_wrapped_in_sublink() -> None:
    # `col LIKE (SELECT current_setting(...))` evaluates the scalar
    # SubLink and feeds the value to LIKE — semantically identical
    # to the un-wrapped form. The wrap is the PERF001 remediation
    # shape; it does not address the SEC026 vulnerability.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "user_email LIKE "
                        "(SELECT current_setting('app.email', true))"
                    )
                ),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.location == "public.documents.p"


def test_sec026_fires_on_pattern_nested_in_subselect() -> None:
    # A pattern operator paired with an auth context INSIDE a
    # sub-select is the subselect's predicate, but SEC026 still
    # walks into the SubLink and catches it on the nested A_Expr.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "tenant_id IN ("
                        "SELECT tenant_id FROM public.members "
                        "WHERE email LIKE current_setting('app.email')"
                        ")"
                    )
                )
            ),
        )
    )
    fires = SEC026().check(schema, options={})
    assert len(fires) == 1
    assert fires[0].location == "public.documents.p"


def test_sec026_fires_once_per_policy_even_when_both_clauses_match() -> None:
    # A policy that has the pattern-vs-auth shape in BOTH its
    # USING and its WITH CHECK should produce one Violation, not
    # two — like SEC018 / SEC019 fire on the policy, not per
    # clause.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="user_email LIKE current_setting('app.email')",
                    with_check=(
                        "user_email ILIKE current_setting('app.email')"
                    ),
                )
            ),
        )
    )
    findings = SEC026().check(schema, options={})
    assert len(findings) == 1


# --- silent --------------------------------------------------------------


def test_sec026_silent_on_equality_against_current_setting() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="user_email = current_setting('app.email')"
                ),
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_silent_on_lower_lower_equality() -> None:
    # The standard remedy — `lower(col) = lower(current_setting(...))`
    # — must not fire. SEC026 only fires on pattern operators.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "lower(user_email) = "
                        "lower(current_setting('app.email'))"
                    )
                ),
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_silent_on_hardcoded_like_pattern() -> None:
    # Pattern operator without an auth context — out of scope.
    # `email LIKE '%@example.com'` isolates by a hard-coded pattern,
    # not by an attacker-controllable value.
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email LIKE '%@example.com'"),
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


@pytest.mark.parametrize(
    "using",
    [
        # Auth value is the SUBJECT, pattern is a hard-coded literal:
        # LIKE/ILIKE family (deparsed and keyword forms).
        "current_user ~~ 'admin%'",
        "current_user LIKE 'admin%'",
        "current_setting('app.tag', true) ~~* 'beta_%'",
        # POSIX regex on the subject side vs a literal pattern.
        "current_setting('app.role', true) ~ '^tenant_'",
        # The literal pattern may carry an explicit cast …
        "current_user ~~ 'admin%'::text",
        # … or be wrapped in the FROM-less scalar sub-select form.
        "current_user ~~ (SELECT 'admin%')",
        # R17 #1: SIMILAR TO must be treated identically to LIKE/`~`.
        # Postgres rewrites `X SIMILAR TO 'lit'` to
        # `X ~ pg_catalog.similar_to_escape('lit')`, so the pattern is a
        # FuncCall — the literal-pattern guard must see through it.
        "current_user SIMILAR TO 'admin%'",
        "current_setting('app.role', true) SIMILAR TO 'admin%'",
        "current_user NOT SIMILAR TO 'admin%'",
        # …including the explicit-ESCAPE 2-arg similar_to_escape form.
        "current_user SIMILAR TO 'admin!%' ESCAPE '!'",
    ],
)
def test_sec026_silent_on_auth_subject_against_literal_pattern(
    using: str,
) -> None:
    # R16 #4: when the auth value is the SUBJECT and the pattern is an
    # author-controlled string literal, every `%`/`_`/`.*` lives in the
    # policy text — the attacker cannot inject a wildcard into the role
    # name or GUC being matched. This is the LIKE/regex analogue of the
    # `current_user = 'postgres'` admin-escape SEC018 deliberately
    # allows; the warning-severity rule must NOT fire.
    schema = Schema(tables=(_table(_policy(using=using)),))
    assert SEC026().check(schema, options={}) == [], using


def test_sec026_still_fires_when_auth_subject_pattern_is_data_driven() -> None:
    # The skip is narrow: only a LITERAL pattern is safe. When the pattern
    # operand is itself a column/expression (which could carry an injected
    # wildcard), the auth-subject form still fires — matching the existing
    # `current_user ILIKE user_email` coverage.
    schema = Schema(
        tables=(_table(_policy(using="current_user ~~ user_email")),)
    )
    assert len(SEC026().check(schema, options={})) == 1


def test_sec026_still_fires_on_similar_to_against_auth_pattern() -> None:
    # The SIMILAR TO literal-pattern allowance must NOT leak into the
    # genuine hazard: when the auth value is the PATTERN (a GUC that could
    # be `%`/`.*`) and the subject is a data column, SEC026 still fires —
    # `similar_to_escape(current_setting(...))` is not a literal pattern.
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email SIMILAR TO current_setting('app.p')")
            ),
        )
    )
    assert len(SEC026().check(schema, options={})) == 1


def test_sec026_silent_on_in_membership_check() -> None:
    # `column IN (...)` is `AEXPR_OP` with operator name `=`
    # against an array; not a pattern operator. No fire.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "user_email IN (current_setting('app.email'))"
                    )
                ),
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_silent_when_policy_has_no_predicates() -> None:
    schema = Schema(
        tables=(_table(_policy(using=None, with_check=None)),)
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_silent_on_ltree_match_against_auth_value() -> None:
    # Regression (#15): `~` is also the ltree/lquery match operator.
    # `path ~ (<auth>)::lquery` is a typed ltree match, NOT a text
    # regex pattern — must not fire.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="(path ~ (current_setting('app.q', true))::lquery)"
                )
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_silent_on_ltree_match_against_subselect_wrapped_auth() -> None:
    # R15 #4: `~` is the ltree/lquery match operator, and the auth value
    # may use the FROM-less scalar sub-select pgrls's PERF001 recommends:
    # `path ~ (SELECT current_setting('app.q')::lquery)`. The non-text
    # guard previously inspected the SubLink (whose top node is not the
    # `::lquery` cast), returned False, and SEC026 false-fired on the very
    # rewrite pgrls advocates. The guard now unwraps the sub-select
    # projection (the same wrapper auth-call detection looks through), so
    # this typed ltree match stays silent — matching the direct form.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="(path ~ (SELECT current_setting('app.q')::lquery))"
                )
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []
    # No false negative: a genuine TEXT regex via the same sub-select wrap
    # still fires (the operand is text-typed, so the guard does not skip).
    text_schema = Schema(
        tables=(
            _table(
                _policy(
                    using="(user_email ~ (SELECT current_setting('app.re')))"
                )
            ),
        )
    )
    assert len(SEC026().check(text_schema, options={})) == 1


def test_sec026_silent_on_geometric_contains_against_auth_value() -> None:
    # Regression (#15): `~` is also the geometric "contains" operator.
    # An operand built via a point() constructor from an auth GUC is a
    # geometric value, not a text regex pattern — must not fire.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "(region ~ point("
                        "current_setting('app.x', true)::float8, 0))"
                    )
                )
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_silent_on_column_side_lquery_cast_against_auth_value() -> None:
    # Regression (R9 #9): `~` is the ltree/lquery match operator when
    # EITHER operand is non-text-typed. The non-text cast may sit on the
    # COLUMN side — `(path::lquery) ~ current_setting(...)` — not just on
    # the auth-value side. The earlier guard only inspected the auth-value
    # operand, so a column-side cast slipped through as a false positive.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "(path::lquery) ~ current_setting('app.x', true)"
                    )
                )
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_still_fires_on_plain_text_regex_against_auth_value() -> None:
    # Guard against over-suppression from the both-operands check: a
    # genuine text `~` regex against an auth value must still fire.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using="user_email ~ current_setting('app.email', true)"
                )
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.rule_id == "SEC026"


# --- allowlist / configuration ------------------------------------------


def test_sec026_respects_allowlist() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email LIKE current_setting('app.email')"),
            ),
        )
    )
    assert (
        SEC026().check(
            schema, options={"allowlist": ["public.documents.p"]}
        )
        == []
    )


def test_sec026_custom_auth_functions_replaces_default() -> None:
    # A user with a custom helper (`my.current_user_id`) configures
    # the auth-function set — the new set REPLACES the default.
    # A policy LIKE-comparing against the new function fires; a
    # policy LIKE-comparing against current_setting (no longer in
    # the set) does NOT fire.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    name="bad",
                    using="user_email LIKE my.current_user_id()",
                ),
                _policy(
                    name="ok",
                    using="user_email LIKE current_setting('app.email')",
                ),
            ),
        )
    )
    findings = SEC026().check(
        schema,
        options={"auth_functions": ["my.current_user_id"]},
    )
    assert [v.location for v in findings] == ["public.documents.bad"]


def test_sec026_raises_on_malformed_auth_functions() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email LIKE current_setting('app.email')"),
            ),
        )
    )
    with pytest.raises(TypeError, match="auth_functions"):
        SEC026().check(
            schema, options={"auth_functions": "current_setting"}
        )
    with pytest.raises(TypeError, match="auth_functions"):
        SEC026().check(
            schema, options={"auth_functions": [1, "current_setting"]}
        )


def test_sec026_raises_on_malformed_allowlist() -> None:
    schema = Schema(
        tables=(
            _table(
                _policy(using="user_email LIKE current_setting('app.email')"),
            ),
        )
    )
    with pytest.raises(TypeError, match="allowlist"):
        SEC026().check(schema, options={"allowlist": "public.documents.p"})
    with pytest.raises(TypeError, match="allowlist"):
        SEC026().check(
            schema, options={"allowlist": [" public.documents.p "]}
        )


def test_sec026_silent_on_auth_call_in_from_bearing_subselect_filter() -> None:
    # Regression (round-5): the auth call (current_setting) is a ROW FILTER
    # inside a FROM-bearing lookup sub-select; the LIKE pattern is the
    # `pattern` column, not the auth value. SEC026 must NOT fire — the auth
    # value's shape does not drive the predicate here.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "user_email LIKE (SELECT pattern FROM patterns "
                        "WHERE tenant = current_setting('app.tenant'))"
                    ),
                ),
            ),
        )
    )
    assert SEC026().check(schema, options={}) == []


def test_sec026_still_fires_on_fromless_wrapped_auth_value() -> None:
    # A FROM-less scalar sub-select (the PERF001 wrap idiom) IS the pattern
    # operand, so the auth value's shape DOES drive the predicate — fires.
    schema = Schema(
        tables=(
            _table(
                _policy(
                    using=(
                        "user_email LIKE "
                        "(SELECT current_setting('app.email'))"
                    ),
                ),
            ),
        )
    )
    [v] = SEC026().check(schema, options={})
    assert v.rule_id == "SEC026"
