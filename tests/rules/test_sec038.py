"""Unit tests for SEC038 — semantic anonymous-read leak (Z3-backed 3VL).

z3-solver is a core dependency as of 0.16.0, so SEC038 runs on a plain
install; these tests still `importorskip` on z3 as a defensive guard. The
soundness contract is that the rule NO-OPs if z3 is somehow absent — pinned
by `test_sec038_noop_when_z3_unavailable`, which does NOT skip).

The fire / no-fire cases are re-derived from the soundness oracle: a
predicate fires iff, under an anonymous session (every auth function NULL),
its USING is VALID — exactly TRUE for every row (Kleene 3VL). The negatives
are the false-positive regression gate: a scoped tenant/owner predicate
becomes Kleene U (not valid) under anon; a narrow public carve-out is TRUE
only for some rows (not valid); an untranslatable shape aborts to no-fire.
"""
from __future__ import annotations

import pytest

pytest.importorskip("z3")

from pgrls.ast_utils import parse_expr  # noqa: E402
from pgrls.model import Policy, Schema, Table  # noqa: E402
from pgrls.rules.sec038 import SEC038  # noqa: E402

# A non-existent owner uuid used in narrow / scoped near-misses.
_OWNER_LIT = "owner_id = '00000000-0000-0000-0000-000000000001'::uuid"


def _policy_with_using(
    using: str, *, command: str = "SELECT", permissive: bool = True
) -> Policy:
    return Policy(
        name="p",
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=("authenticated",),
        using_sql=using,
        with_check_sql=None,
        using_ast=parse_expr(using),
    )


def _wrap(policy: Policy) -> Schema:
    return Schema(
        tables=(
            Table(
                schema="public",
                name="t",
                rls_enabled=True,
                force_rls=True,
                policies=(policy,),
            ),
        )
    )


# ---------------------------------------------------------------------------
# FIRE cases — anon-valid USING (provably TRUE for every row under anon).
# These are exactly the inverted-auth variants SEC004's syntactic match
# misses (plus the canonical Lovable shape).
# ---------------------------------------------------------------------------


def test_sec038_fires_on_not_wrapped_is_not_null() -> None:
    # P1: NOT (auth.uid() IS NOT NULL) is semantically `auth.uid() IS NULL`.
    # SEC004 misses this (no literal `auth() IS NULL` disjunct).
    schema = _wrap(
        _policy_with_using(
            f"NOT ((SELECT auth.uid()) IS NOT NULL) OR {_OWNER_LIT}"
        )
    )
    violations = SEC038().check(schema, {})
    assert len(violations) == 1
    assert violations[0].rule_id == "SEC038"
    assert violations[0].severity == "error"
    assert violations[0].location == "public.t.p"


def test_sec038_fires_on_is_null_or_true() -> None:
    # P2: the bare `auth.uid() IS NULL OR true` tautology.
    schema = _wrap(_policy_with_using("(SELECT auth.uid()) IS NULL OR true"))
    assert len(SEC038().check(schema, {})) == 1


def test_sec038_fires_on_bool_cast_is_null() -> None:
    # P4: `(auth.uid() IS NULL)::bool` — the cast-wrapped variant SEC004's
    # literal matcher misses. The TypeCast feeds a _TV inner (amendment #4).
    schema = _wrap(
        _policy_with_using(
            f"((SELECT auth.uid()) IS NULL)::bool OR {_OWNER_LIT}"
        )
    )
    assert len(SEC038().check(schema, {})) == 1


def test_sec038_fires_on_unknown_type_cast_of_auth_call_is_null() -> None:
    # R11 #3: the catastrophic shape on real Supabase schemas —
    # `auth.uid()::jsonb IS NULL OR <owner>`. The cast of an anon-null
    # auth call to an unknown target type preserves the null flag, so the
    # inverted disjunct is valid under anon and SEC038 fires.
    schema = _wrap(
        _policy_with_using(
            f"((SELECT auth.uid())::jsonb) IS NULL OR {_OWNER_LIT}"
        )
    )
    assert len(SEC038().check(schema, {})) == 1


def test_sec038_fires_on_multiple_auth_is_null_disjuncts() -> None:
    # P6: role IS NULL OR uid IS NULL OR <scoped> — anon makes the first
    # two disjuncts TRUE, so the whole OR is TRUE for every row.
    schema = _wrap(
        _policy_with_using(
            "(SELECT auth.role()) IS NULL "
            "OR (SELECT auth.uid()) IS NULL "
            "OR tenant_id = (SELECT current_setting('app.t', true)::uuid)"
        )
    )
    assert len(SEC038().check(schema, {})) == 1


def test_sec038_fires_on_corpus_inverted_auth_shape() -> None:
    # P3 / sec004-inverted-auth: `(SELECT current_setting(...))::uuid IS NULL
    # OR owner = auth.uid()`. Under anon the current_setting is NULL, so the
    # IS NULL disjunct is TRUE for all rows.
    schema = _wrap(
        _policy_with_using(
            "(SELECT current_setting('app.user_id', true))::uuid IS NULL "
            "OR owner_id = (SELECT auth.uid())"
        )
    )
    assert len(SEC038().check(schema, {})) == 1


# ---------------------------------------------------------------------------
# NO-FIRE cases — scoped / narrow / safe-scary / untranslatable. These are
# the false-positive regression gate.
# ---------------------------------------------------------------------------


def test_sec038_clean_on_owner_predicate() -> None:
    # N2: owner = auth.uid() → under anon owner = NULL → Kleene U → not valid.
    schema = _wrap(_policy_with_using("owner_id = (SELECT auth.uid())"))
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_tenant_predicate() -> None:
    # N1: tenant = current_setting(...) → U under anon → not valid.
    schema = _wrap(
        _policy_with_using(
            "tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_is_null_under_and() -> None:
    # N4 (make-or-break): `owner = uid OR (owner = <pub> AND uid IS NULL)`.
    # The IS NULL is gated by an AND, so anon does NOT make it true for all
    # rows: `U OR (U AND T) = U`. Must stay clean.
    schema = _wrap(
        _policy_with_using(
            "owner_id = (SELECT auth.uid()) OR "
            "(owner_id = (SELECT current_setting('app.public_owner', true)::uuid) "
            "AND (SELECT auth.uid()) IS NULL)"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_is_not_null_guard() -> None:
    # N6: the correct guard `auth.uid() IS NOT NULL AND owner = uid`. Under
    # anon: `F AND U = F` → not valid → clean.
    schema = _wrap(
        _policy_with_using(
            "(SELECT auth.uid()) IS NOT NULL AND owner_id = (SELECT auth.uid())"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_coalesce_sentinel() -> None:
    # N3: coalesce(auth.uid(), <sentinel>) = owner → under anon the coalesce
    # is the sentinel uuid, so it's TRUE only for rows owned by the sentinel
    # (narrow), not all rows → not valid → clean.
    schema = _wrap(
        _policy_with_using(
            "coalesce((SELECT auth.uid()), "
            "'00000000-0000-0000-0000-000000000000'::uuid) = owner_id"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_jwt_claim_tenant() -> None:
    # N8: jwt-claim tenancy. auth.jwt() is anon-NULL; the `->>` operator is
    # untranslatable → soundness abort → clean (either way, no fire).
    schema = _wrap(
        _policy_with_using(
            "tenant_id = (SELECT (auth.jwt() ->> 'tenant_id')::uuid)"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_narrow_public_carveout() -> None:
    # S1: intentional public data — `tenant = <const> OR owner = uid`. The
    # constant carve-out is TRUE only for the public tenant's rows, not all
    # rows → not valid → clean. THE intentional-public-data FP guard.
    schema = _wrap(
        _policy_with_using(
            "tenant_id = '00000000-0000-0000-0000-000000000000'::uuid "
            "OR owner_id = (SELECT auth.uid())"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_shared_bool_carveout() -> None:
    # S2: `shared = true OR owner = uid`. Boolean comparison operand
    # (amendment #3). TRUE only for shared rows → not valid → clean.
    schema = _wrap(
        _policy_with_using("shared = true OR owner_id = (SELECT auth.uid())")
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_no_false_positive_on_user_function_named_like_builtin() -> None:
    # A user-defined `myschema.current_setting(...)` is NOT the
    # pg_catalog builtin and must not be forced to NULL under anon —
    # otherwise `myschema.current_setting('x') IS NULL OR <scoped>`
    # would be proved valid and SEC038 would false-fire. Regression
    # for the bare-name builtin collision (a schema-qualified call is
    # a different function with unknown anonymous behaviour).
    safe = _wrap(
        _policy_with_using(
            "myschema.current_setting('app.tenant') IS NULL OR " + _OWNER_LIT
        )
    )
    assert SEC038().check(safe, {}) == []


def test_sec038_fires_on_unqualified_and_pg_catalog_builtin() -> None:
    # Control for the above: the unqualified builtin (and its explicit
    # pg_catalog form) IS forced to NULL under anon, so the same
    # inverted-auth disjunct is a real anonymous-read leak.
    for fn in ("current_setting", "pg_catalog.current_setting"):
        leak = _wrap(
            _policy_with_using(f"{fn}('app.tenant') IS NULL OR " + _OWNER_LIT)
        )
        assert len(SEC038().check(leak, {})) == 1


def test_sec038_clean_on_coerced_guc_count() -> None:
    # P5-excluded: `0 = current_setting('app.uid_count')::int OR owner = uid`.
    # Under anon the coerced GUC is NULL → `0 = NULL` is U, so `U OR U = U`
    # → not valid → clean.
    schema = _wrap(
        _policy_with_using(
            "0 = (SELECT current_setting('app.uid_count', true))::int "
            "OR owner_id = (SELECT auth.uid())"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_session_state_equality() -> None:
    # `current_setting('app.enabled') = 'true'` → under anon `NULL = 'true'`
    # is U → not valid → clean.
    schema = _wrap(
        _policy_with_using(
            "(SELECT current_setting('app.enabled', true)) = 'true'"
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_clean_on_untranslatable_exists_subquery() -> None:
    # An EXISTS subquery is untranslatable (not unwrapped) → soundness abort
    # → clean, even though it textually contains an `auth.uid() IS NULL`.
    schema = _wrap(
        _policy_with_using(
            "owner_id = (SELECT auth.uid()) OR EXISTS "
            "(SELECT 1 FROM public.t s2 WHERE s2.id = id "
            "AND (SELECT auth.uid()) IS NULL)"
        )
    )
    assert SEC038().check(schema, {}) == []


# ---------------------------------------------------------------------------
# Behavioral / gating cases.
# ---------------------------------------------------------------------------


def test_sec038_skips_policy_without_using_ast() -> None:
    schema = _wrap(
        Policy(
            name="p",
            command="SELECT",
            permissive=True,
            roles=("authenticated",),
            using_sql=None,
            with_check_sql=None,
            using_ast=None,
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_skips_restrictive_policy() -> None:
    # A RESTRICTIVE policy can only narrow access; it can't grant anon read,
    # even with an anon-valid USING.
    schema = _wrap(
        _policy_with_using(
            "(SELECT auth.uid()) IS NULL OR true", permissive=False
        )
    )
    assert SEC038().check(schema, {}) == []


def test_sec038_skips_non_read_commands() -> None:
    # INSERT / UPDATE / DELETE are not read-capable. (UPDATE/DELETE USING
    # gates the rows touched, not rows exposed on SELECT — out of scope.)
    for command in ("INSERT", "UPDATE", "DELETE"):
        schema = _wrap(
            _policy_with_using(
                "(SELECT auth.uid()) IS NULL OR true", command=command
            )
        )
        assert SEC038().check(schema, {}) == [], command


def test_sec038_emits_only_one_violation_per_policy() -> None:
    # Two independent leak shapes in one policy still yield exactly one
    # finding (the rule reports per-policy).
    schema = _wrap(
        _policy_with_using(
            "(SELECT auth.role()) IS NULL OR (SELECT auth.uid()) IS NULL OR true"
        )
    )
    assert len(SEC038().check(schema, {})) == 1


def test_sec038_auth_functions_config_overrides_default() -> None:
    # Removing auth.uid from the auth set means its IS NULL leaf is no
    # longer anon-NULL, so the predicate is no longer provably valid.
    schema = _wrap(
        _policy_with_using(f"(SELECT auth.uid()) IS NULL OR {_OWNER_LIT}")
    )
    assert SEC038().check(schema, {"auth_functions": ["my.custom_auth"]}) == []


def test_sec038_auth_functions_config_can_add_custom() -> None:
    # A custom auth function added to the set is then treated as anon-NULL.
    schema = _wrap(
        _policy_with_using(f"my.tenant() IS NULL OR {_OWNER_LIT}")
    )
    # Default set doesn't include my.tenant → clean.
    assert SEC038().check(schema, {}) == []
    # Add it → fires.
    assert (
        len(SEC038().check(schema, {"auth_functions": ["my.tenant"]})) == 1
    )


def test_sec038_bad_auth_functions_type_raises_clearly() -> None:
    schema = _wrap(_policy_with_using("(SELECT auth.uid()) IS NULL OR a = 1"))
    with pytest.raises(TypeError, match=r"\[lint\.rules\.SEC038\]"):
        SEC038().check(
            schema, {"auth_functions": "auth.uid"}  # type: ignore[dict-item]
        )


def test_sec038_bad_auth_functions_item_type_raises_clearly() -> None:
    schema = _wrap(_policy_with_using("(SELECT auth.uid()) IS NULL OR a = 1"))
    with pytest.raises(TypeError, match=r"\[lint\.rules\.SEC038\]"):
        SEC038().check(
            schema,
            {"auth_functions": ["auth.uid", 42]},  # type: ignore[list-item]
        )


def test_sec038_allowlist_exempts_leaking_policy() -> None:
    schema = _wrap(_policy_with_using("(SELECT auth.uid()) IS NULL OR true"))
    assert (
        SEC038().check(schema, {"allowlist": ["public.t.p"]}) == []
    )


def test_sec038_message_describes_unconditional_anon_leak() -> None:
    schema = _wrap(_policy_with_using("(SELECT auth.uid()) IS NULL OR true"))
    violations = SEC038().check(schema, {})
    assert len(violations) == 1
    msg = violations[0].message
    assert "anonymous" in msg.lower()
    assert "every row" in msg.lower()
    # Honest artifact: it reports an unconditional leak (all rows), not a
    # specific row (amendment #6).
    assert "unconditionally" in msg.lower()
    # Cross-references SEC004 so the reader sees the relationship.
    assert "SEC004" in msg


def test_sec038_message_caveats_one_arg_current_setting() -> None:
    # R9 #10: the one-arg `current_setting('app.x')` RAISES when the GUC
    # is unset (it doesn't return NULL), so for an unconfigured anon
    # session the policy may ERROR rather than read every row. SEC038
    # still fires (the inverted-auth shape is unsound), but the message
    # must acknowledge the error-vs-leak nuance accurately.
    schema = _wrap(
        _policy_with_using(
            f"current_setting('app.x') IS NULL OR {_OWNER_LIT}"
        )
    )
    [v] = SEC038().check(schema, {})
    msg = v.message
    assert "one-argument current_setting" in msg
    assert "unrecognized configuration parameter" in msg
    # Still firing and still pointing at the real fix.
    assert "SEC004" in msg


def test_sec038_message_omits_caveat_for_two_arg_current_setting() -> None:
    # The two-arg `current_setting(name, true)` returns NULL when unset
    # (genuinely leaks, no error), so the one-arg caveat must NOT appear.
    schema = _wrap(
        _policy_with_using(
            f"(SELECT current_setting('app.x', true)) IS NULL OR {_OWNER_LIT}"
        )
    )
    [v] = SEC038().check(schema, {})
    assert "one-argument current_setting" not in v.message


def test_sec038_noop_when_z3_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    # HARD-CONSTRAINT regression guard: SEC038 must NO-OP when z3 is absent.
    # This test does NOT skip — it runs even where z3 IS installed, by
    # monkeypatching the availability flag.
    import pgrls.diff._z3_compare as z3c

    monkeypatch.setattr(z3c, "Z3_AVAILABLE", False)
    schema = _wrap(_policy_with_using("(SELECT auth.uid()) IS NULL OR true"))
    assert SEC038().check(schema, {}) == []


def test_sec038_arithmetic_operand_3vl_branch() -> None:
    # Coverage (round-7): exercise the Kleene arithmetic-operand branch of
    # the 3VL encoder (null-flag propagated as Or(left, right)). FIRE — anon
    # makes the IS NULL disjunct TRUE and the surviving disjunct does
    # arithmetic on a column operand:
    fire = _wrap(
        _policy_with_using("(SELECT auth.uid()) IS NULL OR amount + 1 > 0")
    )
    assert len(SEC038().check(fire, {})) == 1
    # NO-FIRE — arithmetic compared to a per-request auth value: under anon
    # the value is NULL, so the comparison is Kleene-unknown, never provably
    # TRUE for all rows.
    scoped = _wrap(
        _policy_with_using(
            "amount + 1 = (SELECT current_setting('app.x', true))::int"
        )
    )
    assert SEC038().check(scoped, {}) == []


def test_sec038_column_vs_column_operand_3vl_branch() -> None:
    # Coverage (round-7): exercise the col-op-col operand branch (both
    # operands default to StringSort with free null-flags). FIRE via the
    # anon IS NULL disjunct:
    fire = _wrap(
        _policy_with_using("a = b OR (SELECT auth.uid()) IS NULL")
    )
    assert len(SEC038().check(fire, {})) == 1
    # NO-FIRE — a plain two-column comparison is not provably TRUE for every
    # row, so anon cannot read everything.
    assert SEC038().check(_wrap(_policy_with_using("a = b")), {}) == []
