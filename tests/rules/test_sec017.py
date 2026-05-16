"""Unit tests for SEC017 — LEAKPROOF function audit.

SEC017's scope is *every* function carrying the LEAKPROOF attribute
in the introspected schemas. A LEAKPROOF function is evaluated by the
planner below a security barrier (the RLS qual, a security_barrier
view); if it is not genuinely side-channel-free it leaks
RLS-protected rows. The rule is an "audit every LEAKPROOF function"
prompt — pgrls cannot prove a function is or is not leak-free.
"""
from __future__ import annotations

import pytest

from pgrls.model import LeakproofFunction, Schema
from pgrls.rules.sec017 import SEC017


def _leakproof(qname: str) -> LeakproofFunction:
    return LeakproofFunction(qualified_name=qname)


def test_sec017_fires_on_every_leakproof_function() -> None:
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.fast_eq"),
            _leakproof("audit.redact"),
        ),
    )
    violations = SEC017().check(schema, options={})
    # Rule preserves the input tuple's iteration order. (Real runs
    # see introspection-sorted-by-qname tuples; this fixture
    # deliberately uses construction order to pin "rule doesn't
    # re-sort".)
    assert [v.location for v in violations] == [
        "public.fast_eq",
        "audit.redact",
    ]
    for v in violations:
        assert v.rule_id == "SEC017"
        assert v.severity == "warning"
        assert "LEAKPROOF" in v.message
        # The fix and the security-barrier mechanism are both named.
        assert "NOT LEAKPROOF" in v.message
        assert "security barrier" in v.message


def test_sec017_silent_when_no_leakproof_functions() -> None:
    # The common case in a fresh project — marking a function
    # LEAKPROOF requires superuser and is rare, so most schemas have
    # nothing to audit.
    schema = Schema(leakproof_functions=())
    assert SEC017().check(schema, options={}) == []


def test_sec017_silent_when_schema_has_no_leakproof_field_at_all() -> None:
    # Defensive: a Schema constructed without the leakproof_functions
    # kwarg defaults to () via the dataclass factory; SEC017 must
    # handle that empty-tuple case without surprising errors.
    schema = Schema()
    assert SEC017().check(schema, options={}) == []


def test_sec017_allowlist_skips_qualified_function() -> None:
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.fast_eq"),
            _leakproof("audit.redact"),
        ),
    )
    violations = SEC017().check(
        schema, options={"allowlist": ["public.fast_eq"]}
    )
    assert [v.location for v in violations] == ["audit.redact"]


def test_sec017_allowlist_silences_all_leakproof() -> None:
    # Operators who've audited every LEAKPROOF function should be
    # able to silence the rule entirely via the allowlist (preferred
    # over `disable = ["SEC017"]` because the allowlist documents
    # which functions have been reviewed).
    schema = Schema(
        leakproof_functions=(
            _leakproof("public.a"),
            _leakproof("public.b"),
        ),
    )
    violations = SEC017().check(
        schema, options={"allowlist": ["public.a", "public.b"]}
    )
    assert violations == []


def test_sec017_allowlist_rejects_bare_function_name() -> None:
    # `fast_eq` (no schema) — could shadow same-named functions in
    # multiple schemas. Reject loudly per the _allowlist module's
    # shape-validation policy.
    with pytest.raises(TypeError, match="schema.function"):
        SEC017().check(
            Schema(leakproof_functions=(_leakproof("public.fast_eq"),)),
            options={"allowlist": ["fast_eq"]},
        )


def test_sec017_allowlist_rejects_three_part_id() -> None:
    with pytest.raises(TypeError, match="schema.function"):
        SEC017().check(
            Schema(leakproof_functions=(_leakproof("public.fast_eq"),)),
            options={"allowlist": ["public.fast_eq.int"]},
        )


def test_sec017_allowlist_rejects_non_string_entries() -> None:
    with pytest.raises(TypeError, match="list of strings"):
        SEC017().check(
            Schema(leakproof_functions=(_leakproof("public.fast_eq"),)),
            options={"allowlist": ["public.fast_eq", 42]},
        )


def test_sec017_allowlist_rejects_whitespace_padded_entry() -> None:
    with pytest.raises(TypeError, match="public.fast_eq"):
        SEC017().check(
            Schema(leakproof_functions=(_leakproof("public.fast_eq"),)),
            options={"allowlist": [" public.fast_eq "]},
        )


def test_sec017_message_includes_function_qname_in_allowlist_hint() -> None:
    # The remediation hint must name the function so a
    # `[lint.rules.SEC017]` allowlist entry copy-pastes cleanly.
    schema = Schema(
        leakproof_functions=(_leakproof("audit.redact"),),
    )
    [v] = SEC017().check(schema, options={})
    assert "'audit.redact'" in v.message
    assert "[lint.rules.SEC017]" in v.message
    # The fix names the function in the ALTER FUNCTION statement.
    assert "ALTER FUNCTION audit.redact" in v.message
