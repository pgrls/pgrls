"""Unit tests for SEC014 — SECURITY DEFINER function audit (free-standing).

The rule's scope is *every* SECDEF function in the introspected schemas
— SEC014 is a "audit-every-SECDEF-surface" prompt, not a proof-of-leak.
VIEW004 already analyses bodies for RLS-table reads; SEC013 catches
trigger-mediated bypass paths. SEC014 fills the gap for functions
called directly from application code.
"""
from __future__ import annotations

import pytest

from pgrls.model import Schema, SecdefFunction
from pgrls.rules.sec014 import SEC014


def _secdef(
    qname: str,
    *,
    body: str = "SELECT 1",
    language: str = "sql",
) -> SecdefFunction:
    return SecdefFunction(
        qualified_name=qname,
        body=body,
        language=language,
    )


def test_sec014_fires_on_every_secdef_function() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.do_thing"),
            _secdef("audit.log_change"),
        ),
    )
    violations = SEC014().check(schema, options={})
    # Order matches Schema.security_definer_functions iteration order
    # (introspection-captured alphabetical (schema, name)). The
    # fixture here just preserves the construction order.
    assert [v.location for v in violations] == [
        "public.do_thing",
        "audit.log_change",
    ]
    for v in violations:
        assert v.rule_id == "SEC014"
        assert v.severity == "warning"
        assert v.title == "SECURITY DEFINER function bypasses caller's RLS"
        assert "SECURITY DEFINER" in v.message
        assert "SECURITY INVOKER" in v.message
        # Message must point at the cross-rule landscape so operators
        # understand SEC014 vs SEC013 vs VIEW004 don't double-fire on
        # the same architectural surface.
        assert "VIEW004" in v.message
        assert "SEC013" in v.message


def test_sec014_silent_when_no_secdef_functions() -> None:
    # The most common case in a fresh project — no SECDEF functions
    # means nothing to audit.
    schema = Schema(security_definer_functions=())
    assert SEC014().check(schema, options={}) == []


def test_sec014_silent_when_schema_has_no_secdef_field_at_all() -> None:
    # Defensive: a Schema constructed without the security_definer_functions
    # kwarg defaults to () via the dataclass factory; SEC014 must
    # handle that empty-tuple case without surprising errors.
    schema = Schema()
    assert SEC014().check(schema, options={}) == []


def test_sec014_allowlist_skips_qualified_function() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.do_thing"),
            _secdef("audit.log_change"),
        ),
    )
    violations = SEC014().check(
        schema, options={"allowlist": ["public.do_thing"]}
    )
    assert [v.location for v in violations] == ["audit.log_change"]


def test_sec014_allowlist_silences_all_secdef() -> None:
    # Operators who've audited every function should be able to
    # silence the rule entirely via the allowlist (preferred over
    # `disable = ["SEC014"]` because the allowlist documents which
    # functions have been reviewed).
    schema = Schema(
        security_definer_functions=(
            _secdef("public.a"),
            _secdef("public.b"),
        ),
    )
    violations = SEC014().check(
        schema,
        options={"allowlist": ["public.a", "public.b"]},
    )
    assert violations == []


def test_sec014_allowlist_rejects_bare_function_name() -> None:
    # `do_thing` (no schema) — could shadow same-named functions in
    # multiple schemas. Reject loudly per the _allowlist module's
    # shape-validation policy.
    with pytest.raises(TypeError, match="schema.function"):
        SEC014().check(
            Schema(security_definer_functions=(_secdef("public.do_thing"),)),
            options={"allowlist": ["do_thing"]},
        )


def test_sec014_allowlist_rejects_three_part_id() -> None:
    # `schema.function.signature` — operators might mistake this for
    # a policy-ID-like format. Reject so the misconfiguration is
    # surfaced immediately rather than silently failing to match.
    with pytest.raises(TypeError, match="schema.function"):
        SEC014().check(
            Schema(security_definer_functions=(_secdef("public.do_thing"),)),
            options={"allowlist": ["public.do_thing.int"]},
        )


def test_sec014_allowlist_rejects_empty_parts() -> None:
    # `.do_thing` or `public.` — both have an empty side. The
    # _list_of_strings validator catches the whitespace-trim case;
    # this test pins the empty-after-split case.
    with pytest.raises(TypeError):
        SEC014().check(
            Schema(security_definer_functions=(_secdef("public.do_thing"),)),
            options={"allowlist": [".do_thing"]},
        )
    with pytest.raises(TypeError):
        SEC014().check(
            Schema(security_definer_functions=(_secdef("public.do_thing"),)),
            options={"allowlist": ["public."]},
        )


def test_sec014_allowlist_rejects_non_string_entries() -> None:
    # The shared _list_of_strings validator rejects mixed-type lists.
    with pytest.raises(TypeError, match="list of strings"):
        SEC014().check(
            Schema(security_definer_functions=(_secdef("public.do_thing"),)),
            options={"allowlist": ["public.do_thing", 42]},
        )


def test_sec014_allowlist_rejects_leading_trailing_whitespace() -> None:
    # The shared _list_of_strings validator rejects whitespace-padded
    # entries so a typo'd `" public.fn "` doesn't silently fail to
    # match. The error message names the stripped form for one-
    # keystroke fixing.
    with pytest.raises(TypeError, match="public.do_thing"):
        SEC014().check(
            Schema(security_definer_functions=(_secdef("public.do_thing"),)),
            options={"allowlist": [" public.do_thing "]},
        )


def test_sec014_fires_on_plpgsql_secdef_functions() -> None:
    # SEC014 doesn't introspect the function body — every SECDEF
    # function is flagged regardless of language. This is a
    # deliberate divergence from VIEW004 which parses the body and
    # skips non-SQL languages with a stderr warning. SEC014's job
    # is to surface the SECDEF surface; the operator's job is to
    # audit each function (regardless of language) and allowlist.
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "public.plpgsql_fn",
                language="plpgsql",
                body="BEGIN PERFORM 1; END",
            ),
        ),
    )
    [v] = SEC014().check(schema, options={})
    assert v.location == "public.plpgsql_fn"
    # The language is included in the message so the operator's
    # triage can prioritize SQL functions (parseable) over plpgsql
    # (manual review).
    assert "'plpgsql'" in v.message


def test_sec014_message_includes_function_qname_in_allowlist_hint() -> None:
    # The remediation hint in the message must name the function so
    # a `[lint.rules.SEC014]` allowlist entry copy-pastes cleanly.
    schema = Schema(
        security_definer_functions=(_secdef("audit.refresh_cache"),),
    )
    [v] = SEC014().check(schema, options={})
    assert "'audit.refresh_cache'" in v.message
    assert "[lint.rules.SEC014]" in v.message
