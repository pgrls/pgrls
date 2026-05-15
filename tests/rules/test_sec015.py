"""Unit tests for SEC015 — SECURITY DEFINER pg_temp search-path shadowing.

SEC015 fires on every SECDEF function whose effective search_path does
not end with an explicit `pg_temp` token. The only structurally-safe
shape is a pinned search_path with `pg_temp` named last (Postgres
searches the temp schema last only when it's explicitly placed there;
otherwise it's searched first for relations — the shadowing surface).
"""
from __future__ import annotations

import pytest

from pgrls.model import Schema, SecdefFunction
from pgrls.rules.sec015 import SEC015, _is_pg_temp_safe, _search_path_tokens


def _secdef(
    qname: str,
    *,
    search_path: str | None = None,
    body: str = "SELECT 1",
    language: str = "sql",
) -> SecdefFunction:
    return SecdefFunction(
        qualified_name=qname,
        body=body,
        language=language,
        search_path=search_path,
    )


# --- _search_path_tokens -------------------------------------------------


def test_search_path_tokens_splits_and_normalizes() -> None:
    assert _search_path_tokens("pg_catalog, public, pg_temp") == [
        "pg_catalog",
        "public",
        "pg_temp",
    ]


def test_search_path_tokens_strips_quotes_and_lowercases() -> None:
    # `"$user"` and quoted mixed-case names normalize; the pg_temp
    # comparison downstream is case-insensitive.
    assert _search_path_tokens('"$user", "MySchema", PG_TEMP') == [
        "$user",
        "myschema",
        "pg_temp",
    ]


def test_search_path_tokens_drops_empty_tokens() -> None:
    # Trailing comma / empty value yields no spurious "" tokens.
    assert _search_path_tokens("public, , pg_temp,") == ["public", "pg_temp"]
    assert _search_path_tokens("") == []
    assert _search_path_tokens("   ") == []


# --- _is_pg_temp_safe ----------------------------------------------------


def test_is_pg_temp_safe_true_only_when_pg_temp_is_last() -> None:
    assert _is_pg_temp_safe("pg_catalog, pg_temp") is True
    assert _is_pg_temp_safe("public, pg_temp") is True
    assert _is_pg_temp_safe('"$user", public, pg_temp') is True


def test_is_pg_temp_safe_false_when_unpinned() -> None:
    # None = no SET search_path clause — inherits the caller's
    # search_path, pg_temp implicitly first.
    assert _is_pg_temp_safe(None) is False


def test_is_pg_temp_safe_false_when_pg_temp_absent() -> None:
    # pg_temp not named → searched first by default for relations.
    assert _is_pg_temp_safe("pg_catalog, public") is False
    assert _is_pg_temp_safe("public") is False


def test_is_pg_temp_safe_false_when_pg_temp_not_last() -> None:
    # pg_temp explicitly placed early is the worst case — the temp
    # schema is searched before the legitimate schemas.
    assert _is_pg_temp_safe("pg_temp, public") is False
    assert _is_pg_temp_safe("public, pg_temp, pg_catalog") is False


def test_is_pg_temp_safe_false_when_empty_string() -> None:
    # `SET search_path = ''` leaves pg_temp implicitly first for
    # relation lookups — unqualified references still resolve into
    # the temp schema. Not safe on its own.
    assert _is_pg_temp_safe("") is False


# --- SEC015 rule ---------------------------------------------------------


def test_sec015_fires_on_unpinned_secdef_function() -> None:
    schema = Schema(
        security_definer_functions=(_secdef("public.do_thing"),),
    )
    [v] = SEC015().check(schema, options={})
    assert v.rule_id == "SEC015"
    assert v.severity == "warning"
    assert v.location == "public.do_thing"
    assert "pins no search_path" in v.message
    assert "pg_temp" in v.message
    assert "ALTER FUNCTION" in v.message


def test_sec015_fires_on_pinned_but_pg_temp_absent() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.do_thing", search_path="pg_catalog, public"),
        ),
    )
    [v] = SEC015().check(schema, options={})
    assert v.location == "public.do_thing"
    # Message names the actual configured value so the operator
    # sees what they have vs. what they need.
    assert "'pg_catalog, public'" in v.message
    assert "does not end with an explicit pg_temp" in v.message


def test_sec015_fires_on_pg_temp_not_last() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.do_thing", search_path="pg_temp, public"),
        ),
    )
    [v] = SEC015().check(schema, options={})
    assert v.location == "public.do_thing"


def test_sec015_silent_when_pg_temp_pinned_last() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.safe_a", search_path="pg_catalog, pg_temp"),
            _secdef("public.safe_b", search_path="public, pg_temp"),
        ),
    )
    assert SEC015().check(schema, options={}) == []


def test_sec015_silent_when_no_secdef_functions() -> None:
    assert SEC015().check(Schema(), options={}) == []


def test_sec015_mixed_schema_flags_only_unsafe() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.safe", search_path="pg_catalog, pg_temp"),
            _secdef("public.unpinned"),
            _secdef("public.bad_order", search_path="pg_temp, public"),
        ),
    )
    flagged = {v.location for v in SEC015().check(schema, options={})}
    assert flagged == {"public.unpinned", "public.bad_order"}


def test_sec015_allowlist_skips_qualified_function() -> None:
    schema = Schema(
        security_definer_functions=(
            _secdef("public.audited"),
            _secdef("public.unaudited"),
        ),
    )
    violations = SEC015().check(
        schema, options={"allowlist": ["public.audited"]}
    )
    assert [v.location for v in violations] == ["public.unaudited"]


def test_sec015_allowlist_rejects_bare_function_name() -> None:
    with pytest.raises(TypeError, match="schema.function"):
        SEC015().check(
            Schema(security_definer_functions=(_secdef("public.fn"),)),
            options={"allowlist": ["fn"]},
        )


def test_sec015_allowlist_rejects_three_part_id() -> None:
    with pytest.raises(TypeError, match="schema.function"):
        SEC015().check(
            Schema(security_definer_functions=(_secdef("public.fn"),)),
            options={"allowlist": ["public.fn.int"]},
        )


def test_sec015_message_includes_allowlist_hint() -> None:
    schema = Schema(
        security_definer_functions=(_secdef("audit.refresh"),),
    )
    [v] = SEC015().check(schema, options={})
    assert "'audit.refresh'" in v.message
    assert "[lint.rules.SEC015]" in v.message


def test_sec015_fires_regardless_of_language() -> None:
    # SEC015 keys off search_path, not the body — a plpgsql SECDEF
    # function with an unsafe search_path is flagged the same as a
    # sql one.
    schema = Schema(
        security_definer_functions=(
            _secdef(
                "public.plpgsql_fn",
                language="plpgsql",
                body="BEGIN PERFORM 1; END",
            ),
        ),
    )
    [v] = SEC015().check(schema, options={})
    assert v.location == "public.plpgsql_fn"
