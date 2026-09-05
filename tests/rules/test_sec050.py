"""Unit tests for SEC050 — Storage policy not scoped to a bucket.

SEC050 (warning) fires on a permissive ``storage.objects`` policy whose
row-reach clause (USING for SELECT/UPDATE/DELETE/ALL, WITH CHECK for INSERT)
has a non-trivial predicate that does not reference ``bucket_id`` — so it
authorizes object access across every bucket. Literal-``true`` is ceded to
SEC008/SEC006; a restrictive ``bucket_id`` floor keeps it silent; it only
looks at ``storage.objects``.
"""
from __future__ import annotations

import pytest

from pgrls.ast_utils import parse_expr
from pgrls.model import Policy, Schema, Table
from pgrls.rules.sec050 import SEC050

_FOLDER = "(storage.foldername(name))[1] = auth.uid()::text"
_BUCKET_FOLDER = (
    "bucket_id = 'avatars' AND (storage.foldername(name))[1] = auth.uid()::text"
)


def _policy(
    using: str | None = None,
    *,
    with_check: str | None = None,
    name: str = "p",
    command: str = "SELECT",
    permissive: bool = True,
    roles: tuple[str, ...] = ("authenticated",),
) -> Policy:
    return Policy(
        name=name,
        command=command,  # type: ignore[arg-type]
        permissive=permissive,
        roles=roles,
        using_sql=using,
        with_check_sql=with_check,
        using_ast=parse_expr(using) if using else None,
        with_check_ast=parse_expr(with_check) if with_check else None,
    )


def _objects(
    *policies: Policy, schema: str = "storage", name: str = "objects"
) -> Table:
    return Table(
        schema=schema,
        name=name,
        rls_enabled=True,
        force_rls=False,
        policies=policies,
        columns=("id", "bucket_id", "name", "owner_id"),
    )


def _check(table: Table, options: dict | None = None) -> list:
    return SEC050().check(Schema(tables=(table,)), options or {})


# --- firing --------------------------------------------------------------


def test_fires_folder_scoped_no_bucket() -> None:
    [v] = _check(_objects(_policy(_FOLDER)))
    assert v.rule_id == "SEC050"
    assert v.severity == "warning"
    assert v.location == "storage.objects.p"
    assert "bucket_id" in v.message
    assert "every bucket" in v.message


def test_fires_owner_scoped_no_bucket() -> None:
    assert (
        len(_check(_objects(_policy("owner_id = auth.uid()", command="ALL"))))
        == 1
    )


def test_fires_insert_with_check_no_bucket() -> None:
    assert (
        len(_check(_objects(_policy(with_check=_FOLDER, command="INSERT"))))
        == 1
    )


def test_fires_when_only_bucket_id_ref_is_another_table_in_subquery() -> None:
    # The single bucket_id reference belongs to an unrelated table inside an
    # EXISTS subquery; storage.objects' own bucket_id is never constrained, so
    # the policy is cross-bucket and must fire. (Regression: the column walker
    # used to descend into sublinks and be fooled by the foreign bucket_id.)
    [v] = _check(
        _objects(_policy("EXISTS (SELECT 1 FROM acl a WHERE a.bucket_id = name)"))
    )
    assert v.location == "storage.objects.p"


def test_fires_all_using_unscoped_even_if_with_check_scopes_bucket() -> None:
    # The USING reads across every bucket even though WITH CHECK scopes the
    # bucket — the read side is the cross-bucket leak.
    assert (
        len(
            _check(
                _objects(
                    _policy(
                        "owner_id = auth.uid()",
                        with_check="bucket_id = 'x'",
                        command="ALL",
                    )
                )
            )
        )
        == 1
    )


# --- not firing ----------------------------------------------------------


def test_silent_bucket_scoped_select() -> None:
    assert _check(_objects(_policy(_BUCKET_FOLDER))) == []


def test_silent_qualified_bucket_ref() -> None:
    assert (
        _check(_objects(_policy("objects.bucket_id = 'x' AND owner_id = auth.uid()")))
        == []
    )


def test_silent_using_true_ceded_to_sec008() -> None:
    assert _check(_objects(_policy("true", roles=("anon",)))) == []


def test_silent_insert_with_check_bucket() -> None:
    assert (
        _check(_objects(_policy(with_check="bucket_id = 'docs'", command="INSERT")))
        == []
    )


def test_silent_all_using_bucket_with_check_owner() -> None:
    # Read side is bucket-scoped; the unscoped WITH CHECK is an accepted
    # cross-bucket *write* false negative (recall, not a flagged exposure).
    assert (
        _check(
            _objects(
                _policy(
                    "bucket_id = 'x'",
                    with_check="owner_id = auth.uid()",
                    command="ALL",
                )
            )
        )
        == []
    )


def test_silent_restrictive_bucket_floor() -> None:
    # A restrictive bucket_id floor confines the whole table to a bucket.
    assert (
        _check(
            _objects(
                _policy("owner_id = auth.uid()", command="ALL"),
                _policy(
                    "bucket_id = 'docs'",
                    name="floor",
                    permissive=False,
                    command="ALL",
                ),
            )
        )
        == []
    )


def test_silent_restrictive_policy_is_not_a_grant() -> None:
    # SEC050 only flags permissive (access-granting) policies.
    assert _check(_objects(_policy(_FOLDER, name="r", permissive=False))) == []


def test_silent_non_storage_table() -> None:
    assert _check(_objects(_policy(_FOLDER), schema="public", name="documents")) == []


def test_silent_storage_buckets_table() -> None:
    assert _check(_objects(_policy("name = 'x'"), name="buckets")) == []


def test_silent_select_policy_with_unparsed_using() -> None:
    # A SELECT policy whose USING didn't parse → nothing to analyze → silent.
    assert _check(_objects(_policy(None))) == []


def test_offline_without_columns_abstains_loudly() -> None:
    # An offline `--sql-file` that lints only `CREATE POLICY ON storage.objects`
    # (no CREATE TABLE — the table is extension-managed) leaves `columns` empty.
    # bucket_id then can't be resolved to an own column, so no per-policy
    # verdict is possible — a correctly scoped policy must not be flagged.
    # But a SILENT abstain here was a false clean on exactly the Supabase
    # migration input this rule exists for (and it never showed up in
    # `skipped_rules`), so the rule now says so: one info note per table.
    table = Table(
        schema="storage",
        name="objects",
        rls_enabled=True,
        force_rls=False,
        policies=(_policy("bucket_id = 'avatars' AND owner_id = auth.uid()"),),
        columns=(),
    )
    vs = SEC050().check(Schema(tables=(table,)), {})
    assert [(v.severity, v.location) for v in vs] == [("info", "storage.objects")]
    assert "CREATE TABLE storage.objects" in vs[0].message
    # With no policies at all there is nothing to abstain on — stay silent.
    empty = Table(schema="storage", name="objects", rls_enabled=True, force_rls=False, policies=(), columns=())
    assert SEC050().check(Schema(tables=(empty,)), {}) == []


# --- multiple policies + options + metadata ------------------------------


def test_only_the_unscoped_policy_is_reported() -> None:
    vs = _check(
        _objects(
            _policy(_BUCKET_FOLDER, name="scoped"),
            _policy(_FOLDER, name="unscoped"),
        )
    )
    assert [v.location for v in vs] == ["storage.objects.unscoped"]


def test_allowlist_suppresses() -> None:
    assert _check(_objects(_policy(_FOLDER)), {"allowlist": ["storage.objects.p"]}) == []


def test_allowlist_bad_type_raises_typeerror() -> None:
    with pytest.raises(TypeError):
        _check(_objects(_policy(_FOLDER)), {"allowlist": "storage.objects.p"})


def test_metadata() -> None:
    rule = SEC050()
    assert rule.id == "SEC050"
    assert rule.severity == "warning"
    assert rule.title
