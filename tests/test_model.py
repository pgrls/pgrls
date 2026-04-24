from __future__ import annotations

from pgrls.model import Policy, PolicyCommand, Schema, Snapshot, Table


def test_table_construction() -> None:
    t = Table(
        schema="public",
        name="orders",
        rls_enabled=True,
        force_rls=True,
        policies=(),
    )
    assert t.qualified_name == "public.orders"


def test_policy_construction() -> None:
    p = Policy(
        name="tenant_isolation",
        command="SELECT",
        permissive=True,
        roles=("authenticated",),
        using_sql="(tenant_id = current_setting('app.tenant_id'))",
        with_check_sql=None,
    )
    assert p.command == "SELECT"
    assert p.is_permissive is True


def test_policy_command_literal_values() -> None:
    valid: list[PolicyCommand] = ["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
    for cmd in valid:
        p = Policy(
            name=f"p_{cmd}",
            command=cmd,
            permissive=True,
            roles=(),
            using_sql=None,
            with_check_sql=None,
        )
        assert p.command == cmd


def test_schema_to_snapshot_shape() -> None:
    table = Table(
        schema="public",
        name="orders",
        rls_enabled=True,
        force_rls=False,
        policies=(
            Policy(
                name="select_own",
                command="SELECT",
                permissive=True,
                roles=("authenticated",),
                using_sql="(user_id = current_setting('app.user_id'))",
                with_check_sql=None,
            ),
        ),
    )
    snap: Snapshot = Schema(tables=(table,)).to_snapshot()
    assert snap == {
        "version": 1,
        "tables": [
            {
                "schema": "public",
                "name": "orders",
                "rls_enabled": True,
                "force_rls": False,
            }
        ],
        "policies": [
            {
                "id": "public.orders.select_own",
                "table_schema": "public",
                "table_name": "orders",
                "policy_name": "select_own",
                "command": "SELECT",
                "permissive": True,
                "roles": ["authenticated"],
                "using_sql": "(user_id = current_setting('app.user_id'))",
                "with_check_sql": None,
            }
        ],
    }


def test_snapshot_is_json_serializable() -> None:
    import json

    schema = Schema(
        tables=(
            Table(
                schema="public",
                name="empty",
                rls_enabled=False,
                force_rls=False,
                policies=(),
            ),
        )
    )
    text = json.dumps(schema.to_snapshot(), sort_keys=True)
    assert "public.empty" not in text  # no policies, no policy ids
    assert '"rls_enabled": false' in text


def test_model_classes_are_hashable() -> None:
    """Frozen dataclasses with tuple fields should be hashable for set/dict use."""
    p = Policy(
        name="x",
        command="SELECT",
        permissive=True,
        roles=(),
        using_sql=None,
        with_check_sql=None,
    )
    t = Table(
        schema="public",
        name="t",
        rls_enabled=True,
        force_rls=False,
        policies=(p,),
    )
    s = Schema(tables=(t,))

    # Each is independently hashable
    hash(p)
    hash(t)
    hash(s)

    # And usable in a set
    assert {p, t, s} == {p, t, s}
