"""Use case 42: Multi-schema scan — `tenant` schema."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc42_multi_schema_scan_picks_up_other_schema(
    demo_db: str,
    tmp_path: Path,
    lint,
    pgrls_toml,
) -> None:
    # `tenant.tenant_orphans` is in a schema the default
    # config doesn't scan. Adding `tenant` via --schemas
    # surfaces SEC001 on it.
    default_out = lint(config=pgrls_toml)
    assert "SEC001  tenant.tenant_orphans" not in default_out

    out = lint(config=pgrls_toml,
        extra_args=("--schemas", "app,tenant"),
    )
    assert "SEC001  tenant.tenant_orphans\n" in out


