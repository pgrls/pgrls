"""Use case 39: Custom auth function — config-driven detection."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc39_custom_auth_function_detected_via_config(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
    pgrls_toml,
) -> None:
    # `app.current_user_id()` is silent under the default
    # PERF001 auth_functions list. Override the list to add it,
    # and PERF001 fires on `app.user_workspaces.workspace_owner`.
    # Note: an override REPLACES the default list, so we
    # re-include the defaults to avoid losing other detection.
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config
        + '[lint.rules.PERF001]\n'
        'auth_functions = ["auth.uid", "auth.role", "auth.jwt", '
        '"current_setting", "app.current_user_id"]\n'
    )
    out = lint(config=cfg)
    # Default config: silent on user_workspaces.
    default_out = lint(config=pgrls_toml)
    assert "PERF001  app.user_workspaces" not in default_out
    # Custom config: fires.
    assert (
        "PERF001  app.user_workspaces.workspace_owner\n" in out
    )


