"""Use case 40: Admin audit log — SEC005 allowlist demo."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc40_sec005_allowlist_silences_admin_audit(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
    pgrls_toml,
) -> None:
    # admin_audit's policy is legitimately session-state-only.
    # SEC005 fires by default; allowlisting the qualified
    # policy ID silences it.
    default_out = lint(config=pgrls_toml)
    assert (
        "SEC005  app.admin_audit.admin_only_read\n" in default_out
    )

    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config
        + '[lint.rules.SEC005]\n'
        'allowlist = ["app.admin_audit.admin_only_read"]\n'
    )
    out = lint(config=cfg)
    assert "SEC005  app.admin_audit" not in out


