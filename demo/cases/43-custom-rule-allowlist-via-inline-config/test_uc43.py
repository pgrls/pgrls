"""Use case 43: Custom rule allowlist via inline config —."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc43_sec003_allowlist_silences_intentional_public_read(
    demo_db: str,
    tmp_path: Path,
    lint,
    base_config,
    pgrls_toml,
) -> None:
    # `app.public_metadata.metadata_read` is a deliberate
    # PUBLIC SELECT policy on a documentation table. SEC003
    # fires by default; allowlisting silences it.
    default_out = lint(config=pgrls_toml)
    assert (
        "SEC003  app.public_metadata.metadata_read\n" in default_out
    )

    cfg = tmp_path / "p.toml"
    cfg.write_text(
        base_config
        + '[lint.rules.SEC003]\n'
        'allowlist = ["app.public_metadata.metadata_read"]\n'
    )
    out = lint(config=cfg)
    assert "SEC003  app.public_metadata" not in out


