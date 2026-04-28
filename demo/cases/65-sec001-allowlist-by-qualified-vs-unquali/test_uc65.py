"""Use case 65: SEC001 allowlist by qualified vs unqualified —."""
from __future__ import annotations

from pathlib import Path  # noqa: F401

def test_uc65_sec001_allowlist_accepts_unqualified_name(
    demo_db: str,
    tmp_path: Path,
    lint,
) -> None:
    # Default config allowlists `app.countries` (qualified).
    # The rule also accepts unqualified names — running with
    # `allowlist = ["legacy_orders"]` (unqualified) should
    # silence SEC001 on uc03's `app.legacy_orders`.
    cfg = tmp_path / "p.toml"
    cfg.write_text(
        '[database]\nschemas = ["app"]\n'
        '[lint.rules.SEC001]\n'
        'allowlist = ["legacy_orders", "countries"]\n'
    )
    out = lint(config=cfg)
    assert "SEC001  app.legacy_orders" not in out


