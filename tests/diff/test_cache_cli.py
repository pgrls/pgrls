"""Tests for the v0.5.3 ``pgrls cache`` subcommand group and the
``pgrls diff --verbose`` flag.

Unit tests cover:
  * Human-readable byte formatting (``_human_bytes``).
  * ``pgrls cache list`` with empty + populated cache (mocked).
  * ``pgrls cache prune`` with --yes / interactive abort paths.
  * ``pgrls diff --verbose`` flag wiring (no apply path).

Integration tests (Docker-required) live in ``test_cli_apply.py``
and exercise the verbose telemetry's actual content during a
real testcontainer run.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pgrls.cli import _human_bytes, main


# ---------------------------------------------------------------------------
# _human_bytes
# ---------------------------------------------------------------------------


def test_human_bytes_zero():
    """Zero is a valid disk size (empty image, theoretically).
    Pin the format so the cache list output stays tidy."""
    assert _human_bytes(0) == "0B"


def test_human_bytes_under_kilobyte():
    """Sub-kB sizes use the bare B unit, no decimal."""
    assert _human_bytes(512) == "512B"
    assert _human_bytes(999) == "999B"


def test_human_bytes_kilobytes():
    """1000+ bytes step up to kB with one decimal of precision."""
    assert _human_bytes(1000) == "1.0kB"
    assert _human_bytes(1500) == "1.5kB"
    assert _human_bytes(999_999) == "1000.0kB"


def test_human_bytes_megabytes():
    """A real-world Postgres image (~437MB) lands here."""
    assert _human_bytes(437_000_000) == "437.0MB"


def test_human_bytes_gigabytes():
    """Pin the GB stepover; nobody's caching TB-scale images
    but worth verifying the unit ladder works."""
    assert _human_bytes(2_500_000_000) == "2.5GB"


def test_human_bytes_uses_decimal_units():
    """Docker reports image sizes in decimal (1000-based) units;
    pgrls cache list mirrors that convention. Pin the boundary
    so a future swap to binary (1024-based) doesn't slip in
    silently — that would make `pgrls cache list` numbers stop
    matching `docker images`."""
    # 1 MB decimal = 1_000_000 bytes; 1 MiB binary = 1_048_576.
    # If we're decimal, 1_000_000 → "1.0MB". If binary,
    # 1_000_000 → "976.6kB".
    assert _human_bytes(1_000_000) == "1.0MB"


# ---------------------------------------------------------------------------
# pgrls cache list — mocked
# ---------------------------------------------------------------------------


def test_cache_list_reports_empty_when_no_baselines():
    """No cached images → friendly "no cached baselines" message
    instead of empty output. Matches the `pgrls cache prune`
    path so the two commands' empty-cache UX is consistent."""
    runner = CliRunner()
    with patch("pgrls.cli._cache_images", return_value=[]):
        result = runner.invoke(main, ["cache", "list"])
    assert result.exit_code == 0
    assert "no cached baselines" in result.output


def test_cache_list_reports_populated_cache_with_tags_and_total():
    """Each pgrls-baseline:* tag gets one line; total summary on
    the last line. Pin the row format so users / docs / scripts
    can rely on it."""
    img1 = MagicMock()
    img1.attrs = {"Size": 437_000_000}
    img1.tags = ["pgrls-baseline:abcdef0123456789"]
    img1.short_id = "abcdef012345"

    img2 = MagicMock()
    img2.attrs = {"Size": 200_000_000}
    img2.tags = ["pgrls-baseline:0011223344556677"]
    img2.short_id = "001122334455"

    runner = CliRunner()
    with patch("pgrls.cli._cache_images", return_value=[img1, img2]):
        result = runner.invoke(main, ["cache", "list"])
    assert result.exit_code == 0
    out = result.output
    assert "pgrls-baseline:abcdef0123456789" in out
    assert "pgrls-baseline:0011223344556677" in out
    assert "437.0MB" in out
    assert "200.0MB" in out
    # Total summary line — rough, allow whitespace formatting.
    assert "2 image(s)" in out
    assert "637.0MB" in out


def test_cache_list_filters_out_user_tags_on_same_image():
    """An image may carry multiple tags (e.g. user added their
    own tag for clarity). Only `pgrls-baseline:*` tags should
    appear in the listing, since the cache subcommand is
    specifically for the cache."""
    img = MagicMock()
    img.attrs = {"Size": 100_000_000}
    img.tags = [
        "pgrls-baseline:abcdef0123456789",
        "my-debug-tag:latest",
    ]
    img.short_id = "abcdef012345"

    runner = CliRunner()
    with patch("pgrls.cli._cache_images", return_value=[img]):
        result = runner.invoke(main, ["cache", "list"])
    assert result.exit_code == 0
    assert "pgrls-baseline:abcdef0123456789" in result.output
    assert "my-debug-tag" not in result.output


# ---------------------------------------------------------------------------
# pgrls cache prune — mocked
# ---------------------------------------------------------------------------


def test_cache_prune_does_nothing_when_cache_is_empty():
    """Empty cache prune → friendly message + no-op. No docker
    calls made; mocked _cache_images returning [] is enough."""
    runner = CliRunner()
    with patch("pgrls.cli._cache_images", return_value=[]):
        result = runner.invoke(main, ["cache", "prune", "--yes"])
    assert result.exit_code == 0
    assert "nothing to prune" in result.output


def test_cache_prune_with_yes_skips_confirmation_and_removes_all():
    """With --yes, prune skips the y/N prompt and removes every
    pgrls-baseline image. Pin the docker.images.remove call
    count so a refactor that double-removes (or skips) gets
    caught."""
    img1 = MagicMock()
    img1.attrs = {"Size": 100_000_000}
    img1.id = "sha256:111"
    img1.short_id = "111"
    img2 = MagicMock()
    img2.attrs = {"Size": 200_000_000}
    img2.id = "sha256:222"
    img2.short_id = "222"

    fake_client = MagicMock()
    fake_client.images.remove = MagicMock()

    runner = CliRunner()
    with (
        patch("pgrls.cli._cache_images", return_value=[img1, img2]),
        patch("docker.from_env", return_value=fake_client),
    ):
        result = runner.invoke(main, ["cache", "prune", "--yes"])

    assert result.exit_code == 0
    assert fake_client.images.remove.call_count == 2
    assert "removed 2 image(s)" in result.output


def test_cache_prune_interactive_abort_keeps_images():
    """Without --yes, a "no" at the confirmation prompt aborts
    cleanly with no docker.remove calls. Pin the abort UX so
    the cancel path doesn't accidentally proceed."""
    img = MagicMock()
    img.attrs = {"Size": 100_000_000}
    img.id = "sha256:abc"
    img.short_id = "abc"

    fake_client = MagicMock()
    fake_client.images.remove = MagicMock()

    runner = CliRunner()
    with (
        patch("pgrls.cli._cache_images", return_value=[img]),
        patch("docker.from_env", return_value=fake_client),
    ):
        # CliRunner sends "n\n" to the confirmation prompt.
        result = runner.invoke(main, ["cache", "prune"], input="n\n")

    assert result.exit_code == 0
    assert "aborted" in result.output
    assert fake_client.images.remove.call_count == 0


def test_cache_prune_interactive_yes_proceeds():
    """Without --yes, a "y" response runs the prune. Mirrors
    the --yes test but exercises the interactive yes path."""
    img = MagicMock()
    img.attrs = {"Size": 100_000_000}
    img.id = "sha256:abc"
    img.short_id = "abc"

    fake_client = MagicMock()
    fake_client.images.remove = MagicMock()

    runner = CliRunner()
    with (
        patch("pgrls.cli._cache_images", return_value=[img]),
        patch("docker.from_env", return_value=fake_client),
    ):
        result = runner.invoke(main, ["cache", "prune"], input="y\n")

    assert result.exit_code == 0
    assert fake_client.images.remove.call_count == 1
    assert "removed 1 image(s)" in result.output


# ---------------------------------------------------------------------------
# pgrls diff --verbose flag wiring
# ---------------------------------------------------------------------------


_EMPTY_SNAP = {
    "version": 5,
    "tables": [],
    "policies": [],
    "views": [],
    "security_definer_functions": [],
}


def test_diff_verbose_flag_is_accepted_on_snapshot_path(tmp_path: Path) -> None:
    """`-v` on a snapshot-vs-snapshot diff should be a no-op (the
    verbose telemetry only kicks in on the --apply path) but
    must be ACCEPTED — not a Click parse error. Pin so a future
    refactor that drops the flag doesn't silently break docs."""
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")
    head.write_text(json.dumps(_EMPTY_SNAP), encoding="utf-8")

    runner = CliRunner()
    result_short = runner.invoke(main, ["diff", str(base), str(head), "-v"])
    result_long = runner.invoke(main, ["diff", str(base), str(head), "--verbose"])

    assert result_short.exit_code == 0, result_short.output
    assert result_long.exit_code == 0, result_long.output
    # Snapshot-vs-snapshot has no testcontainer and no cache —
    # nothing to log. The flag should accept silently.
    assert "cache:" not in result_short.output
    assert "cache:" not in result_long.output
