from click.testing import CliRunner

from pgrls.cli import main


def test_root_help_lists_lint():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "lint" in result.output


def test_lint_help_runs():
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "--help"])
    assert result.exit_code == 0
    for flag in ("--database-url", "--config", "--schemas", "--fail-on"):
        assert flag in result.output


def test_root_version_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.0.1" in result.output


def test_lint_stub_raises_not_implemented():
    runner = CliRunner()
    result = runner.invoke(main, ["lint"])
    assert result.exit_code != 0
    assert "not implemented" in result.output
