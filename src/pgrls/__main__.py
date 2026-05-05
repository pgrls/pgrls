"""Allow `python -m pgrls` to invoke the CLI.

The `[project.scripts]` entry in pyproject.toml installs a `pgrls`
console script for normal use. This module exists so callers that
need to bypass the script (e.g. test subprocesses that must run
against the same interpreter as the parent process) can use
`sys.executable -m pgrls` and skip $PATH / shebang resolution
entirely.
"""
from pgrls.cli import main

if __name__ == "__main__":
    main()
