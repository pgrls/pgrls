"""Exception classes for pgrls.testing.

A small hierarchy: every error pgrls.testing raises inherits from
`PgrlsTestError`, so callers can `except PgrlsTestError` to catch
any. Assertion failures additionally subclass Python's
`AssertionError` so pytest renders them with its standard
diff-style output.
"""
from __future__ import annotations


class PgrlsTestError(Exception):
    """Base class for every error raised inside pgrls.testing."""


class PgrlsTestAssertionError(PgrlsTestError, AssertionError):
    """Raised by assert_* helpers when their precondition fails.

    Subclasses `AssertionError` (in addition to PgrlsTestError) so
    pytest's standard AssertionError handling — diff-style output,
    `--tb=long` rewrites — engages without us doing anything
    special.
    """


class PgrlsTestConfigError(PgrlsTestError):
    """Raised when pgrls.testing has no database URL to use.

    Surfaced by the `pgrls_test_database_url` fixture when neither
    `PGRLS_TEST_DATABASE_URL` nor `DATABASE_URL` is set in the
    environment and the user hasn't supplied a
    `pgrls_test_database_url` override in conftest.
    """
