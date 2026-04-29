"""Unit tests for pgrls.testing.errors."""
from __future__ import annotations

import pytest

from pgrls.testing.errors import (
    PgrlsTestAssertionError,
    PgrlsTestConfigError,
    PgrlsTestError,
)


def test_assertion_error_is_subclass_of_test_error() -> None:
    # All pgrls.testing-raised errors share a common base so a
    # caller can `except PgrlsTestError` to catch any.
    assert issubclass(PgrlsTestAssertionError, PgrlsTestError)


def test_config_error_is_subclass_of_test_error() -> None:
    assert issubclass(PgrlsTestConfigError, PgrlsTestError)


def test_assertion_error_carries_message() -> None:
    exc = PgrlsTestAssertionError("expected 1 row, got 2")
    assert "expected 1 row" in str(exc)


def test_assertion_error_is_assertion_subclass() -> None:
    # pytest renders AssertionError subclasses with diff-style
    # output. Our assertion-failure errors should plug into that
    # machinery — making them an AssertionError subclass is the
    # standard pytest-ecosystem convention.
    assert issubclass(PgrlsTestAssertionError, AssertionError)


def test_pgrls_test_error_is_exception() -> None:
    assert issubclass(PgrlsTestError, Exception)


def test_can_raise_and_catch_via_base() -> None:
    with pytest.raises(PgrlsTestError):
        raise PgrlsTestAssertionError("from assertion")
    with pytest.raises(PgrlsTestError):
        raise PgrlsTestConfigError("from config")
