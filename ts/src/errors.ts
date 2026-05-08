/**
 * Exception classes for pgrls-test.
 *
 * A small hierarchy: every error pgrls-test throws inherits from
 * `PgrlsTestError`, so callers can `catch (e) { if (e instanceof
 * PgrlsTestError) … }` to catch any.
 *
 * **Why not extend Node's `AssertionError`?** Vitest matches errors
 * by name + message pattern, not by the Node-specific
 * `AssertionError` shape. The parent chain
 * `PgrlsTestAssertionError → PgrlsTestError → Error` renders
 * cleanly in Vitest's diff output without coupling us to Node's
 * `assert` module.
 *
 * Mirrors `pgrls.testing.errors` (Python). The class hierarchy is
 * intentionally identical so the conformance suite can compare
 * "exception thrown vs raised" assertions byte-for-byte across the
 * two languages.
 */

/**
 * Base class for every error thrown inside pgrls-test.
 *
 * Catch this (`catch (e) { if (e instanceof PgrlsTestError) … }`)
 * to handle any pgrls-test error uniformly.
 */
export class PgrlsTestError extends Error {
  constructor(message: string) {
    super(message);
    // V8's `Error` doesn't auto-set `name` from the constructor;
    // assign it explicitly so stack traces and serialization
    // (e.g. JSON.stringify) carry the subclass name rather than
    // a generic "Error".
    this.name = 'PgrlsTestError';
  }
}

/**
 * Thrown by `assert*` helpers when their precondition fails.
 *
 * Vitest renders this as a normal test failure (no special
 * AssertionError handling needed); its message is the diff /
 * description of what didn't match.
 */
export class PgrlsTestAssertionError extends PgrlsTestError {
  constructor(message: string) {
    super(message);
    this.name = 'PgrlsTestAssertionError';
  }
}

/**
 * Thrown when pgrls-test has no database URL or driver to use.
 *
 * Surfaced when the test setup hasn't supplied a connection /
 * driver, or when an env-var fallback comes back empty.
 */
export class PgrlsTestConfigError extends PgrlsTestError {
  constructor(message: string) {
    super(message);
    this.name = 'PgrlsTestConfigError';
  }
}
