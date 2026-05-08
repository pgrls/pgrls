/**
 * Unit tests for `pgrls-test`'s error hierarchy.
 *
 * Mirrors `tests/testing/test_errors.py` (Python). Subclass
 * relationships and "catch-via-base" semantics must match the
 * Python implementation byte-for-byte so cross-language
 * tests can rely on identical exception flow.
 */
import { describe, expect, it } from 'vitest';

import {
  PgrlsTestAssertionError,
  PgrlsTestConfigError,
  PgrlsTestError,
} from '../src/index.js';

describe('PgrlsTestError hierarchy', () => {
  it('PgrlsTestAssertionError is a subclass of PgrlsTestError', () => {
    const e = new PgrlsTestAssertionError('boom');
    expect(e).toBeInstanceOf(PgrlsTestError);
    expect(e).toBeInstanceOf(PgrlsTestAssertionError);
  });

  it('PgrlsTestConfigError is a subclass of PgrlsTestError', () => {
    const e = new PgrlsTestConfigError('boom');
    expect(e).toBeInstanceOf(PgrlsTestError);
    expect(e).toBeInstanceOf(PgrlsTestConfigError);
  });

  it('every subclass is also an Error', () => {
    expect(new PgrlsTestError('x')).toBeInstanceOf(Error);
    expect(new PgrlsTestAssertionError('x')).toBeInstanceOf(Error);
    expect(new PgrlsTestConfigError('x')).toBeInstanceOf(Error);
  });
});

describe('PgrlsTestError.message', () => {
  it('PgrlsTestError carries its message', () => {
    const e = new PgrlsTestError('bad config');
    expect(e.message).toBe('bad config');
    expect(String(e)).toContain('bad config');
  });

  it('PgrlsTestAssertionError carries its message', () => {
    const e = new PgrlsTestAssertionError('expected 1 row, got 2');
    expect(e.message).toContain('expected 1 row');
  });

  it('PgrlsTestConfigError carries its message', () => {
    const e = new PgrlsTestConfigError('no DATABASE_URL');
    expect(e.message).toContain('no DATABASE_URL');
  });
});

describe('PgrlsTestError.name', () => {
  // Pin the class-name attribute so stack traces and serialization
  // (e.g. JSON.stringify on a structured logger) don't render
  // every error as a generic "Error".
  it('PgrlsTestError.name is "PgrlsTestError"', () => {
    expect(new PgrlsTestError('x').name).toBe('PgrlsTestError');
  });

  it('PgrlsTestAssertionError.name is "PgrlsTestAssertionError"', () => {
    expect(new PgrlsTestAssertionError('x').name).toBe('PgrlsTestAssertionError');
  });

  it('PgrlsTestConfigError.name is "PgrlsTestConfigError"', () => {
    expect(new PgrlsTestConfigError('x').name).toBe('PgrlsTestConfigError');
  });
});

describe('catch-via-base', () => {
  it('PgrlsTestAssertionError caught as PgrlsTestError', () => {
    expect(() => {
      throw new PgrlsTestAssertionError('from assertion');
    }).toThrow(PgrlsTestError);
  });

  it('PgrlsTestConfigError caught as PgrlsTestError', () => {
    expect(() => {
      throw new PgrlsTestConfigError('from config');
    }).toThrow(PgrlsTestError);
  });

  it('catching as Error also works (universal fallback)', () => {
    expect(() => {
      throw new PgrlsTestAssertionError('boom');
    }).toThrow(Error);
  });
});
