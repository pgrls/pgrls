/**
 * Unit tests for `pgrls-test`'s identifier-quoting helpers.
 *
 * Mirrors the Python tests in `tests/test_fixers.py` (the
 * `quote_ident` cluster) plus the cross-language conformance
 * pin: the Python and TS implementations MUST produce identical
 * output for every input. The reserved-keyword set, the
 * doubled-quote escaping rule, and the "plain identifier" regex
 * are all part of the byte-for-byte protocol.
 */
import { describe, expect, it } from 'vitest';

import { quoteIdent, quoteQualified, RESERVED_KEYWORDS } from '../src/index.js';

describe('quoteIdent — plain identifiers (no quoting needed)', () => {
  it('lowercase snake_case: returned verbatim', () => {
    expect(quoteIdent('users')).toBe('users');
    expect(quoteIdent('user_id')).toBe('user_id');
    expect(quoteIdent('app_authenticated')).toBe('app_authenticated');
  });

  it('underscore prefix is allowed', () => {
    expect(quoteIdent('_internal')).toBe('_internal');
    expect(quoteIdent('_')).toBe('_');
  });

  it('digits after the first char are allowed', () => {
    expect(quoteIdent('users_v2')).toBe('users_v2');
    expect(quoteIdent('a1b2c3')).toBe('a1b2c3');
  });
});

describe('quoteIdent — needs quoting', () => {
  it('mixed case forces quoting', () => {
    expect(quoteIdent('Users')).toBe('"Users"');
    expect(quoteIdent('MixedCase Table')).toBe('"MixedCase Table"');
  });

  it('embedded space forces quoting', () => {
    expect(quoteIdent('weird name')).toBe('"weird name"');
  });

  it('embedded dot forces quoting (qualified-style names in a single string)', () => {
    expect(quoteIdent('schema.table')).toBe('"schema.table"');
  });

  it('leading digit forces quoting', () => {
    expect(quoteIdent('1table')).toBe('"1table"');
  });

  it('non-ASCII characters force quoting', () => {
    expect(quoteIdent('résumé')).toBe('"résumé"');
    expect(quoteIdent('日本語')).toBe('"日本語"');
  });

  it('embedded double-quote is escaped by doubling', () => {
    expect(quoteIdent('he"llo')).toBe('"he""llo"');
  });

  it('all special characters together stay round-trippable', () => {
    // Pgls-relevant pathological case: a name with multiple
    // reasons-to-quote at once. Pin the precise output so
    // future refactors can't drift the escaping.
    expect(quoteIdent('Weird "Name" 1')).toBe('"Weird ""Name"" 1"');
  });
});

describe('quoteIdent — reserved keywords (case-insensitive)', () => {
  it('lowercase reserved keyword is quoted', () => {
    expect(quoteIdent('select')).toBe('"select"');
    expect(quoteIdent('order')).toBe('"order"');
    expect(quoteIdent('user')).toBe('"user"');
  });

  it('uppercase reserved keyword is quoted, case preserved', () => {
    expect(quoteIdent('SELECT')).toBe('"SELECT"');
    expect(quoteIdent('Select')).toBe('"Select"');
  });

  it('every keyword in the set round-trips through quoting', () => {
    for (const kw of RESERVED_KEYWORDS) {
      const out = quoteIdent(kw);
      expect(out.startsWith('"')).toBe(true);
      expect(out.endsWith('"')).toBe(true);
      // Inner content matches the input verbatim (no escaping
      // needed because reserved keywords don't contain `"`).
      expect(out.slice(1, -1)).toBe(kw);
    }
  });

  it('non-reserved type-ish words are NOT quoted', () => {
    // Per the design comment in the Python source: type-context-
    // only reserved (e.g. `bigint`, `numeric`) parse as
    // identifiers in non-type position, so we don't quote them.
    expect(quoteIdent('bigint')).toBe('bigint');
    expect(quoteIdent('numeric')).toBe('numeric');
    expect(quoteIdent('text')).toBe('text');
  });
});

describe('quoteIdent — rejection paths', () => {
  it('throws on empty string', () => {
    expect(() => quoteIdent('')).toThrow(/empty/);
  });

  it('throws on null byte', () => {
    expect(() => quoteIdent('evil\x00name')).toThrow(/control character/);
  });

  it('throws on embedded newline', () => {
    expect(() => quoteIdent('name\nwith\nnewlines')).toThrow(/control character/);
  });

  it('throws on embedded carriage return', () => {
    expect(() => quoteIdent('name\rwith\rcr')).toThrow(/control character/);
  });

  it('throws on embedded tab', () => {
    expect(() => quoteIdent('weird\tname')).toThrow(/control character/);
  });

  it('throws on every C0 control character', () => {
    for (let i = 0; i <= 0x1f; i++) {
      const ch = String.fromCharCode(i);
      expect(() => quoteIdent(`a${ch}b`), `expected reject for charCode ${i}`).toThrow(
        /control character/,
      );
    }
  });

  it('throws on DEL (0x7f)', () => {
    expect(() => quoteIdent('a\x7fb')).toThrow(/control character/);
  });
});

describe('quoteQualified', () => {
  it('combines plain schema + plain name with a single dot', () => {
    expect(quoteQualified('public', 'users')).toBe('public.users');
  });

  it('quotes only the components that need it', () => {
    expect(quoteQualified('app', 'MixedCase Table')).toBe('app."MixedCase Table"');
    expect(quoteQualified('Schema', 'users')).toBe('"Schema".users');
  });

  it('quotes both when both need it', () => {
    expect(quoteQualified('Weird Schema', 'select')).toBe('"Weird Schema"."select"');
  });

  it('throws when either component is empty', () => {
    expect(() => quoteQualified('', 'users')).toThrow(/empty/);
    expect(() => quoteQualified('public', '')).toThrow(/empty/);
  });

  it('throws when either component has a control character', () => {
    expect(() => quoteQualified('a\x00b', 'users')).toThrow(/control/);
    expect(() => quoteQualified('public', 'a\x00b')).toThrow(/control/);
  });
});

describe('RESERVED_KEYWORDS — protocol invariant', () => {
  // The reserved-keyword set is part of the cross-language
  // protocol contract. Pin its size + a few sentinel members so
  // a future patch that adds or removes a keyword has to update
  // the test loudly (and, by extension, the Python copy).
  it('contains exactly 78 keywords (matches Python)', () => {
    // Verified against `pgrls.fixers._idents._RESERVED_KEYWORDS`
    // — the cross-language contract requires the sets be
    // identical. Updating one without the other would silently
    // produce different SQL on the two clients.
    expect(RESERVED_KEYWORDS.size).toBe(78);
  });

  it('contains the high-traffic SQL words', () => {
    for (const kw of [
      'select',
      'from',
      'where',
      'order',
      'group',
      'having',
      'union',
      'all',
      'and',
      'or',
      'not',
      'null',
      'true',
      'false',
      'create',
      'table',
      'primary',
      'foreign',
      'check',
      'default',
      'user',
      'current_user',
    ]) {
      expect(RESERVED_KEYWORDS.has(kw), `expected "${kw}" in RESERVED_KEYWORDS`).toBe(
        true,
      );
    }
  });

  it('does NOT contain type-context-only reserved words', () => {
    // These parse as identifiers in non-type position.
    for (const word of ['bigint', 'numeric', 'text', 'integer']) {
      expect(
        RESERVED_KEYWORDS.has(word),
        `did not expect "${word}" in RESERVED_KEYWORDS`,
      ).toBe(false);
    }
  });
});
