/**
 * Scaffold sanity test — confirms the test runner is wired up
 * and the public surface re-exports `PROTOCOL_VERSION`. As the
 * port progresses, real per-module tests replace this one.
 */
import { describe, expect, it } from 'vitest';

import { PROTOCOL_VERSION } from '../src/index.js';

describe('scaffold', () => {
  it('exports PROTOCOL_VERSION = 1', () => {
    expect(PROTOCOL_VERSION).toBe(1);
  });
});
