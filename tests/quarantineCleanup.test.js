'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { isQuarantineFileStale } = require('../helpers/quarantineCleanup');

test('isQuarantineFileStale flags files older than the TTL', () => {
  const now = Date.parse('2026-07-08T12:00:00Z');
  const ttlMs = 60 * 60 * 1000; // 1h

  const staleMtime = now - ttlMs - 1000; // 1h + 1s old
  const freshMtime = now - ttlMs + 1000; // just under 1h old

  assert.equal(isQuarantineFileStale(staleMtime, ttlMs, now), true);
  assert.equal(isQuarantineFileStale(freshMtime, ttlMs, now), false);
});

test('isQuarantineFileStale is false exactly at the TTL boundary', () => {
  const now = 1_000_000;
  const ttlMs = 500;

  assert.equal(isQuarantineFileStale(now - ttlMs, ttlMs, now), false);
});
