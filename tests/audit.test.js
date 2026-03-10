'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildRequestAuditMeta, normalizeEmail } = require('../helpers/audit');

test('normalizeEmail trims and lowercases emails', () => {
  assert.equal(normalizeEmail('  USER@Example.COM '), 'user@example.com');
  assert.equal(normalizeEmail(''), undefined);
  assert.equal(normalizeEmail(null), undefined);
});

test('buildRequestAuditMeta extracts request context safely', () => {
  const req = {
    ip: '127.0.0.1',
    user: {
      id: 'user-1',
      email: 'ADMIN@Example.COM',
    },
    get(header) {
      if (header === 'user-agent') return 'node-test';
      return undefined;
    },
  };

  const meta = buildRequestAuditMeta(req, { event: 'sample_event' });

  assert.deepEqual(meta, {
    userId: 'user-1',
    userEmail: 'admin@example.com',
    ip: '127.0.0.1',
    userAgent: 'node-test',
    event: 'sample_event',
  });
});