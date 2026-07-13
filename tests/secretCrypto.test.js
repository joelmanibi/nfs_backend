'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { encryptSecret, decryptSecret } = require('../helpers/secretCrypto');

test('encryptSecret and decryptSecret round-trip values', () => {
  const previous = process.env.FILE_ENCRYPTION_KEY;
  process.env.FILE_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  const encrypted = encryptSecret('super-secret-value');
  const decrypted = decryptSecret(encrypted);

  assert.notEqual(encrypted, 'super-secret-value');
  assert.equal(decrypted, 'super-secret-value');

  if (previous === undefined) delete process.env.FILE_ENCRYPTION_KEY;
  else process.env.FILE_ENCRYPTION_KEY = previous;
});