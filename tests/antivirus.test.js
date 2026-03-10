'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { parseScanResponse, scanBuffer } = require('../helpers/antivirus');

test('parseScanResponse identifies clean files', () => {
  const result = parseScanResponse('stream: OK\0');

  assert.equal(result.status, 'clean');
  assert.equal(result.rawResponse, 'stream: OK');
});

test('parseScanResponse identifies infected files', () => {
  const result = parseScanResponse('stream: Eicar-Test-Signature FOUND\0');

  assert.equal(result.status, 'infected');
  assert.equal(result.threat, 'Eicar-Test-Signature');
});

test('scanBuffer skips scan when antivirus is disabled', async () => {
  const previous = process.env.ANTIVIRUS_ENABLED;
  delete process.env.ANTIVIRUS_ENABLED;

  const result = await scanBuffer(Buffer.from('hello'));

  if (previous === undefined) {
    delete process.env.ANTIVIRUS_ENABLED;
  } else {
    process.env.ANTIVIRUS_ENABLED = previous;
  }

  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'disabled');
});