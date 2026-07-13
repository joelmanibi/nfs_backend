'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const path = require('node:path');
const { once } = require('node:events');

const { parseScanResponse, scanBuffer, scanPath, QUARANTINE_DIR } = require('../helpers/antivirus');

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

test('scanPath skips scan when antivirus is disabled', async () => {
  const previous = process.env.ANTIVIRUS_ENABLED;
  delete process.env.ANTIVIRUS_ENABLED;

  const result = await scanPath(path.join(QUARANTINE_DIR, 'whatever.bin'));

  if (previous === undefined) {
    delete process.env.ANTIVIRUS_ENABLED;
  } else {
    process.env.ANTIVIRUS_ENABLED = previous;
  }

  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'disabled');
});

test('scanPath refuses paths outside the quarantine directory', async (t) => {
  const previous = process.env.ANTIVIRUS_ENABLED;
  process.env.ANTIVIRUS_ENABLED = 'true';
  t.after(() => {
    if (previous === undefined) delete process.env.ANTIVIRUS_ENABLED;
    else process.env.ANTIVIRUS_ENABLED = previous;
  });

  const result = await scanPath(path.resolve('outside-quarantine.bin'));

  assert.equal(result.status, 'error');
  assert.match(result.error, /quarantaine/);
});

test('scanPath sends a zSCAN command and parses the clamd response', async (t) => {
  const filePath = path.join(QUARANTINE_DIR, 'fake-clamd-test.bin');
  let receivedCommand = '';

  const server = net.createServer((socket) => {
    socket.on('data', (chunk) => {
      receivedCommand += chunk.toString();
      if (receivedCommand.includes('\0')) {
        socket.end(`${filePath}: OK\0`);
      }
    });
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());

  const { port } = server.address();
  const previousEnabled = process.env.ANTIVIRUS_ENABLED;
  const previousHost    = process.env.ANTIVIRUS_HOST;
  const previousPort    = process.env.ANTIVIRUS_PORT;

  process.env.ANTIVIRUS_ENABLED = 'true';
  process.env.ANTIVIRUS_HOST    = '127.0.0.1';
  process.env.ANTIVIRUS_PORT    = String(port);

  t.after(() => {
    if (previousEnabled === undefined) delete process.env.ANTIVIRUS_ENABLED; else process.env.ANTIVIRUS_ENABLED = previousEnabled;
    if (previousHost === undefined) delete process.env.ANTIVIRUS_HOST; else process.env.ANTIVIRUS_HOST = previousHost;
    if (previousPort === undefined) delete process.env.ANTIVIRUS_PORT; else process.env.ANTIVIRUS_PORT = previousPort;
  });

  const result = await scanPath(filePath);

  assert.equal(result.status, 'clean');
  assert.equal(receivedCommand.startsWith('zSCAN '), true);
});