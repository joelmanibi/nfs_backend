'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');

const { encryptSecret } = require('../helpers/secretCrypto');
const {
  buildHttpClient,
  buildHttpCollectionUrl,
} = require('../helpers/collectionExecution');

test('buildHttpCollectionUrl builds an API URL with query parameters', () => {
  const url = buildHttpCollectionUrl({
    protocol: 'HTTPS',
    host: 'api.paa.local',
    port: 443,
    sourceDirectory: '/exports/files',
    requestQuery: 'scope=finance&format=zip',
  });

  assert.equal(url, 'https://api.paa.local/exports/files?scope=finance&format=zip');
});

test('buildHttpClient downloads a file from a parameterized HTTP API with POST and custom headers', async (t) => {
  const previousKey = process.env.FILE_ENCRYPTION_KEY;
  process.env.FILE_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  t.after(() => {
    process.env.FILE_ENCRYPTION_KEY = previousKey;
  });

  let receivedAuthHeader = null;
  let receivedApiKey = null;
  let receivedMethod = null;
  let receivedBody = null;

  const server = http.createServer((req, res) => {
    receivedMethod = req.method;
    receivedAuthHeader = req.headers.authorization || null;
    receivedApiKey = req.headers['x-api-key'] || null;
    assert.equal(req.url, '/api/export?scope=finance&format=zip');

    const chunks = [];
    req.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    req.on('end', () => {
      receivedBody = Buffer.concat(chunks).toString();

      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Disposition': 'attachment; filename="finance_export.zip"',
        'Last-Modified': 'Tue, 16 Jun 2026 10:45:00 GMT',
      });
      res.end(Buffer.from('zip-content'));
    });
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());

  const { port } = server.address();
  const client = await buildHttpClient({
    protocol: 'HTTP',
    host: '127.0.0.1',
    port,
    username: 'collector',
    encryptedPassword: encryptSecret('secret-pass'),
    httpMethod: 'POST',
    httpHeaders: encryptSecret('{"X-API-Key":"paa-secret"}'),
    httpBody: encryptSecret('{"scope":"finance","format":"zip"}'),
    httpResponseMode: 'SINGLE_FILE',
    requestQuery: 'scope=finance&format=zip',
    sourceDirectory: '/api/export',
    name: 'Collecte Finance',
  });

  const files = await client.listFiles('/api/export');
  assert.equal(files.length, 1);
  assert.equal(files[0].name, 'finance_export.zip');
  assert.equal(files[0].size, Buffer.byteLength('zip-content'));

  const buffer = await client.downloadBuffer(files[0].remotePath);
  assert.equal(buffer.toString(), 'zip-content');
  assert.equal(receivedMethod, 'POST');
  assert.match(receivedAuthHeader, /^Basic /);
  assert.equal(receivedApiKey, 'paa-secret');
  assert.equal(receivedBody, '{"scope":"finance","format":"zip"}');

  await client.close();
});

test('buildHttpClient supports FILE_LIST responses and downloads each file URL', async (t) => {
  const previousKey = process.env.FILE_ENCRYPTION_KEY;
  process.env.FILE_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  t.after(() => {
    process.env.FILE_ENCRYPTION_KEY = previousKey;
  });

  const requestedUrls = [];
  const requestedAuthHeaders = [];

  const server = http.createServer((req, res) => {
    requestedUrls.push(req.url);
    requestedAuthHeaders.push(req.headers.authorization || null);

    if (req.url === '/api/list') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        files: [
          { name: 'report-a.csv', url: '/files/report-a.csv', modifiedAt: '2026-06-18T10:00:00Z' },
          { name: 'report-b.csv', url: '/files/report-b.csv', modifiedAt: '2026-06-18T11:00:00Z' },
        ],
      }));
      return;
    }

    if (req.url === '/files/report-a.csv') {
      res.writeHead(200, { 'Content-Type': 'text/csv' });
      res.end('a,1');
      return;
    }

    if (req.url === '/files/report-b.csv') {
      res.writeHead(200, { 'Content-Type': 'text/csv' });
      res.end('b,2');
      return;
    }

    res.writeHead(404);
    res.end();
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());

  const { port } = server.address();
  const client = await buildHttpClient({
    protocol: 'HTTP',
    host: '127.0.0.1',
    port,
    username: 'collector',
    encryptedPassword: encryptSecret('secret-pass'),
    httpMethod: 'GET',
    httpResponseMode: 'FILE_LIST',
    sourceDirectory: '/api/list',
    name: 'Collecte Multi Fichiers',
  });

  const files = await client.listFiles('/api/list');
  assert.equal(files.length, 2);
  assert.equal(files[0].name, 'report-a.csv');
  assert.equal(files[1].name, 'report-b.csv');

  const firstBuffer = await client.downloadBuffer(files[0].remotePath);
  const secondBuffer = await client.downloadBuffer(files[1].remotePath);
  assert.equal(firstBuffer.toString(), 'a,1');
  assert.equal(secondBuffer.toString(), 'b,2');
  assert.deepEqual(requestedUrls, ['/api/list', '/files/report-a.csv', '/files/report-b.csv']);
  assert.equal(requestedAuthHeaders.length, 3);
  requestedAuthHeaders.forEach((header) => assert.match(header, /^Basic /));

  await client.close();
});