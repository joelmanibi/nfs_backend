'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

const { loadVaultSecrets } = require('../config/vault');

const ENV_KEYS = [
  'VAULT_ENABLED',
  'VAULT_ADDR',
  'VAULT_TOKEN',
  'VAULT_ROLE_ID',
  'VAULT_SECRET_ID',
  'VAULT_SECRET_PATH',
  'VAULT_KV_VERSION',
  'VAULT_NAMESPACE',
  'VAULT_OVERRIDE_EXISTING',
  'VAULT_FAIL_ON_ERROR',
  'TEST_VAULT_SECRET',
];

const snapshotEnv = () => Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));

const restoreEnv = (snapshot) => {
  for (const key of ENV_KEYS) {
    if (snapshot[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = snapshot[key];
    }
  }
};

const withServer = async (handler, callback) => {
  const server = http.createServer(handler);

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const address = server.address();
    return await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
};

test('loadVaultSecrets returns env mode when vault is disabled', async () => {
  const snapshot = snapshotEnv();
  delete process.env.VAULT_ENABLED;

  const result = await loadVaultSecrets();
  restoreEnv(snapshot);

  assert.equal(result.enabled, false);
  assert.equal(result.source, 'env');
});

test('loadVaultSecrets falls back to env when vault config is incomplete', async () => {
  const snapshot = snapshotEnv();
  process.env.VAULT_ENABLED = 'true';
  process.env.VAULT_FAIL_ON_ERROR = 'false';
  delete process.env.VAULT_ADDR;
  delete process.env.VAULT_TOKEN;
  delete process.env.VAULT_SECRET_PATH;

  const result = await loadVaultSecrets();
  restoreEnv(snapshot);

  assert.equal(result.enabled, true);
  assert.equal(result.fallback, true);
  assert.equal(result.source, 'env');
  assert.match(result.reason, /configuration incomplète/i);
});

test('loadVaultSecrets throws when failOnError is enabled', async () => {
  const snapshot = snapshotEnv();
  process.env.VAULT_ENABLED = 'true';
  process.env.VAULT_FAIL_ON_ERROR = 'true';
  delete process.env.VAULT_ADDR;
  delete process.env.VAULT_TOKEN;
  delete process.env.VAULT_SECRET_PATH;

  await assert.rejects(() => loadVaultSecrets(), /configuration incomplète/i);
  restoreEnv(snapshot);
});

test('loadVaultSecrets supports AppRole authentication and KV v2 paths', async () => {
  const snapshot = snapshotEnv();
  const requests = [];

  await withServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });

    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body: raw });

      if (req.method === 'POST' && req.url === '/v1/auth/approle/login') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ auth: { client_token: 'approle-test-token' } }));
        return;
      }

      if (req.method === 'GET' && req.url === '/v1/secret/data/app/config') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: { data: { TEST_VAULT_SECRET: 'loaded-from-vault' } } }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ errors: ['not found'] }));
    });
  }, async (addr) => {
    process.env.VAULT_ENABLED = 'true';
    process.env.VAULT_FAIL_ON_ERROR = 'true';
    process.env.VAULT_ADDR = addr;
    delete process.env.VAULT_TOKEN;
    process.env.VAULT_ROLE_ID = 'test-role-id';
    process.env.VAULT_SECRET_ID = 'test-secret-id';
    process.env.VAULT_SECRET_PATH = 'secret/app/config';
    process.env.VAULT_KV_VERSION = '2';
    delete process.env.TEST_VAULT_SECRET;

    const result = await loadVaultSecrets();

    assert.equal(result.enabled, true);
    assert.equal(result.source, 'vault');
    assert.equal(process.env.TEST_VAULT_SECRET, 'loaded-from-vault');
    assert.equal(requests.length, 2);
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].url, '/v1/auth/approle/login');
    assert.match(requests[0].body, /role_id/);
    assert.match(requests[0].body, /secret_id/);
    assert.equal(requests[1].method, 'GET');
    assert.equal(requests[1].url, '/v1/secret/data/app/config');
    assert.equal(requests[1].headers['x-vault-token'], 'approle-test-token');
  });

  restoreEnv(snapshot);
});

test('loadVaultSecrets keeps direct token mode compatible', async () => {
  const snapshot = snapshotEnv();
  const requests = [];

  await withServer((req, res) => {
    requests.push({ method: req.method, url: req.url, headers: req.headers });

    if (req.method === 'GET' && req.url === '/v1/secret/data/app/config') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { data: { TEST_VAULT_SECRET: 'loaded-with-token' } } }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ errors: ['not found'] }));
  }, async (addr) => {
    process.env.VAULT_ENABLED = 'true';
    process.env.VAULT_FAIL_ON_ERROR = 'true';
    process.env.VAULT_ADDR = addr;
    process.env.VAULT_TOKEN = 'direct-token';
    delete process.env.VAULT_ROLE_ID;
    delete process.env.VAULT_SECRET_ID;
    process.env.VAULT_SECRET_PATH = 'secret/app/config';
    process.env.VAULT_KV_VERSION = '2';
    delete process.env.TEST_VAULT_SECRET;

    const result = await loadVaultSecrets();

    assert.equal(result.enabled, true);
    assert.equal(result.source, 'vault');
    assert.equal(process.env.TEST_VAULT_SECRET, 'loaded-with-token');
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'GET');
    assert.equal(requests[0].url, '/v1/secret/data/app/config');
    assert.equal(requests[0].headers['x-vault-token'], 'direct-token');
  });

  restoreEnv(snapshot);
});