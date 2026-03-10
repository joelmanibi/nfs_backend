'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { loadVaultSecrets } = require('../config/vault');

const ENV_KEYS = [
  'VAULT_ENABLED',
  'VAULT_ADDR',
  'VAULT_TOKEN',
  'VAULT_SECRET_PATH',
  'VAULT_FAIL_ON_ERROR',
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