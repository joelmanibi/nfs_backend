'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

const { loadVaultSecrets } = require('../config/vault');
const { assertCriticalSecrets, getJwtSecret } = require('../config/secrets');
const config = require('../config');

const ENV_KEYS = [
  'NODE_ENV', 'VAULT_ENABLED', 'VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_ROLE_ID', 'VAULT_SECRET_ID',
  'VAULT_SECRET_PATH', 'VAULT_KV_VERSION', 'VAULT_OVERRIDE_EXISTING', 'VAULT_FAIL_ON_ERROR',
  'FILE_ENCRYPTION_KEY', 'JWT_SECRET', 'SECRET_CONFIG', 'SMTP_HOST',
];

const withEnv = async (fn) => {
  const snapshot = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  try {
    return await fn();
  } finally {
    for (const k of ENV_KEYS) {
      if (snapshot[k] === undefined) delete process.env[k];
      else process.env[k] = snapshot[k];
    }
  }
};

const VAULT_FILE_KEY = 'a'.repeat(64);
const VAULT_JWT = 'jwt-from-vault-'.padEnd(48, 'x');

// Faux Vault : login AppRole + secret KV v2 au chemin de la prod
const withFakeVault = async (secrets, callback) => {
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'POST' && req.url === '/v1/auth/approle/login') {
      res.end(JSON.stringify({ auth: { client_token: 't' } }));
    } else if (req.method === 'GET' && req.url === '/v1/secret/data/mft-backend/production') {
      res.end(JSON.stringify({ data: { data: secrets } }));
    } else {
      res.statusCode = 404;
      res.end(JSON.stringify({ errors: ['not found'] }));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await callback(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

const useVault = (addr) => {
  process.env.VAULT_ENABLED = 'true';
  process.env.VAULT_FAIL_ON_ERROR = 'true';
  process.env.VAULT_ADDR = addr;
  delete process.env.VAULT_TOKEN;
  process.env.VAULT_ROLE_ID = 'role';
  process.env.VAULT_SECRET_ID = 'secret';
  process.env.VAULT_SECRET_PATH = 'secret/mft-backend/production';
  process.env.VAULT_KV_VERSION = '2';
  process.env.VAULT_OVERRIDE_EXISTING = 'false';
};

test('Vault overrides critical keys left in .env even with VAULT_OVERRIDE_EXISTING=false', () => withEnv(() =>
  withFakeVault({ FILE_ENCRYPTION_KEY: VAULT_FILE_KEY, JWT_SECRET: VAULT_JWT, SMTP_HOST: 'vault-smtp' }, async (addr) => {
    useVault(addr);
    process.env.FILE_ENCRYPTION_KEY = 'b'.repeat(64); // ancienne valeur du .env
    process.env.JWT_SECRET = 'old-env-jwt';
    process.env.SMTP_HOST = 'env-smtp';

    const result = await loadVaultSecrets();

    assert.equal(result.source, 'vault');
    assert.equal(process.env.FILE_ENCRYPTION_KEY, VAULT_FILE_KEY);
    assert.equal(process.env.JWT_SECRET, VAULT_JWT);
    // Clé non critique : le .env garde la main (VAULT_OVERRIDE_EXISTING=false)
    assert.equal(process.env.SMTP_HOST, 'env-smtp');
  })));

test('SECRET_CONFIG from Vault becomes the JWT secret', () => withEnv(() =>
  withFakeVault({ FILE_ENCRYPTION_KEY: VAULT_FILE_KEY, SECRET_CONFIG: VAULT_JWT }, async (addr) => {
    useVault(addr);
    delete process.env.JWT_SECRET;
    process.env.NODE_ENV = 'production';

    await loadVaultSecrets();

    assert.equal(process.env.JWT_SECRET, VAULT_JWT);
    assert.equal(getJwtSecret(), VAULT_JWT);
  })));

test('config.jwt.secret is read at use time, after Vault injection', () => withEnv(() => {
  process.env.JWT_SECRET = 'first-value';
  assert.equal(config.jwt.secret, 'first-value');
  process.env.JWT_SECRET = 'injected-later-by-vault';
  assert.equal(config.jwt.secret, 'injected-later-by-vault');
}));

test('no default JWT secret in production', () => withEnv(() => {
  process.env.NODE_ENV = 'production';
  delete process.env.JWT_SECRET;
  delete process.env.SECRET_CONFIG;
  assert.equal(getJwtSecret(), undefined);
}));

test('assertCriticalSecrets blocks startup in production when a key is missing or weak', () => withEnv(() => {
  process.env.NODE_ENV = 'production';
  process.env.FILE_ENCRYPTION_KEY = VAULT_FILE_KEY;
  delete process.env.SECRET_CONFIG;

  process.env.JWT_SECRET = 'your_super_secret_jwt_key';
  assert.throws(() => assertCriticalSecrets({ processName: 'api' }), /clé JWT trop faible/);

  delete process.env.JWT_SECRET;
  assert.throws(() => assertCriticalSecrets({ processName: 'api' }), /clé JWT absente/);

  process.env.JWT_SECRET = VAULT_JWT;
  process.env.FILE_ENCRYPTION_KEY = 'short';
  assert.throws(() => assertCriticalSecrets({ processName: 'api' }), /FILE_ENCRYPTION_KEY/);

  // Le worker n'a pas besoin de la clé JWT
  process.env.FILE_ENCRYPTION_KEY = VAULT_FILE_KEY;
  delete process.env.JWT_SECRET;
  assert.doesNotThrow(() => assertCriticalSecrets({ processName: 'worker', requireJwt: false }));

  process.env.JWT_SECRET = VAULT_JWT;
  assert.doesNotThrow(() => assertCriticalSecrets({ processName: 'api' }));
}));

test('assertCriticalSecrets only warns outside production', () => withEnv(() => {
  process.env.NODE_ENV = 'development';
  delete process.env.FILE_ENCRYPTION_KEY;
  delete process.env.JWT_SECRET;
  delete process.env.SECRET_CONFIG;
  assert.doesNotThrow(() => assertCriticalSecrets({ processName: 'api' }));
}));
