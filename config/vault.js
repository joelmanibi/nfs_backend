'use strict';

require('dotenv').config();

const http = require('http');
const https = require('https');
const logger = require('./logger');

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);

const asBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null || value === '') return defaultValue;
  return TRUE_VALUES.has(String(value).toLowerCase());
};

const isVaultEnabled = () => asBoolean(process.env.VAULT_ENABLED, false);

const getVaultConfig = () => ({
  addr: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN,
  roleId: process.env.VAULT_ROLE_ID,
  secretId: process.env.VAULT_SECRET_ID,
  namespace: process.env.VAULT_NAMESPACE,
  secretPath: (process.env.VAULT_SECRET_PATH || '').replace(/^\/+/, ''),
  kvVersion: String(process.env.VAULT_KV_VERSION || '2'),
  skipTlsVerify: asBoolean(process.env.VAULT_SKIP_TLS_VERIFY, false),
  overrideExisting: asBoolean(process.env.VAULT_OVERRIDE_EXISTING, true),
  failOnError: asBoolean(process.env.VAULT_FAIL_ON_ERROR, false),
});

const ensureVaultConfig = (config) => {
  const missing = [];

  if (!config.addr) missing.push('VAULT_ADDR');
  if (!config.secretPath) missing.push('VAULT_SECRET_PATH');
  if (!config.token && !(config.roleId && config.secretId)) {
    missing.push('VAULT_TOKEN ou VAULT_ROLE_ID + VAULT_SECRET_ID');
  }

  if (missing.length > 0) {
    throw new Error(`Vault activé mais configuration incomplète : ${missing.join(', ')}`);
  }
};

const requestJson = (url, { headers = {}, method = 'GET', body, skipTlsVerify = false } = {}) => {
  const transport = url.protocol === 'http:' ? http : https;
  const options = {
    method,
    headers,
  };

  if (url.protocol === 'https:' && skipTlsVerify) {
    options.agent = new https.Agent({ rejectUnauthorized: false });
  }

  return new Promise((resolve, reject) => {
    const req = transport.request(url, options, (res) => {
      let raw = '';

      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        raw += chunk;
      });
      res.on('end', () => {
        let payload = {};

        if (raw) {
          try {
            payload = JSON.parse(raw);
          } catch (error) {
            reject(new Error(`Réponse Vault invalide (JSON attendu) : ${error.message}`));
            return;
          }
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          const details = Array.isArray(payload.errors) ? payload.errors.join(', ') : raw;
          reject(new Error(`Vault a répondu ${res.statusCode} ${res.statusMessage}: ${details}`));
          return;
        }

        resolve(payload);
      });
    });

    req.on('error', (error) => {
      reject(new Error(`Impossible de joindre Vault : ${error.message}`));
    });

    if (body !== undefined) {
      req.write(JSON.stringify(body));
    }

    req.end();
  });
};

const normalizeSecretValue = (value) => {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'string') return value;
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

const extractSecrets = (payload, kvVersion) => {
  if (kvVersion === '1') return payload.data;
  return payload.data && payload.data.data;
};

const buildSecretApiPath = (secretPath, kvVersion) => {
  const normalizedPath = String(secretPath || '').replace(/^\/+/, '');
  if (!normalizedPath) return '/v1/';
  if (kvVersion !== '2') return `/v1/${normalizedPath}`;

  const parts = normalizedPath.split('/').filter(Boolean);
  if (parts[1] === 'data') {
    return `/v1/${parts.join('/')}`;
  }

  if (parts.length === 1) {
    return `/v1/${parts[0]}/data`;
  }

  return `/v1/${parts[0]}/data/${parts.slice(1).join('/')}`;
};

const buildVaultHeaders = (config, token) => {
  const headers = {};

  if (token) {
    headers['X-Vault-Token'] = token;
  }

  if (config.namespace) {
    headers['X-Vault-Namespace'] = config.namespace;
  }

  return headers;
};

const resolveVaultToken = async (config) => {
  if (config.token) {
    return config.token;
  }

  const loginUrl = new URL(
    '/v1/auth/approle/login',
    config.addr.endsWith('/') ? config.addr : `${config.addr}/`,
  );

  const payload = await requestJson(loginUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...buildVaultHeaders(config),
    },
    body: {
      role_id: config.roleId,
      secret_id: config.secretId,
    },
    skipTlsVerify: config.skipTlsVerify,
  });

  const token = payload && payload.auth && payload.auth.client_token;
  if (!token) {
    throw new Error('Vault AppRole n’a pas retourné de token exploitable.');
  }

  return token;
};

const fallbackToEnvironment = (config, error) => {
  logger.warn('Vault indisponible, utilisation des variables d’environnement existantes.', {
    event: 'vault_fallback_to_env',
    secretPath: config.secretPath || null,
    vaultAddr: config.addr || null,
    reason: error.message,
    failOnError: config.failOnError,
  });

  return {
    enabled: true,
    loadedKeys: [],
    secretPath: config.secretPath || null,
    fallback: true,
    source: 'env',
    reason: error.message,
  };
};

async function loadVaultSecrets() {
  if (!isVaultEnabled()) {
    return { enabled: false, loadedKeys: [], source: 'env' };
  }

  const config = getVaultConfig();

  try {
    ensureVaultConfig(config);

    const token = await resolveVaultToken(config);
    const secretApiPath = buildSecretApiPath(config.secretPath, config.kvVersion);
    const url = new URL(secretApiPath, config.addr.endsWith('/') ? config.addr : `${config.addr}/`);
    const payload = await requestJson(url, {
      headers: buildVaultHeaders(config, token),
      skipTlsVerify: config.skipTlsVerify,
    });
    const secrets = extractSecrets(payload, config.kvVersion);

    if (!secrets || typeof secrets !== 'object') {
      throw new Error(`Aucun secret exploitable trouvé dans Vault au chemin ${config.secretPath}`);
    }

    const loadedKeys = [];

    for (const [key, value] of Object.entries(secrets)) {
      if (!config.overrideExisting && process.env[key] !== undefined) {
        continue;
      }

      const normalized = normalizeSecretValue(value);
      if (normalized === undefined) continue;

      process.env[key] = normalized;
      loadedKeys.push(key);
    }

    logger.info('Secrets Vault chargés avec succès.', {
      event: 'vault_secrets_loaded',
      secretPath: config.secretPath,
      loadedKeyCount: loadedKeys.length,
    });

    return {
      enabled: true,
      loadedKeys,
      secretPath: config.secretPath,
      fallback: false,
      source: 'vault',
    };
  } catch (error) {
    if (config.failOnError) {
      throw error;
    }

    return fallbackToEnvironment(config, error);
  }
}

module.exports = {
  isVaultEnabled,
  loadVaultSecrets,
};