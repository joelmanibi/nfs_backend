'use strict';

const crypto = require('crypto');

/**
 * Secrets critiques de l'application, fournis par Vault en production :
 *  - FILE_ENCRYPTION_KEY : clé AES-256 des fichiers (64 caractères hex)
 *  - JWT_SECRET (ou son alias SECRET_CONFIG) : clé de signature des sessions
 *
 * Ces valeurs sont lues À CHAQUE UTILISATION (jamais figées au chargement d'un
 * module), car Vault les injecte dans process.env après le démarrage du
 * process. Ce module ne dépend pas du logger (évite une dépendance circulaire
 * config/index ↔ config/logger).
 */

const CRITICAL_KEYS = ['FILE_ENCRYPTION_KEY', 'JWT_SECRET', 'SECRET_CONFIG'];
const DEV_DEFAULT_JWT_SECRET = 'your_super_secret_jwt_key';
const MIN_JWT_SECRET_LENGTH = 32;

const isProduction = () => process.env.NODE_ENV === 'production';

/** Clé JWT courante. Jamais de valeur par défaut en production. */
const getJwtSecret = () => process.env.JWT_SECRET
  || process.env.SECRET_CONFIG
  || (isProduction() ? undefined : DEV_DEFAULT_JWT_SECRET);

/**
 * Empreinte courte (SHA-256 tronqué) d'un secret : permet de vérifier dans les
 * journaux que l'API et le worker utilisent bien la même clé, sans l'exposer.
 */
const fingerprint = (value) => (value
  ? crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 12)
  : null);

/**
 * Vérifie les secrets critiques après le chargement de Vault.
 * En production : lève une erreur (arrêt du démarrage) si un secret manque ou
 * est invalide. En développement : se contente d'un avertissement.
 *
 * @param {object}  opts
 * @param {string}  opts.processName  'api' | 'worker'
 * @param {boolean} [opts.requireJwt] le process signe/vérifie-t-il des JWT ?
 * @param {object}  [opts.vault]      résultat de loadVaultSecrets()
 */
const assertCriticalSecrets = ({ processName, requireJwt = true, vault = null }) => {
  const logger = require('./logger');
  const problems = [];

  const fileKey = process.env.FILE_ENCRYPTION_KEY;
  if (!fileKey || !/^[0-9a-f]{64}$/i.test(fileKey)) {
    problems.push('FILE_ENCRYPTION_KEY absente ou invalide (64 caractères hexadécimaux attendus)');
  }

  const jwtSecret = process.env.JWT_SECRET || process.env.SECRET_CONFIG;
  if (requireJwt) {
    if (!jwtSecret) {
      problems.push('clé JWT absente (JWT_SECRET ou SECRET_CONFIG)');
    } else if (jwtSecret === DEV_DEFAULT_JWT_SECRET || jwtSecret.length < MIN_JWT_SECRET_LENGTH) {
      problems.push(`clé JWT trop faible (valeur par défaut ou moins de ${MIN_JWT_SECRET_LENGTH} caractères)`);
    }
  }

  const meta = {
    event: 'secrets_check',
    processName,
    nodeEnv: process.env.NODE_ENV || 'development',
    source: vault?.source || 'env',
    vaultFallback: Boolean(vault?.fallback),
    fingerprints: {
      fileEncryptionKey: fingerprint(fileKey),
      ...(requireJwt ? { jwtKey: fingerprint(getJwtSecret()) } : {}),
    },
  };

  if (problems.length) {
    const message = `Secrets critiques invalides : ${problems.join(' ; ')}`;
    if (isProduction()) {
      logger.error(`[${processName}] ${message} — arrêt du démarrage`, { ...meta, problems });
      throw new Error(message);
    }
    logger.warn(`[${processName}] ${message} (toléré hors production)`, { ...meta, problems });
    return;
  }

  logger.info(`[${processName}] Secrets critiques chargés`, meta);
};

module.exports = {
  CRITICAL_KEYS,
  getJwtSecret,
  fingerprint,
  assertCriticalSecrets,
};
