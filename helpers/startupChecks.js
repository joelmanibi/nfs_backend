'use strict';

const net         = require('net');
const { Client }  = require('ldapts');
const nodemailer  = require('nodemailer');
const logger      = require('../config/logger');
const { errorDetails } = require('./errorDetails');

/**
 * Tests de connectivité vers les services externes. Lancés au démarrage
 * (runStartupChecks) et à la demande depuis la console SUPER_ADMIN
 * (runConnectivityChecks → GET /admin/logs/health). Chaque test journalise son
 * résultat (événement startup_check_<service>_ok|failed) et le renvoie.
 */

const CHECK_TIMEOUT_MS = 8000;

const withTimeout = (promise, ms, label) => Promise.race([
  promise,
  new Promise((_, reject) => setTimeout(() => {
    const err = new Error(`${label} : délai dépassé (${ms} ms)`);
    err.code = 'ETIMEDOUT';
    reject(err);
  }, ms)),
]);

/**
 * Exécute un test, journalise et renvoie un résultat homogène :
 * { service, label, status: 'OK'|'FAILED'|'DISABLED', target, durationMs, error?, errorInfo? }
 */
const runCheck = async ({ service, label, target, trigger, extra = {}, failLevel = 'error' }, fn) => {
  const start = Date.now();
  const base = { service, label, target, ...extra };
  try {
    const details = await fn();
    const result = { ...base, ...(details || {}), status: 'OK', durationMs: Date.now() - start };
    // `service` est réservé au nom du process dans les logs (defaultMeta winston)
    const { service: _s, ...logMeta } = result;
    logger.info(`[${trigger}] ${label} connectivity check passed`, {
      event: `startup_check_${service}_ok`, trigger, ...logMeta,
    });
    return result;
  } catch (err) {
    const { stack, ...errMeta } = errorDetails(err);
    const result = { ...base, status: 'FAILED', durationMs: Date.now() - start, ...errMeta };
    const { service: _s, ...logMeta } = result;
    logger[failLevel](`[${trigger}] ${label} connectivity check FAILED`, {
      event: `startup_check_${service}_failed`, trigger, ...logMeta, stack,
    });
    return result;
  }
};

const disabled = (service, label, reason) => ({ service, label, status: 'DISABLED', target: reason });

// ─── LDAP / Active Directory ─────────────────────────────────────────────────
async function checkLdap(trigger = 'startup') {
  const url      = process.env.LDAP_URL           || 'ldaps://10.32.15.110:636';
  const bindDn   = process.env.LDAP_BIND_DN       || 'idssecuremft@paa.local';
  const bindPass = process.env.LDAP_BIND_PASSWORD || '';

  return runCheck({ service: 'ldap', label: 'LDAP / AD', target: url, trigger, extra: { bindDn } }, async () => {
    const client = new Client({
      url,
      tlsOptions: { rejectUnauthorized: false },
      timeout:        CHECK_TIMEOUT_MS,
      connectTimeout: CHECK_TIMEOUT_MS,
    });
    try {
      await client.bind(bindDn, bindPass);
    } finally {
      await client.unbind().catch(() => {});
    }
  });
}

// ─── SMTP (envoi des emails) ─────────────────────────────────────────────────
async function checkSmtp(trigger = 'startup') {
  const provider = (process.env.MAIL_PROVIDER || 'gmail').toLowerCase().trim();

  let transporter;
  let host;

  if (provider === 'smtp') {
    host = `${process.env.SMTP_HOST || '(non configuré)'}:${parseInt(process.env.SMTP_PORT, 10) || 587}`;
    transporter = nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT, 10) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      tls: {
        rejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== 'false',
      },
      connectionTimeout: CHECK_TIMEOUT_MS,
      greetingTimeout:   CHECK_TIMEOUT_MS,
    });
  } else {
    host = 'smtp.gmail.com';
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });
  }

  return runCheck({ service: 'smtp', label: 'SMTP', target: host, trigger, extra: { provider }, failLevel: 'warn' }, async () => {
    try {
      await withTimeout(transporter.verify(), CHECK_TIMEOUT_MS + 2000, 'SMTP');
    } finally {
      transporter.close();
    }
  });
}

// ─── Base de données ─────────────────────────────────────────────────────────
async function checkDatabase(trigger = 'startup') {
  const { sequelize } = require('../src/models');
  const { host, port, database } = sequelize.config;
  return runCheck({ service: 'database', label: 'Base de données', target: `${sequelize.getDialect()}://${host}:${port}/${database}`, trigger }, async () => {
    await withTimeout(sequelize.authenticate(), CHECK_TIMEOUT_MS, 'Base de données');
  });
}

// ─── Redis (file de scan antivirus) ──────────────────────────────────────────
async function checkRedis(trigger = 'startup') {
  const { getQueueConfig } = require('./scanQueue');
  const config = getQueueConfig();
  if (!config.enabled) return disabled('redis', 'Redis (file de scan)', 'ANTIVIRUS_QUEUE_ENABLED=false');

  const target = config.redisUrl.replace(/\/\/[^@]*@/, '//***@'); // masque les identifiants
  return runCheck({ service: 'redis', label: 'Redis (file de scan)', target, trigger }, async () => {
    const { createClient } = require('redis');
    const client = createClient({ url: config.redisUrl, socket: { connectTimeout: CHECK_TIMEOUT_MS, reconnectStrategy: false } });
    client.on('error', () => {}); // l'erreur est remontée par connect()/ping()
    try {
      await withTimeout(client.connect(), CHECK_TIMEOUT_MS, 'Redis');
      const pong = await withTimeout(client.ping(), CHECK_TIMEOUT_MS, 'Redis');
      const pending = await client.xLen(config.streamKey).catch(() => null);
      return { response: pong, queueLength: pending };
    } finally {
      await client.quit().catch(() => client.disconnect().catch(() => {}));
    }
  });
}

// ─── Antivirus ClamAV (clamd) ────────────────────────────────────────────────
async function checkAntivirus(trigger = 'startup') {
  const { getAntivirusConfig } = require('./antivirus');
  const config = getAntivirusConfig();
  if (!config.enabled) return disabled('antivirus', 'Antivirus ClamAV', 'ANTIVIRUS_ENABLED=false');

  return runCheck({ service: 'antivirus', label: 'Antivirus ClamAV', target: `${config.host}:${config.port}`, trigger }, () => new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: config.host, port: config.port });
    let response = '';
    socket.setTimeout(CHECK_TIMEOUT_MS);
    socket.on('connect', () => socket.write('zPING\0'));
    socket.on('data', (chunk) => { response += chunk.toString(); });
    socket.on('timeout', () => {
      const err = new Error(`clamd ne répond pas (${CHECK_TIMEOUT_MS} ms)`);
      err.code = 'ETIMEDOUT';
      socket.destroy();
      reject(err);
    });
    socket.on('error', reject);
    socket.on('end', () => {
      const text = response.replace(/\0/g, '').trim();
      if (text === 'PONG') resolve({ response: text });
      else reject(new Error(`Réponse inattendue de clamd : "${text}"`));
    });
  }));
}

// ─── Lancement en parallèle ───────────────────────────────────────────────────
async function runConnectivityChecks(trigger = 'manual') {
  const results = await Promise.allSettled([
    checkDatabase(trigger),
    checkLdap(trigger),
    checkSmtp(trigger),
    checkRedis(trigger),
    checkAntivirus(trigger),
  ]);
  return results.map((r) => (r.status === 'fulfilled'
    ? r.value
    : { service: 'unknown', status: 'FAILED', ...errorDetails(r.reason) }));
}

async function runStartupChecks() {
  logger.info('[startup] Vérification des connectivités externes (LDAP + SMTP)...', {
    event: 'startup_checks_begin',
  });

  await Promise.allSettled([
    checkLdap('startup'),
    checkSmtp('startup'),
  ]);

  logger.info('[startup] Vérifications terminées.', {
    event: 'startup_checks_done',
  });
}

module.exports = { runStartupChecks, runConnectivityChecks };
