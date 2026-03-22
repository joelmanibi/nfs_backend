'use strict';

const { Client } = require('ldapts');
const nodemailer  = require('nodemailer');
const logger      = require('../config/logger');

// ─── Test LDAPS ───────────────────────────────────────────────────────────────
async function checkLdap() {
  const url      = process.env.LDAP_URL           || 'ldaps://10.32.15.110:636';
  const bindDn   = process.env.LDAP_BIND_DN       || 'CN=idssecuremft,OU=PAA,DC=paa,DC=local';
  const bindPass = process.env.LDAP_BIND_PASSWORD || '';

  const client = new Client({
    url,
    tlsOptions: { rejectUnauthorized: false },
    timeout:        8000,
    connectTimeout: 8000,
  });

  const start = Date.now();
  try {
    await client.bind(bindDn, bindPass);
    await client.unbind().catch(() => {});

    logger.info('[startup] LDAP connectivity check passed', {
      event:      'startup_check_ldap_ok',
      status:     'OK',
      url,
      bindDn,
      durationMs: Date.now() - start,
    });
  } catch (err) {
    logger.error('[startup] LDAP connectivity check FAILED', {
      event:      'startup_check_ldap_failed',
      status:     'FAILED',
      url,
      bindDn,
      durationMs: Date.now() - start,
      error:      err.message,
    });
  }
}

// ─── Test SMTP ────────────────────────────────────────────────────────────────
async function checkSmtp() {
  const provider = (process.env.MAIL_PROVIDER || 'gmail').toLowerCase().trim();

  let transporter;
  let host;

  if (provider === 'smtp') {
    host = process.env.SMTP_HOST || '(non configuré)';
    transporter = nodemailer.createTransport({
      host,
      port:   parseInt(process.env.SMTP_PORT, 10) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      tls: {
        rejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== 'false',
      },
    });
  } else {
    // Gmail
    host = 'smtp.gmail.com';
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });
  }

  const start = Date.now();
  try {
    await transporter.verify();

    logger.info('[startup] SMTP connectivity check passed', {
      event:      'startup_check_smtp_ok',
      status:     'OK',
      provider,
      host,
      durationMs: Date.now() - start,
    });
  } catch (err) {
    logger.warn('[startup] SMTP connectivity check FAILED', {
      event:      'startup_check_smtp_failed',
      status:     'FAILED',
      provider,
      host,
      durationMs: Date.now() - start,
      error:      err.message,
    });
  }
}

// ─── Lancement en parallèle ───────────────────────────────────────────────────
async function runStartupChecks() {
  logger.info('[startup] Vérification des connectivités externes (LDAP + SMTP)...', {
    event: 'startup_checks_begin',
  });

  await Promise.allSettled([
    checkLdap(),
    checkSmtp(),
  ]);

  logger.info('[startup] Vérifications terminées.', {
    event: 'startup_checks_done',
  });
}

module.exports = { runStartupChecks };

