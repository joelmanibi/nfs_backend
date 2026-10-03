'use strict';

/**
 * Transforme une erreur en métadonnées de log exploitables pour le diagnostic
 * (console SUPER_ADMIN → Journaux techniques). À utiliser dans les appels
 * logger à la place de `error: err.message` :
 *
 *   logger.error('Email send failed', { event: '...', ...errorDetails(err) });
 *
 * Conserve `error` (message) pour la compatibilité avec les lecteurs de logs
 * existants, et ajoute dans `errorInfo` tout ce qui aide à comprendre une
 * panne d'intégration : code système (ECONNREFUSED, ETIMEDOUT…), hôte/port,
 * réponse SMTP, code LDAP, statut HTTP, erreur SQL, cause, et la pile d'appels.
 */

const MAX_STACK_LINES = 20;
const MAX_TEXT_LENGTH = 2000;

const truncate = (value) => {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (!text) return text;
  return text.length > MAX_TEXT_LENGTH ? `${text.slice(0, MAX_TEXT_LENGTH)}…` : text;
};

const isSet = (value) => value !== undefined && value !== null && value !== '';

// Champs posés par Node (réseau/fs), nodemailer (SMTP), ldapts (LDAP), redis, ftp…
const DIRECT_FIELDS = [
  'code', 'errno', 'syscall', 'address', 'port', 'hostname', 'host', 'path',
  'responseCode', 'command', 'response', // nodemailer / SMTP
  'statusCode', 'status',                // HTTP
  'lde_message', 'lde_dn',               // ldapts
];

const errorDetails = (err) => {
  if (!isSet(err)) return { error: 'Erreur inconnue' };
  if (typeof err !== 'object') return { error: String(err) };

  const info = {};
  if (err.name && err.name !== 'Error') info.name = err.name;

  for (const key of DIRECT_FIELDS) {
    if (isSet(err[key]) && typeof err[key] !== 'object') {
      info[key] = typeof err[key] === 'string' ? truncate(err[key]) : err[key];
    }
  }

  // Erreur SQL (Sequelize) : l'erreur du driver est dans original/parent
  const sqlError = err.original || err.parent;
  if (sqlError) {
    info.sql = {
      code: sqlError.code,
      message: truncate(sqlError.sqlMessage || sqlError.message),
      ...(err.sql ? { query: truncate(err.sql) } : {}),
    };
  }
  if (Array.isArray(err.errors) && err.errors.length) {
    info.validation = err.errors.slice(0, 10).map((e) => e.message || String(e));
  }

  // Réponse HTTP (fetch/axios) d'un service distant
  if (err.response && typeof err.response === 'object') {
    info.httpResponse = {
      status: err.response.status,
      data: isSet(err.response.data) ? truncate(err.response.data) : undefined,
    };
  }

  if (err.cause) {
    info.cause = err.cause.message || String(err.cause);
    if (err.cause.code) info.causeCode = err.cause.code;
  }

  const details = { error: err.message || String(err) };
  if (Object.keys(info).length) details.errorInfo = info;
  if (err.stack) details.stack = err.stack.split('\n').slice(0, MAX_STACK_LINES).join('\n');
  return details;
};

module.exports = { errorDetails };
