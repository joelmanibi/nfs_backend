'use strict';

const fs     = require('fs');
const path   = require('path');
const logger = require('../../config/logger');
const { errorDetails } = require('../../helpers/errorDetails');
const { runConnectivityChecks } = require('../../helpers/startupChecks');

/**
 * Journaux techniques — console SUPER_ADMIN.
 * Lit logs/combined.log (tous niveaux, écrit par l'API et le worker) en
 * partant de la fin, pour rester rapide même sur un gros fichier : on
 * s'arrête dès que `limit` entrées correspondent aux filtres, ou après
 * MAX_SCAN_BYTES lus (la page suivante reprend via `before`).
 */

const LOG_FILE       = path.resolve('logs', 'combined.log');
const CHUNK_SIZE     = 256 * 1024;
const MAX_SCAN_BYTES = 30 * 1024 * 1024;
const DEFAULT_LIMIT  = 200;
const MAX_LIMIT      = 1000;
const LEVELS         = ['error', 'warn', 'info', 'http', 'verbose', 'debug'];

// ─── Classement par service (déduit de event + message) ─────────────────────
// L'ordre compte : la première règle qui correspond l'emporte
// (ex. auth_ldap_* → LDAP et non Authentification).
const COMPONENTS = [
  { key: 'ldap',       label: 'LDAP / Active Directory',   re: /ldap/ },
  { key: 'smtp',       label: 'SMTP / Emails',             re: /smtp|^email_|email_(sent|failed)|e-?mail send|mailer/ },
  { key: 'database',   label: 'Base de données',           re: /startup_check_database|\bdb_|database|sequelize|migration|sql/ },
  { key: 'redis',      label: 'Redis / File de scan',      re: /redis|scan_queue|scan_job|scan_worker|dead-?letter/ },
  { key: 'antivirus',  label: 'Antivirus ClamAV',          re: /antivirus|clam|virus|infected|scan/ },
  { key: 'vault',      label: 'Vault (secrets)',           re: /vault/ },
  { key: 'collection', label: 'Collecte (SFTP/FTP/HTTP)',  re: /collection|sftp|ftp/ },
  { key: 'auth',       label: 'Authentification',          re: /^auth_|otp|password|token/ },
  { key: 'files',      label: 'Fichiers & partage',        re: /^file_|^share_|upload|download/ },
  { key: 'admin',      label: 'Administration',            re: /^admin[_ ]/ },
  { key: 'system',     label: 'Application / système',     re: /process_|server_|unhandled|startup|purge|quarantine|worker|request/ },
];
const COMPONENT_LABELS = Object.fromEntries([...COMPONENTS.map((c) => [c.key, c.label]), ['other', 'Autre']]);

// L'event (identifiant stable) prime ; le message ne sert que s'il n'y a pas
// d'event reconnu (anciens logs sans event).
const classify = (entry) => {
  const event = (entry.event || '').toLowerCase();
  const message = (entry.message || '').toLowerCase();
  const match = (event && COMPONENTS.find((c) => c.re.test(event)))
    || COMPONENTS.find((c) => c.re.test(message));
  return match ? match.key : 'other';
};

// ─── Masquage des secrets ────────────────────────────────────────────────────
const SECRET_KEY = /(password|passwd|^pass$|secret|authorization|cookie|api_?key|private_?key|bindpass|otpcode|codehash|tokenhash)/i;

const redact = (value, depth = 0) => {
  if (depth > 6 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SECRET_KEY.test(k) && v !== null && v !== '' ? '***' : redact(v, depth + 1);
  }
  return out;
};

// ─── Lecture du fichier de la fin vers le début ──────────────────────────────
async function* readLinesBackward(file, endOffset) {
  const fh = await fs.promises.open(file, 'r');
  try {
    let pos = endOffset;
    let leftover = Buffer.alloc(0);
    while (pos > 0) {
      const size = Math.min(CHUNK_SIZE, pos);
      pos -= size;
      const buf = Buffer.alloc(size);
      await fh.read(buf, 0, size, pos);
      const data = Buffer.concat([buf, leftover]);
      let end = data.length;
      for (let i = data.length - 1; i >= 0; i--) {
        if (data[i] === 0x0a) {
          if (end > i + 1) yield { line: data.subarray(i + 1, end).toString('utf8'), offset: pos + i + 1 };
          end = i;
        }
      }
      leftover = data.subarray(0, end);
    }
    if (leftover.length) yield { line: leftover.toString('utf8'), offset: 0 };
  } finally {
    await fh.close();
  }
}

// Horodatage winston : 'YYYY-MM-DD HH:mm:ss' (heure locale du serveur).
// Les bornes reçues ('YYYY-MM-DDTHH:mm') sont normalisées au même format pour
// une comparaison lexicographique, indépendante du fuseau.
const normalizeBound = (value) => (value ? String(value).trim().replace('T', ' ') : null);

const localTimestamp = (date) => {
  const p = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())} ${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`;
};

const toEntry = (raw, offset) => {
  const component = classify(raw);
  return {
    id: offset,
    timestamp: raw.timestamp || null,
    level: raw.level || 'info',
    message: raw.message || '',
    event: raw.event || null,
    component,
    componentLabel: COMPONENT_LABELS[component],
    error: raw.error || null,
    data: redact(raw),
  };
};

// ─── GET /admin/logs ─────────────────────────────────────────────────────────
/**
 * Query : level=error,warn · component=ldap,smtp · search=texte · from/to
 * (YYYY-MM-DDTHH:mm) · limit · before (offset renvoyé par la page précédente).
 */
const getLogs = async (req, res) => {
  try {
    const limit      = Math.min(MAX_LIMIT, parseInt(req.query.limit, 10) || DEFAULT_LIMIT);
    const levels     = (req.query.level || '').split(',').map((l) => l.trim()).filter((l) => LEVELS.includes(l));
    const components = (req.query.component || '').split(',').map((c) => c.trim()).filter((c) => COMPONENT_LABELS[c]);
    const search     = (req.query.search || '').trim().toLowerCase();
    const from       = normalizeBound(req.query.from);
    const to         = normalizeBound(req.query.to);

    if (!fs.existsSync(LOG_FILE)) {
      return res.json({ entries: [], nextBefore: null, fileSize: 0, components: COMPONENT_LABELS });
    }

    const { size: fileSize } = await fs.promises.stat(LOG_FILE);
    const requestedBefore = parseInt(req.query.before, 10);
    const endOffset = Number.isFinite(requestedBefore) && requestedBefore >= 0 && requestedBefore <= fileSize
      ? requestedBefore
      : fileSize;

    const entries = [];
    let scannedBytes = 0;
    // nextBefore : offset de la dernière ligne lue, pour reprendre juste avant.
    // Reste null si on a atteint le début du fichier ou la borne `from`.
    let nextBefore = null;

    for await (const { line, offset } of readLinesBackward(LOG_FILE, endOffset)) {
      scannedBytes += Buffer.byteLength(line) + 1;

      let raw;
      try { raw = JSON.parse(line); } catch { raw = null; } // ligne non JSON (ancien format)

      if (raw) {
        if (from && raw.timestamp && raw.timestamp < from) break; // plus ancien que la borne : fin
        const keep = !(to && raw.timestamp && raw.timestamp > to)
          && (!levels.length || levels.includes(raw.level))
          && (!components.length || components.includes(classify(raw)))
          && (!search || line.toLowerCase().includes(search));
        if (keep) entries.push(toEntry(raw, offset));
      }

      if (entries.length >= limit || scannedBytes >= MAX_SCAN_BYTES) {
        nextBefore = offset > 0 ? offset : null;
        break;
      }
    }

    return res.json({
      entries,
      nextBefore,
      scannedBytes,
      scanLimited: scannedBytes >= MAX_SCAN_BYTES,
      fileSize,
      components: COMPONENT_LABELS,
    });
  } catch (err) {
    logger.error('Admin getLogs error', { event: 'admin_logs_read_failed', ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur lors de la lecture des journaux.' });
  }
};

// ─── GET /admin/logs/summary ─────────────────────────────────────────────────
/**
 * Synthèse des dernières 24 h : nombre d'erreurs / avertissements par service
 * et dernière erreur de chacun — pour repérer d'un coup d'œil le service en
 * cause.
 */
const getLogsSummary = async (req, res) => {
  try {
    const hours = Math.min(24 * 30, Math.max(1, parseInt(req.query.hours, 10) || 24));
    const since = localTimestamp(new Date(Date.now() - hours * 3600 * 1000));

    const byComponent = {};
    const totals = { error: 0, warn: 0 };

    if (fs.existsSync(LOG_FILE)) {
      const { size } = await fs.promises.stat(LOG_FILE);
      let scannedBytes = 0;
      for await (const { line, offset } of readLinesBackward(LOG_FILE, size)) {
        scannedBytes += Buffer.byteLength(line) + 1;
        if (scannedBytes > MAX_SCAN_BYTES) break;

        let raw;
        try { raw = JSON.parse(line); } catch { continue; }
        if (raw.timestamp && raw.timestamp < since) break;
        if (raw.level !== 'error' && raw.level !== 'warn') continue;

        const key = classify(raw);
        const bucket = byComponent[key] || (byComponent[key] = { component: key, label: COMPONENT_LABELS[key], error: 0, warn: 0, lastError: null, lastWarn: null });
        bucket[raw.level] += 1;
        totals[raw.level] += 1;
        // Lecture à rebours : la première rencontrée est la plus récente
        if (raw.level === 'error' && !bucket.lastError) bucket.lastError = toEntry(raw, offset);
        if (raw.level === 'warn' && !bucket.lastWarn) bucket.lastWarn = toEntry(raw, offset);
      }
    }

    const components = Object.values(byComponent).sort((a, b) => (b.error - a.error) || (b.warn - a.warn));
    return res.json({ hours, since, totals, components });
  } catch (err) {
    logger.error('Admin getLogsSummary error', { event: 'admin_logs_summary_failed', ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur lors de l\'analyse des journaux.' });
  }
};

// ─── POST /admin/logs/health-check ───────────────────────────────────────────
/** Teste maintenant la connectivité vers DB, LDAP, SMTP, Redis et ClamAV. */
const runHealthCheck = async (req, res) => {
  try {
    logger.info('Admin triggered connectivity checks', { event: 'admin_health_check', adminId: req.user.id });
    const results = await runConnectivityChecks('manual');
    return res.json({ checkedAt: new Date().toISOString(), results });
  } catch (err) {
    logger.error('Admin health check error', { event: 'admin_health_check_failed', ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur lors des tests de connectivité.' });
  }
};

module.exports = { getLogs, getLogsSummary, runHealthCheck, classify, readLinesBackward };
