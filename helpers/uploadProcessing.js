'use strict';

const fs     = require('fs');
const path   = require('path');
const { Op } = require('sequelize');
const { File, ShareLink, User } = require('../src/models');
const { scanPath }              = require('./antivirus');
const { encryptFileStream }     = require('./crypto');
const { sendFileReceivedEmail, sendShareLinkEmail } = require('./mailer');
const logger                    = require('../config/logger');

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://securetransport.paa.ci';
const ENCRYPTED_DIR = path.resolve('assets', 'encrypted');

/**
 * Supprime un fichier si présent, sans jamais lever d'exception
 * (utilisé pour le nettoyage best-effort du plaintext de quarantaine).
 */
const safeUnlink = (filePath, context = {}) => {
  try {
    if (filePath && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (error) {
    logger.error('Quarantine cleanup failed', {
      event: 'quarantine_cleanup_failed',
      filePath,
      error: error.message,
      ...context,
    });
  }
};

/**
 * Cœur partagé scan → chiffrement, utilisé en synchrone (mode dev, sans
 * queue) comme en asynchrone (worker prod). Scanne le fichier de
 * quarantaine par son chemin, puis :
 *  - infecté            → supprime le plaintext, ne chiffre pas.
 *  - erreur + failOnError → ne supprime rien, laisse l'appelant décider
 *                           (fail-fast immédiat ou retry via la queue).
 *  - clean / skipped / erreur non bloquante → chiffre en streaming vers
 *    encryptedDestPath puis supprime le plaintext de quarantaine.
 * Ne lève jamais pour un verdict antivirus normal (même contrat que
 * scanBuffer côté helpers/antivirus.js). `context` (sharedFileId, fileIds…)
 * sert uniquement à corréler les lignes de log entre elles.
 */
const scanAndEncrypt = async ({ quarantinePath, encryptedDestPath, ivHex, context = {} }) => {
  logger.debug('File processing: scan step started', {
    event: 'file_processing_scan_started',
    quarantinePath,
    ...context,
  });

  const scanStartedAt = Date.now();
  const scanResult = await scanPath(quarantinePath);
  const scanDurationMs = Date.now() - scanStartedAt;

  logger.debug('File processing: scan step finished', {
    event: 'file_processing_scan_finished',
    status: scanResult.status,
    scanDurationMs,
    ...(scanResult.threat ? { threat: scanResult.threat } : {}),
    ...(scanResult.error ? { error: scanResult.error } : {}),
    ...context,
  });

  if (scanResult.status === 'infected') {
    logger.warn('File processing: rejected as infected', {
      event: 'file_processing_infected',
      threat: scanResult.threat,
      ...context,
    });
    safeUnlink(quarantinePath, { reason: 'infected', ...context });
    return { scanResult, encrypted: false };
  }

  if (scanResult.status === 'error' && scanResult.config.failOnError) {
    logger.error('File processing: halted, blocking antivirus error', {
      event: 'file_processing_scan_error_blocking',
      error: scanResult.error,
      ...context,
    });
    return { scanResult, encrypted: false };
  }

  logger.debug('File processing: encryption step started', {
    event: 'file_processing_encryption_started',
    encryptedDestPath,
    ...context,
  });

  const encryptStartedAt = Date.now();
  try {
    await encryptFileStream(quarantinePath, encryptedDestPath, ivHex);
  } catch (encryptError) {
    logger.error('File processing: encryption step failed', {
      event: 'file_processing_encryption_failed',
      error: encryptError.message,
      ...context,
    });
    throw encryptError;
  }

  logger.debug('File processing: encryption step finished', {
    event: 'file_processing_encryption_finished',
    encryptDurationMs: Date.now() - encryptStartedAt,
    ...context,
  });

  safeUnlink(quarantinePath, { reason: 'encrypted', ...context });
  return { scanResult, encrypted: true };
};

/**
 * Met à jour le statut des enregistrements File issus d'un même upload
 * physique, une fois le scan+chiffrement résolu (utilisé par le worker).
 */
const applyScanOutcomeToFiles = async ({ fileIds, encrypted, scanResult }) => {
  const status = encrypted
    ? 'clean'
    : (scanResult.status === 'infected' ? 'infected' : 'scan_failed');

  await File.update({ status }, { where: { id: { [Op.in]: fileIds } } });

  logger.debug('File processing: status applied', {
    event: 'file_processing_status_applied',
    fileIds,
    status,
  });

  return status;
};

/**
 * Envoie l'email "fichier reçu / lien de partage" (mail 1) pour chaque
 * destinataire d'un upload. Appelée soit directement après un scan
 * synchrone (mode dev), soit par le worker après un scan clean (mode prod).
 */
const sendFileArrivedEmails = async (fileIds) => {
  const records = await File.findAll({
    where: { id: { [Op.in]: fileIds } },
    include: [
      { model: ShareLink, as: 'shareLinks' },
      { model: User, as: 'sender', attributes: ['firstName'] },
    ],
  });

  for (const record of records) {
    try {
      const senderFirstName = record.sender?.firstName || '—';
      const shareLink = record.shareLinks?.[0] || null;

      logger.debug('File processing: sending recipient notification email', {
        event: 'file_processing_email_started',
        fileId: record.id,
        receiverEmail: record.receiverEmail,
        emailType: shareLink ? 'share_link' : 'file_received',
      });

      if (shareLink) {
        await sendShareLinkEmail({
          to:              record.receiverEmail,
          fileId:          record.id,
          senderFirstName,
          reference:       record.reference,
          isProtected:     record.isProtected,
          shareUrl:        `${FRONTEND_URL}/download/${shareLink.token}`,
          comment:         record.comment || null,
        });
      } else {
        await sendFileReceivedEmail({
          to:              record.receiverEmail,
          fileId:          record.id,
          senderFirstName,
          originalName:    record.originalName,
          reference:       record.reference,
          size:            record.size,
          isProtected:     record.isProtected,
          comment:         record.comment || null,
        });
      }

      logger.debug('File processing: recipient notification email sent', {
        event: 'file_processing_email_finished',
        fileId: record.id,
        receiverEmail: record.receiverEmail,
      });
    } catch (mailError) {
      logger.error('Recipient notification email failed', {
        event: 'file_recipient_email_failed',
        fileId: record.id,
        receiverEmail: record.receiverEmail,
        error: mailError.message,
      });
    }
  }
};

/**
 * Traite un job de scan mis en queue (mode prod) : scanne + chiffre,
 * applique le statut résultant, puis envoie l'email "fichier reçu" si
 * clean. Lève une exception uniquement pour une erreur antivirus
 * transitoire bloquante (clamd indisponible) — ce qui laisse le message
 * Redis non-acquitté pour être retenté (voir helpers/scanQueue.js).
 * Un verdict "infecté" est en revanche terminal : jamais de retry.
 */
const processScanJob = async (job) => {
  const { sharedFileId, quarantinePath, iv, fileIds } = job;
  const encryptedDestPath = path.join(ENCRYPTED_DIR, sharedFileId);
  const context = { sharedFileId, fileIds };
  const jobStartedAt = Date.now();

  logger.info('Scan job started', {
    event: 'scan_job_started',
    quarantinePath,
    ...context,
  });

  const { scanResult, encrypted } = await scanAndEncrypt({
    quarantinePath,
    encryptedDestPath,
    ivHex: iv,
    context,
  });

  if (!encrypted && scanResult.status === 'error') {
    logger.error('Scan job aborted — antivirus unavailable, will retry', {
      event: 'scan_job_aborted',
      error: scanResult.error,
      ...context,
    });
    throw new Error(`Analyse antivirus indisponible : ${scanResult.error}`);
  }

  await applyScanOutcomeToFiles({ fileIds, encrypted, scanResult });

  if (encrypted) {
    logger.debug('Scan job: dispatching recipient notification emails', {
      event: 'scan_job_emails_started',
      ...context,
    });
    await sendFileArrivedEmails(fileIds);
  }

  logger.info('Scan job processed', {
    event: 'scan_job_processed',
    status: encrypted ? 'clean' : scanResult.status,
    durationMs: Date.now() - jobStartedAt,
    ...context,
  });
};

module.exports = {
  safeUnlink,
  scanAndEncrypt,
  applyScanOutcomeToFiles,
  sendFileArrivedEmails,
  processScanJob,
};
