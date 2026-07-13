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
 * scanBuffer côté helpers/antivirus.js).
 */
const scanAndEncrypt = async ({ quarantinePath, encryptedDestPath, ivHex }) => {
  const scanResult = await scanPath(quarantinePath);

  if (scanResult.status === 'infected') {
    safeUnlink(quarantinePath, { reason: 'infected' });
    return { scanResult, encrypted: false };
  }

  if (scanResult.status === 'error' && scanResult.config.failOnError) {
    return { scanResult, encrypted: false };
  }

  await encryptFileStream(quarantinePath, encryptedDestPath, ivHex);
  safeUnlink(quarantinePath, { reason: 'encrypted' });
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

  const { scanResult, encrypted } = await scanAndEncrypt({
    quarantinePath,
    encryptedDestPath,
    ivHex: iv,
  });

  if (!encrypted && scanResult.status === 'error') {
    throw new Error(`Analyse antivirus indisponible : ${scanResult.error}`);
  }

  await applyScanOutcomeToFiles({ fileIds, encrypted, scanResult });

  if (encrypted) {
    await sendFileArrivedEmails(fileIds);
  }

  logger.info('Scan job processed', {
    event: 'scan_job_processed',
    sharedFileId,
    fileIds,
    status: encrypted ? 'clean' : scanResult.status,
  });
};

module.exports = {
  safeUnlink,
  scanAndEncrypt,
  applyScanOutcomeToFiles,
  sendFileArrivedEmails,
  processScanJob,
};
