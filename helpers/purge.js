'use strict';

const fs   = require('fs');
const path = require('path');
const { Op } = require('sequelize');
const { File, ShareLink } = require('../src/models');
const logger = require('../config/logger');

const ENCRYPTED_DIR  = path.resolve('assets', 'encrypted');
const PURGE_DAYS     = parseInt(process.env.PURGE_RETENTION_DAYS, 10) || 15;

/**
 * Purge automatique des fichiers et enregistrements DB de plus de PURGE_DAYS jours.
 *
 * Logique :
 *  1. Cherche tous les enregistrements File créés il y a plus de PURGE_DAYS jours.
 *  2. Pour chaque fichier physique (encryptedPath), vérifie qu'aucun autre
 *     enregistrement RÉCENT (< PURGE_DAYS jours) ne pointe vers lui.
 *     → Si oui : ne supprime PAS le fichier disque (un autre destinataire l'attend encore).
 *     → Si non : supprime le fichier disque.
 *  3. Supprime les ShareLinks expirés.
 *  4. Supprime les enregistrements DB.
 */
const runPurge = async () => {
  const startedAt  = new Date();
  const cutoffDate = new Date(Date.now() - PURGE_DAYS * 24 * 60 * 60 * 1000);

  logger.info('Purge automatique démarrée', {
    event:       'purge_started',
    cutoffDate:  cutoffDate.toISOString(),
    retentionDays: PURGE_DAYS,
  });

  let deletedFiles    = 0;
  let deletedRecords  = 0;
  let deletedLinks    = 0;
  let errors          = 0;

  try {
    // ── 1. Récupérer tous les enregistrements à purger ────────────────────────
    const expiredRecords = await File.findAll({
      where: { createdAt: { [Op.lt]: cutoffDate } },
      attributes: ['id', 'encryptedPath', 'originalName', 'senderId'],
    });

    if (expiredRecords.length === 0) {
      logger.info('Purge terminée — aucun fichier à purger', { event: 'purge_nothing_to_do' });
      return;
    }

    // ── 2. Identifier les chemins physiques uniques à traiter ─────────────────
    const uniquePaths = [...new Set(expiredRecords.map((f) => f.encryptedPath))];

    for (const encryptedPath of uniquePaths) {
      // Vérifie si un enregistrement RÉCENT partage ce même fichier physique
      const recentSiblingCount = await File.count({
        where: {
          encryptedPath,
          createdAt: { [Op.gte]: cutoffDate },
        },
      });

      if (recentSiblingCount > 0) {
        // Un destinataire récent pointe encore vers ce fichier → ne pas supprimer
        logger.info('Fichier physique conservé (destinataire récent actif)', {
          event: 'purge_file_kept',
          encryptedPath,
          recentSiblings: recentSiblingCount,
        });
        continue;
      }

      // Aucun enregistrement récent → supprimer le fichier physique
      const absPath = path.isAbsolute(encryptedPath)
        ? encryptedPath
        : path.join(ENCRYPTED_DIR, encryptedPath);

      if (fs.existsSync(absPath)) {
        try {
          fs.unlinkSync(absPath);
          deletedFiles++;
          logger.info('Fichier physique supprimé', { event: 'purge_file_deleted', encryptedPath });
        } catch (fsErr) {
          errors++;
          logger.error('Échec suppression fichier physique', {
            event: 'purge_file_error',
            encryptedPath,
            error: fsErr.message,
          });
        }
      }
    }

    // ── 3. Supprimer les ShareLinks expirés ──────────────────────────────────
    const expiredFileIds = expiredRecords.map((f) => f.id);
    const linkResult = await ShareLink.destroy({
      where: {
        [Op.or]: [
          { fileId:    { [Op.in]: expiredFileIds } },
          { expiresAt: { [Op.lt]: new Date() } },   // liens expirés (toute date)
        ],
      },
    });
    deletedLinks = linkResult;

    // ── 4. Supprimer les enregistrements File en base ─────────────────────────
    const dbResult = await File.destroy({
      where: { createdAt: { [Op.lt]: cutoffDate } },
    });
    deletedRecords = dbResult;

  } catch (err) {
    errors++;
    logger.error('Erreur critique lors de la purge', {
      event: 'purge_critical_error',
      error: err.message,
    });
  }

  const durationMs = Date.now() - startedAt.getTime();
  logger.info('Purge automatique terminée', {
    event:          'purge_completed',
    deletedFiles,
    deletedRecords,
    deletedLinks,
    errors,
    durationMs,
  });
};

module.exports = { runPurge };
