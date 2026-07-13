'use strict';

const fs     = require('fs');
const path   = require('path');
const { Op } = require('sequelize');
const { File } = require('../src/models');
const logger = require('../config/logger');

const QUARANTINE_DIR = path.resolve('assets', 'quarantine');
const TTL_MINUTES    = parseInt(process.env.QUARANTINE_TTL_MINUTES, 10) || 60;
const TTL_MS         = TTL_MINUTES * 60 * 1000;

/**
 * Fonction pure — un fichier de quarantaine est considéré abandonné
 * s'il est plus vieux que le TTL (aucun job ne l'a traité à temps,
 * que ce soit parce qu'aucun job n'a jamais été créé — crash avant
 * commit DB — ou parce que le worker qui le traitait a crashé).
 */
const isQuarantineFileStale = (mtimeMs, ttlMs, now) => (now - mtimeMs) > ttlMs;

/**
 * Filet de sécurité complémentaire au reclaim Redis (helpers/scanQueue.js) :
 * celui-ci couvre les jobs Redis orphelins, celui-ci couvre aussi le cas
 * où aucun job n'a même été créé (crash entre écriture disque et commit).
 */
const runQuarantineCleanup = async () => {
  if (!fs.existsSync(QUARANTINE_DIR)) return;

  const now = Date.now();
  const entries = fs.readdirSync(QUARANTINE_DIR);

  let staleFiles    = 0;
  let orphanedFiles = 0;
  let markedFailed  = 0;

  for (const entry of entries) {
    const fullPath = path.join(QUARANTINE_DIR, entry);

    let stats;
    try {
      stats = fs.statSync(fullPath);
    } catch {
      continue;
    }

    if (!stats.isFile() || !isQuarantineFileStale(stats.mtimeMs, TTL_MS, now)) continue;

    staleFiles += 1;

    const pendingRows = await File.findAll({
      where: { encryptedPath: entry, status: 'pending_scan' },
      attributes: ['id'],
    });

    if (pendingRows.length) {
      await File.update(
        { status: 'scan_failed' },
        { where: { id: { [Op.in]: pendingRows.map((row) => row.id) } } },
      );
      markedFailed += pendingRows.length;
    } else {
      orphanedFiles += 1;
    }

    try {
      fs.unlinkSync(fullPath);
    } catch (error) {
      logger.error('Quarantine stale file deletion failed', {
        event: 'quarantine_cleanup_delete_failed',
        file: entry,
        error: error.message,
      });
    }
  }

  if (staleFiles > 0) {
    logger.info('Quarantine cleanup completed', {
      event: 'quarantine_cleanup_completed',
      staleFiles,
      orphanedFiles,
      markedFailed,
      ttlMinutes: TTL_MINUTES,
    });
  }
};

module.exports = { runQuarantineCleanup, isQuarantineFileStale };
