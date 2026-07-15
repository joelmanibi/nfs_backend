'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const multer = require('multer');
const logger = require('../config/logger');

// ─── Taille max configurable via .env (défaut : 1 Go) ────────────────────────
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE_MB || '1024', 10) * 1024 * 1024;
const PROGRESS_LOG_INTERVAL_MS = parseInt(process.env.UPLOAD_PROGRESS_LOG_INTERVAL_MS || '5000', 10);

// ─── Répertoire de quarantaine ────────────────────────────────────────────────
const QUARANTINE_DIR = path.resolve('assets', 'quarantine');
fs.mkdirSync(QUARANTINE_DIR, { recursive: true });

// ─── Instance Multer ──────────────────────────────────────────────────────────
/**
 * Tous les types de fichiers sont acceptés.
 * diskStorage : le fichier est streamé directement sur disque (jamais
 * bufferisé intégralement en RAM), dans un répertoire de quarantaine.
 * Il y reste en clair le temps du scan antivirus + chiffrement, puis
 * est supprimé (voir helpers/uploadProcessing.js).
 * Le nom de fichier généré (UUID) est réutilisé comme identifiant du
 * blob chiffré final une fois le scan validé.
 */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, QUARANTINE_DIR),
  filename: (req, file, cb) => cb(null, crypto.randomUUID()),
});

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
  },
});

/**
 * Journalise la réception brute du corps de la requête d'upload, avant même
 * que Multer ait fini de le parser (donc avant que `uploadFile` ne s'exécute).
 * Pour un gros fichier sur une connexion lente, c'est cette phase — invisible
 * jusqu'ici — qui prend le plus de temps et où les échecs (timeout serveur,
 * déconnexion client, erreur disque) passaient inaperçus.
 * S'appuie sur `req.socket.bytesRead`, qui progresse indépendamment de qui
 * consomme le flux — n'interfère donc pas avec la lecture faite par Multer.
 */
const trackUploadProgress = (req, res, next) => {
  const contentLength = parseInt(req.headers['content-length'], 10) || null;
  const startedAt = Date.now();
  let bodyReceived = false;

  logger.info('Upload request received', {
    event: 'upload_request_received',
    contentLength,
    contentType: req.headers['content-type'],
    ip: req.ip,
  });

  const progressInterval = setInterval(() => {
    const bytesRead = req.socket?.bytesRead ?? 0;
    logger.debug('Upload request in progress', {
      event: 'upload_request_progress',
      bytesRead,
      contentLength,
      percent: contentLength ? Math.round((bytesRead / contentLength) * 100) : null,
      elapsedMs: Date.now() - startedAt,
    });
  }, PROGRESS_LOG_INTERVAL_MS);

  req.on('end', () => {
    bodyReceived = true;
    logger.debug('Upload request body fully received', {
      event: 'upload_request_body_received',
      bytesRead: req.socket?.bytesRead ?? 0,
      elapsedMs: Date.now() - startedAt,
    });
  });

  // 'close' se déclenche dans tous les cas (fin normale ou interruption) —
  // le flag bodyReceived permet de ne signaler que les interruptions.
  req.on('close', () => {
    clearInterval(progressInterval);
    if (!bodyReceived) {
      logger.warn('Upload request interrupted before body fully received', {
        event: 'upload_request_interrupted',
        bytesRead: req.socket?.bytesRead ?? 0,
        contentLength,
        elapsedMs: Date.now() - startedAt,
      });
    }
  });

  next();
};

module.exports = upload;
module.exports.QUARANTINE_DIR = QUARANTINE_DIR;
module.exports.trackUploadProgress = trackUploadProgress;
