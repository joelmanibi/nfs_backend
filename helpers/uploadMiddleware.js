'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const multer = require('multer');

// ─── Taille max configurable via .env (défaut : 1 Go) ────────────────────────
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE_MB || '1024', 10) * 1024 * 1024;

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

module.exports = upload;
module.exports.QUARANTINE_DIR = QUARANTINE_DIR;
