'use strict';

const multer = require('multer');

// ─── Taille max configurable via .env (défaut : 1 Go) ────────────────────────
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE_MB || '1024', 10) * 1024 * 1024;

// ─── Instance Multer ──────────────────────────────────────────────────────────
/**
 * Tous les types de fichiers sont acceptés.
 * memoryStorage : le fichier reste en RAM (req.file.buffer).
 * Il n'est JAMAIS écrit en clair sur le disque.
 * Le chiffrement AES-256-CBC est appliqué avant toute persistance.
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
  },
});

module.exports = upload;

