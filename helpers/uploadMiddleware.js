'use strict';

const multer = require('multer');

// ─── MIME types autorisés ─────────────────────────────────────────────────────
const ALLOWED_MIMETYPES = new Set([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'image/jpeg',
  'image/png',
]);

// Taille max configurable via .env (défaut : 10 Mo)
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE_MB || '10', 10) * 1024 * 1024;

// ─── Filtre MIME ──────────────────────────────────────────────────────────────
const fileFilter = (req, file, cb) => {
  if (ALLOWED_MIMETYPES.has(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error(
        'Type de fichier non autorisé. Formats acceptés : PDF, Word, Excel, JPEG, PNG.',
      ),
      false,
    );
  }
};

// ─── Instance Multer ──────────────────────────────────────────────────────────
/**
 * memoryStorage : le fichier reste en RAM (req.file.buffer).
 * Il n'est JAMAIS écrit en clair sur le disque.
 * Le chiffrement AES-256-CBC est appliqué avant toute persistance.
 */
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
  },
});

module.exports = upload;

