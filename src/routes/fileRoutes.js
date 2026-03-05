'use strict';

const { Router } = require('express');
const upload     = require('../../helpers/uploadMiddleware');
const { verifyToken } = require('../middleware/authMiddleware');
const {
  uploadFile,
  downloadFile,
  getInbox,
  getSent,
} = require('../controllers/fileController');

const router = Router();

// Toutes les routes fichiers requièrent un JWT valide
router.use(verifyToken);

// ─── Upload ───────────────────────────────────────────────────────────────────
// POST /api/files/upload
// Body (multipart/form-data): file, receiverEmail, isProtected?, downloadCode?
router.post('/upload', upload.single('file'), uploadFile);

// ─── Download ─────────────────────────────────────────────────────────────────
// POST /api/files/:id/download
// Body (JSON): { downloadCode? }
router.post('/:id/download', downloadFile);

// ─── Inbox / Sent ─────────────────────────────────────────────────────────────
// GET /api/files/inbox
router.get('/inbox', getInbox);

// GET /api/files/sent
router.get('/sent', getSent);

module.exports = router;

