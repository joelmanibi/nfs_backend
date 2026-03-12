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
const { createShareLink } = require('../controllers/shareController');

const router = Router();

// Toutes les routes fichiers requièrent un JWT valide
router.use(verifyToken);

// ─── Upload ───────────────────────────────────────────────────────────────────
// POST /api/files/upload
router.post('/upload', upload.single('file'), uploadFile);

// ─── Download ─────────────────────────────────────────────────────────────────
// POST /api/files/:id/download
router.post('/:id/download', downloadFile);

// ─── Share link ───────────────────────────────────────────────────────────────
// POST /api/files/:id/share
router.post('/:id/share', createShareLink);

// ─── Inbox / Sent ─────────────────────────────────────────────────────────────
// GET /api/files/inbox
router.get('/inbox', getInbox);

// GET /api/files/sent
router.get('/sent', getSent);

module.exports = router;

