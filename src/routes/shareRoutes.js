'use strict';

const { Router } = require('express');
const {
  downloadViaToken,
  getShareLinkInfo,
} = require('../controllers/shareController');

const router = Router();

// ─── Routes publiques (pas de JWT requis) ─────────────────────────────────────
// GET /api/share/:token            → infos du fichier (nom, taille, expiry)
router.get('/:token', getShareLinkInfo);

// POST /api/share/:token/download  → téléchargement direct (body: { downloadCode? })
router.post('/:token/download', downloadViaToken);

module.exports = router;

