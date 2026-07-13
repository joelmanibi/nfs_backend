'use strict';

const fs                       = require('fs');
const path                     = require('path');
const { randomUUID }           = require('crypto');
const { promisify }            = require('util');
const { pipeline }             = require('stream');
const bcrypt                   = require('bcryptjs');
const { File, ShareLink, DownloadLog } = require('../models');
const { createDecipherStream } = require('../../helpers/crypto');
const { NON_DOWNLOADABLE_STATUS } = require('./fileController');
const logger                   = require('../../config/logger');

const pipelineAsync  = promisify(pipeline);
const ENCRYPTED_DIR  = path.resolve('assets', 'encrypted');

// Durée max autorisée : 15 jours
const MAX_HOURS       = 15 * 24;
const RETENTION_DAYS  = parseInt(process.env.PURGE_RETENTION_DAYS, 10) || 15;
const RETENTION_MS    = RETENTION_DAYS * 24 * 60 * 60 * 1000;

// ─── Créer un lien de partage ─────────────────────────────────────────────────
/**
 * POST /api/files/:id/share
 * Body: { expiresInHours: number }   (1 – 720)
 * Auth requise : l'expéditeur du fichier uniquement.
 */
const createShareLink = async (req, res) => {
  try {
    const { id } = req.params;
    const expiresInHours = parseInt(req.body.expiresInHours, 10);

    if (!expiresInHours || expiresInHours < 1 || expiresInHours > MAX_HOURS) {
      return res.status(400).json({
        message: `expiresInHours doit être compris entre 1 et ${MAX_HOURS}.`,
      });
    }

    const file = await File.findByPk(id);
    if (!file) {
      return res.status(404).json({ message: 'Fichier introuvable.' });
    }

    // Seul l'expéditeur peut générer un lien
    if (file.senderId !== req.user.id) {
      return res.status(403).json({ message: 'Accès refusé.' });
    }

    const token     = randomUUID().replace(/-/g, '');
    const expiresAt = new Date(Date.now() + expiresInHours * 3600 * 1000);

    const link = await ShareLink.create({ fileId: id, token, expiresAt });

    logger.info('Share link created', {
      event: 'share_link_created',
      fileId: id,
      token,
      expiresAt,
      createdBy: req.user.id,
    });

    return res.status(201).json({
      token:     link.token,
      expiresAt: link.expiresAt,
    });
  } catch (err) {
    logger.error('Share link creation failed', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

// ─── Télécharger via lien public ──────────────────────────────────────────────
/**
 * POST /api/share/:token/download
 * Public — aucun JWT requis.
 * Body (JSON, optionnel si fichier protégé): { downloadCode }
 */
const downloadViaToken = async (req, res) => {
  try {
    const { token } = req.params;

    const link = await ShareLink.findOne({
      where: { token },
      include: [{ model: File, as: 'file' }],
    });

    if (!link) {
      return res.status(404).json({ message: 'Lien de partage introuvable.' });
    }

    if (new Date() > link.expiresAt) {
      return res.status(410).json({
        message: "Ce lien a expiré. Demandez un nouveau lien à l'expéditeur.",
      });
    }

    const file = link.file;

    // Fichier expiré (durée de vie = 15 jours à partir de la création)
    const fileExpiresAt = new Date(new Date(file.createdAt).getTime() + RETENTION_MS);
    if (fileExpiresAt < new Date()) {
      return res.status(410).json({
        message: `Ce fichier a expiré le ${fileExpiresAt.toLocaleDateString('fr-FR')}. Il a été supprimé automatiquement.`,
        expired: true,
      });
    }

    // L'expéditeur a bloqué le fichier
    if (file.isBlocked) {
      logger.warn('Public share download denied — blocked by sender', {
        event: 'share_link_download_blocked',
        token,
        fileId: file.id,
      });
      return res.status(403).json({ message: 'Ce fichier a été bloqué par l\'expéditeur.' });
    }

    // Fichier pas encore scanné / rejeté / échec de scan → pas de téléchargement
    if (file.status !== 'clean') {
      const [statusCode, message] = NON_DOWNLOADABLE_STATUS[file.status] || [422, 'Ce fichier n’est pas disponible.'];
      logger.warn('Public share download denied — not clean', {
        event: 'share_link_download_not_clean',
        token,
        fileId: file.id,
        status: file.status,
      });
      return res.status(statusCode).json({ message, status: file.status });
    }

    // Reconstruction du chemin absolu (rétrocompat : anciens enregistrements ont un chemin absolu)
    const fullEncryptedPath = file && (
      path.isAbsolute(file.encryptedPath)
        ? file.encryptedPath
        : path.join(ENCRYPTED_DIR, file.encryptedPath)
    );
    if (!file || !fs.existsSync(fullEncryptedPath)) {
      return res.status(404).json({ message: 'Fichier source introuvable.' });
    }

    // ── Vérification du code de protection ───────────────────────────────────
    if (file.isProtected) {
      const { downloadCode } = req.body;

      if (!downloadCode?.trim()) {
        return res.status(400).json({
          message: 'Ce fichier est protégé. Fournissez le code de téléchargement.',
          requiresCode: true,
        });
      }

      const valid = await bcrypt.compare(downloadCode.trim(), file.downloadCodeHash);
      if (!valid) {
        logger.warn('Share link download: invalid code', { token, fileId: file.id });
        return res.status(401).json({ message: 'Code de téléchargement invalide.' });
      }
    }

    logger.info('Public share download', {
      event: 'share_link_download',
      token,
      fileId: file.id,
      originalName: file.originalName,
    });

    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${encodeURIComponent(file.originalName)}"`,
    );
    res.setHeader('Content-Type', 'application/octet-stream');

    const readStream     = fs.createReadStream(fullEncryptedPath);
    const decipherStream = createDecipherStream(file.iv);

    await pipelineAsync(readStream, decipherStream, res);

    // ── Enregistrer le statut de téléchargement + l'historique (comme pour le téléchargement authentifié) ──
    await file.update({
      downloadedAt: new Date(),
      downloadedBy: file.receiverEmail,
    });
    await DownloadLog.create({
      fileId:       file.id,
      downloadedBy: file.receiverEmail,
      method:       'link',
      ip:           req.ip,
      userAgent:    req.get('user-agent') || null,
    });

    logger.info('Public share download succeeded', {
      event: 'share_link_download_succeeded',
      token,
      fileId: file.id,
    });
  } catch (err) {
    logger.error('Public share download failed', { error: err.message });
    if (!res.headersSent) {
      return res.status(500).json({ message: 'Erreur interne.', error: err.message });
    }
  }
};

// ─── Infos publiques du lien (sans télécharger) ───────────────────────────────
/**
 * GET /api/share/:token
 * Public — retourne les métadonnées du fichier si le lien est valide.
 */
const getShareLinkInfo = async (req, res) => {
  try {
    const { token } = req.params;

    const link = await ShareLink.findOne({
      where: { token },
      include: [{ model: File, as: 'file', attributes: ['originalName', 'size', 'isProtected', 'status', 'isBlocked'] }],
    });

    if (!link) {
      return res.status(404).json({ message: 'Lien de partage introuvable.' });
    }

    if (new Date() > link.expiresAt) {
      return res.status(410).json({
        message: 'Ce lien a expiré.',
        expired: true,
      });
    }

    return res.status(200).json({
      originalName: link.file.originalName,
      size:         link.file.size,
      isProtected:  link.file.isProtected,
      status:       link.file.status,
      isBlocked:    link.file.isBlocked,
      expiresAt:    link.expiresAt,
    });
  } catch (err) {
    logger.error('Share link info failed', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

module.exports = { createShareLink, downloadViaToken, getShareLinkInfo };

