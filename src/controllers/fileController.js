'use strict';

const fs                                  = require('fs');
const path                                = require('path');
const { randomUUID }                      = require('crypto');
const { pipeline }                        = require('stream');
const { promisify }                       = require('util');
const bcrypt                              = require('bcryptjs');
const { File }                            = require('../models');
const { encryptToFile, createDecipherStream } = require('../../helpers/crypto');
const logger                              = require('../../config/logger');

const pipelineAsync   = promisify(pipeline);
const ENCRYPTED_DIR   = path.resolve('assets', 'encrypted');
const BCRYPT_ROUNDS   = 12;

// ─── Upload ───────────────────────────────────────────────────────────────────
const uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Aucun fichier fourni.' });
    }

    const { receiverEmail, isProtected, downloadCode } = req.body;

    if (!receiverEmail?.trim()) {
      return res.status(400).json({ message: 'receiverEmail est requis.' });
    }

    const protected_ = isProtected === 'true' || isProtected === true;

    if (protected_ && !downloadCode?.trim()) {
      return res.status(400).json({ message: 'downloadCode requis pour un fichier protégé.' });
    }

    // ── ID partagé entre nom de fichier sur disque et PK en DB ──
    const fileId  = randomUUID();
    const destPath = path.join(ENCRYPTED_DIR, fileId);

    // ── Chiffrement AES-256-CBC (buffer mémoire → disque chiffré) ──
    const iv = encryptToFile(req.file.buffer, destPath);

    // ── Hash du code de protection ──
    const downloadCodeHash = protected_
      ? await bcrypt.hash(downloadCode.trim(), BCRYPT_ROUNDS)
      : null;

    const record = await File.create({
      id:            fileId,
      senderId:      req.user.id,
      receiverEmail: receiverEmail.toLowerCase().trim(),
      originalName:  req.file.originalname,
      encryptedPath: destPath,
      size:          req.file.size,
      isProtected:   protected_,
      downloadCodeHash,
      iv,
    });

    logger.info('File uploaded', {
      fileId:        record.id,
      senderId:      req.user.id,
      receiverEmail: record.receiverEmail,
      size:          record.size,
      isProtected:   record.isProtected,
    });

    return res.status(201).json({
      message: 'Fichier envoyé avec succès.',
      file: {
        id:            record.id,
        originalName:  record.originalName,
        size:          record.size,
        isProtected:   record.isProtected,
        receiverEmail: record.receiverEmail,
        createdAt:     record.createdAt,
      },
    });
  } catch (err) {
    logger.error('Upload error', { error: err.message, userId: req.user?.id });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

// ─── Download ─────────────────────────────────────────────────────────────────
const downloadFile = async (req, res) => {
  try {
    const { id }           = req.params;
    const { downloadCode } = req.body;

    const file = await File.findByPk(id);
    if (!file) {
      return res.status(404).json({ message: 'Fichier introuvable.' });
    }

    // Seul le destinataire peut télécharger
    if (file.receiverEmail !== req.user.email.toLowerCase()) {
      return res.status(403).json({ message: 'Accès refusé.' });
    }

    // Vérification du code pour les fichiers protégés
    if (file.isProtected) {
      if (!downloadCode?.trim()) {
        return res.status(400).json({ message: 'Ce fichier est protégé. Fournissez le downloadCode.' });
      }
      const valid = await bcrypt.compare(downloadCode.trim(), file.downloadCodeHash);
      if (!valid) {
        logger.warn('Invalid downloadCode', { fileId: id, userId: req.user.id });
        return res.status(401).json({ message: 'Code de téléchargement invalide.' });
      }
    }

    if (!fs.existsSync(file.encryptedPath)) {
      logger.error('Encrypted file missing', { fileId: id });
      return res.status(500).json({ message: 'Fichier physique introuvable.' });
    }

    logger.info('File downloaded', { fileId: id, userId: req.user.id });

    // ── Streaming déchiffrement → client (jamais persisté en clair) ──
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');

    const readStream    = fs.createReadStream(file.encryptedPath);
    const decipherStream = createDecipherStream(file.iv);

    await pipelineAsync(readStream, decipherStream, res);
  } catch (err) {
    logger.error('Download error', { error: err.message, userId: req.user?.id });
    if (!res.headersSent) {
      return res.status(500).json({ message: 'Erreur interne.', error: err.message });
    }
  }
};

// ─── Inbox (fichiers reçus) ───────────────────────────────────────────────────
const getInbox = async (req, res) => {
  try {
    const files = await File.findAll({
      where: { receiverEmail: req.user.email.toLowerCase() },
      attributes: { exclude: ['encryptedPath', 'downloadCodeHash', 'iv', 'senderId'] },
      order: [['createdAt', 'DESC']],
    });
    return res.status(200).json({ count: files.length, files });
  } catch (err) {
    logger.error('Inbox error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

// ─── Sent (fichiers envoyés) ──────────────────────────────────────────────────
const getSent = async (req, res) => {
  try {
    const files = await File.findAll({
      where: { senderId: req.user.id },
      attributes: { exclude: ['encryptedPath', 'downloadCodeHash', 'iv'] },
      order: [['createdAt', 'DESC']],
    });
    return res.status(200).json({ count: files.length, files });
  } catch (err) {
    logger.error('Sent error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

module.exports = { uploadFile, downloadFile, getInbox, getSent };

