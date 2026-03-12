'use strict';

const fs                                  = require('fs');
const path                                = require('path');
const { randomUUID }                      = require('crypto');
const { pipeline }                        = require('stream');
const { promisify }                       = require('util');
const bcrypt                              = require('bcryptjs');
const { File, ShareLink, sequelize }      = require('../models');
const { encryptToFile, createDecipherStream } = require('../../helpers/crypto');
const { scanBuffer }                      = require('../../helpers/antivirus');
const { sendFileReceivedEmail, sendShareLinkEmail } = require('../../helpers/mailer');
const logger                              = require('../../config/logger');

const FRONTEND_URL   = process.env.FRONTEND_URL || 'http://localhost:3000';
const MAX_LINK_HOURS = 30 * 24; // 720 h

const pipelineAsync   = promisify(pipeline);
const ENCRYPTED_DIR   = path.resolve('assets', 'encrypted');
const BCRYPT_ROUNDS   = 12;

const buildAuditMeta = (req, extra = {}) => ({
  userId: req.user?.id,
  userEmail: req.user?.email?.toLowerCase(),
  ip: req.ip,
  userAgent: req.get('user-agent'),
  ...extra,
});

// ─── Upload ───────────────────────────────────────────────────────────────────
const uploadFile = async (req, res) => {
  let encryptedPath  = null;
  let anyPersisted   = false;

  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Aucun fichier fourni.' });
    }

    const {
      receiverEmail,
      receiverEmails: receiverEmailsRaw,
      isProtected,
      downloadCode,
      sendViaLink,
      linkExpiresInHours: rawLinkHours,
    } = req.body;

    // ── Normalisation des destinataires ───────────────────────────────────────
    let emailList = [];
    if (receiverEmailsRaw) {
      try {
        const parsed = JSON.parse(receiverEmailsRaw);
        emailList = Array.isArray(parsed) ? parsed : [parsed];
      } catch {
        emailList = [receiverEmailsRaw];
      }
    } else if (receiverEmail) {
      emailList = [receiverEmail];
    }

    emailList = [...new Set(
      emailList.map((e) => String(e).toLowerCase().trim()).filter(Boolean)
    )];

    if (!emailList.length) {
      return res.status(400).json({ message: 'Au moins un email destinataire est requis.' });
    }

    const protected_            = isProtected === 'true' || isProtected === true;
    const normalizedDownloadCode = protected_ ? downloadCode?.trim() : null;
    const viaLink               = sendViaLink === 'true' || sendViaLink === true;
    const linkHours             = Math.min(
      parseInt(rawLinkHours, 10) || 24,
      MAX_LINK_HOURS,
    );

    const uploadMeta = buildAuditMeta(req, {
      receiverEmails: emailList,
      originalName: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype,
      isProtected: protected_,
    });

    if (protected_ && !normalizedDownloadCode) {
      return res.status(400).json({ message: 'downloadCode requis pour un fichier protégé.' });
    }

    logger.info('Antivirus scan started', {
      event: 'antivirus_scan_started',
      ...uploadMeta,
    });

    const scanResult = await scanBuffer(req.file.buffer);
    const scanMeta = {
      ...uploadMeta,
      event: `antivirus_scan_${scanResult.status}`,
      antivirusHost: scanResult.config.host,
      antivirusPort: scanResult.config.port,
      antivirusFailOnError: scanResult.config.failOnError,
      antivirusEnabled: scanResult.config.enabled,
    };

    if (scanResult.status === 'infected') {
      logger.warn('Antivirus detected malware', {
        ...scanMeta,
        threat: scanResult.threat,
        rawResponse: scanResult.rawResponse,
      });

      return res.status(422).json({ message: 'Le fichier a été rejeté par l’antivirus.' });
    }

    if (scanResult.status === 'error') {
      logger[scanResult.config.failOnError ? 'error' : 'warn']('Antivirus scan failed', {
        ...scanMeta,
        error: scanResult.error,
        fallbackToUpload: !scanResult.config.failOnError,
      });

      if (scanResult.config.failOnError) {
        return res.status(503).json({
          message: 'Le service antivirus est indisponible. Réessayez plus tard.',
        });
      }
    }

    if (scanResult.status === 'clean') {
      logger.info('Antivirus scan clean', {
        ...scanMeta,
        rawResponse: scanResult.rawResponse,
      });
    }

    if (scanResult.status === 'skipped') {
      logger.warn('Antivirus scan skipped', {
        ...scanMeta,
        reason: scanResult.reason,
      });
    }

    // ── Chiffrement (une seule fois, partagé entre tous les destinataires) ──
    const sharedFileId = randomUUID();
    const destPath     = path.join(ENCRYPTED_DIR, sharedFileId);
    encryptedPath      = destPath;
    const iv           = encryptToFile(req.file.buffer, destPath);

    // ── Hash du code de protection ──
    const downloadCodeHash = protected_
      ? await bcrypt.hash(normalizedDownloadCode, BCRYPT_ROUNDS)
      : null;

    // ── Création des enregistrements DB dans une transaction ──────────────────
    const createdRecords = [];
    const t = await sequelize.transaction();
    try {
      for (const email of emailList) {
        const fileId = randomUUID();
        const record = await File.create({
          id:            fileId,
          senderId:      req.user.id,
          receiverEmail: email,
          originalName:  req.file.originalname,
          encryptedPath: destPath,
          size:          req.file.size,
          isProtected:   protected_,
          downloadCodeHash,
          iv,
        }, { transaction: t });

        let shareLink = null;
        if (viaLink) {
          const token     = randomUUID().replace(/-/g, '');
          const expiresAt = new Date(Date.now() + linkHours * 3600 * 1000);
          shareLink = await ShareLink.create({ fileId, token, expiresAt }, { transaction: t });
        }

        createdRecords.push({ record, shareLink });
      }
      await t.commit();
      anyPersisted = true;
    } catch (dbErr) {
      await t.rollback();
      throw dbErr;
    }

    logger.info('File(s) uploaded', {
      event:      'file_upload_succeeded',
      sharedFileId,
      senderId:   req.user.id,
      recipients: emailList,
      originalName: req.file.originalname,
      size:       req.file.size,
      isProtected: protected_,
      viaLink,
    });

    // ── Envoi des emails (hors transaction — l'upload est considéré réussi) ──
    for (const { record, shareLink } of createdRecords) {
      try {
        if (viaLink && shareLink) {
          const shareUrl = `${FRONTEND_URL}/download/${shareLink.token}`;
          await sendShareLinkEmail({
            to: record.receiverEmail,
            fileId: record.id,
            senderEmail: req.user.email,
            originalName: record.originalName,
            size: record.size,
            isProtected: record.isProtected,
            downloadCode: normalizedDownloadCode,
            shareUrl,
            expiresAt: shareLink.expiresAt,
          });
        } else {
          await sendFileReceivedEmail({
            to: record.receiverEmail,
            fileId: record.id,
            senderEmail: req.user.email,
            originalName: record.originalName,
            size: record.size,
            isProtected: record.isProtected,
            downloadCode: normalizedDownloadCode,
          });
        }
      } catch (mailError) {
        logger.error('Recipient notification email failed', {
          event: 'file_recipient_email_failed',
          fileId: record.id,
          receiverEmail: record.receiverEmail,
          error: mailError.message,
        });
      }
    }

    return res.status(201).json({
      message: `Fichier envoyé à ${createdRecords.length} destinataire(s).`,
      files: createdRecords.map(({ record, shareLink }) => ({
        id:            record.id,
        originalName:  record.originalName,
        size:          record.size,
        isProtected:   record.isProtected,
        receiverEmail: record.receiverEmail,
        createdAt:     record.createdAt,
        shareToken:    shareLink?.token ?? null,
        shareExpiresAt: shareLink?.expiresAt ?? null,
      })),
    });
  } catch (err) {
    if (encryptedPath && !anyPersisted && fs.existsSync(encryptedPath)) {
      try { fs.unlinkSync(encryptedPath); } catch (cleanupError) {
        logger.error('Encrypted upload cleanup failed', {
          event: 'file_upload_cleanup_failed',
          encryptedPath,
          error: cleanupError.message,
        });
      }
    }

    logger.error('Upload error', {
      event: 'file_upload_failed',
      error: err.message,
      ...buildAuditMeta(req, {
        originalName: req.file?.originalname,
        size: req.file?.size,
      }),
    });

    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

// ─── Download ─────────────────────────────────────────────────────────────────
const downloadFile = async (req, res) => {
  try {
    const { id }           = req.params;
    const { downloadCode } = req.body;

    logger.info('File download attempt', {
      event: 'file_download_attempt',
      ...buildAuditMeta(req, { fileId: id }),
    });

    const file = await File.findByPk(id);
    if (!file) {
      logger.warn('File download target not found', {
        event: 'file_download_not_found',
        ...buildAuditMeta(req, { fileId: id }),
      });

      return res.status(404).json({ message: 'Fichier introuvable.' });
    }

    const downloadMeta = buildAuditMeta(req, {
      fileId: id,
      receiverEmail: file.receiverEmail,
      originalName: file.originalName,
      size: file.size,
      isProtected: file.isProtected,
    });

    // Seul le destinataire peut télécharger
    if (file.receiverEmail !== req.user.email.toLowerCase()) {
      logger.warn('File download denied', {
        event: 'file_download_denied',
        ...downloadMeta,
        reason: 'recipient_mismatch',
      });

      return res.status(403).json({ message: 'Accès refusé.' });
    }

    // Vérification du code pour les fichiers protégés
    if (file.isProtected) {
      if (!downloadCode?.trim()) {
        logger.warn('File download code missing', {
          event: 'file_download_code_missing',
          ...downloadMeta,
        });

        return res.status(400).json({ message: 'Ce fichier est protégé. Fournissez le downloadCode.' });
      }

      const valid = await bcrypt.compare(downloadCode.trim(), file.downloadCodeHash);
      if (!valid) {
        logger.warn('Invalid downloadCode', {
          event: 'file_download_code_invalid',
          ...downloadMeta,
        });

        return res.status(401).json({ message: 'Code de téléchargement invalide.' });
      }
    }

    if (!fs.existsSync(file.encryptedPath)) {
      logger.error('Encrypted file missing', {
        event: 'file_download_storage_missing',
        ...downloadMeta,
        encryptedPath: file.encryptedPath,
      });

      return res.status(500).json({ message: 'Fichier physique introuvable.' });
    }

    logger.info('File download started', {
      event: 'file_download_started',
      ...downloadMeta,
    });

    // ── Streaming déchiffrement → client (jamais persisté en clair) ──
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.originalName)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');

    const readStream    = fs.createReadStream(file.encryptedPath);
    const decipherStream = createDecipherStream(file.iv);

    await pipelineAsync(readStream, decipherStream, res);

    logger.info('File download succeeded', {
      event: 'file_download_succeeded',
      ...downloadMeta,
    });
  } catch (err) {
    logger.error('Download error', {
      event: 'file_download_failed',
      error: err.message,
      ...buildAuditMeta(req, { fileId: req.params?.id }),
    });

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

