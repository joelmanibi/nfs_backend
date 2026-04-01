'use strict';

const fs                                  = require('fs');
const path                                = require('path');
const { randomUUID }                      = require('crypto');
const { pipeline }                        = require('stream');
const { promisify }                       = require('util');
const bcrypt                              = require('bcryptjs');
const { Op }                               = require('sequelize');
const { File, ShareLink, User, sequelize } = require('../models');
const { encryptToFile, createDecipherStream } = require('../../helpers/crypto');
const { scanBuffer }                      = require('../../helpers/antivirus');
const { sendFileReceivedEmail, sendShareLinkEmail, sendDownloadCodeEmail } = require('../../helpers/mailer');
const logger                              = require('../../config/logger');

const FRONTEND_URL   = process.env.FRONTEND_URL || 'http://10.112.30.143:3000';
const MAX_LINK_HOURS = 30 * 24; // 720 h

const pipelineAsync   = promisify(pipeline);
const ENCRYPTED_DIR   = path.resolve('assets', 'encrypted');
const BCRYPT_ROUNDS   = 12;

// ─── Référence unique DOC-YYYY-MM-XX-DDHHmmSS ────────────────────────────────
const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
function generateReference() {
  const now = new Date();
  const YYYY = now.getFullYear();
  const MM   = String(now.getMonth() + 1).padStart(2, '0');
  const DD   = String(now.getDate()).padStart(2, '0');
  const HH   = String(now.getHours()).padStart(2, '0');
  const mm   = String(now.getMinutes()).padStart(2, '0');
  const SS   = String(now.getSeconds()).padStart(2, '0');
  const R1   = LETTERS[Math.floor(Math.random() * 26)];
  const R2   = LETTERS[Math.floor(Math.random() * 26)];
  return `DOC-${YYYY}-${MM}-${R1}${R2}-${DD}${HH}${mm}${SS}`;
}

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

    // ── Correction encodage filename (busboy décode en latin-1, le navigateur envoie UTF-8) ──
    const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');

    const {
      receiverEmail,
      receiverEmails: receiverEmailsRaw,
      isProtected,
      downloadCode,
      sendViaLink,
      linkExpiresInHours: rawLinkHours,
      comment,
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

    // ── Règle métier : un utilisateur externe ne peut pas envoyer à un externe ──
    const senderRecord = await User.findByPk(req.user.id, { attributes: ['isInternalUser'] });
    if (senderRecord && !senderRecord.isInternalUser) {
      const recipientRecords = await User.findAll({
        where: { email: { [Op.in]: emailList } },
        attributes: ['email', 'isInternalUser'],
      });

      // Map email → isInternalUser pour lookup rapide
      const recipientMap = new Map(
        recipientRecords.map((r) => [r.email.toLowerCase(), r.isInternalUser]),
      );

      // Bloquer si le destinataire est externe (isInternalUser=false) ou inconnu
      const blockedEmails = emailList.filter(
        (e) => !recipientMap.has(e) || recipientMap.get(e) === false,
      );

      if (blockedEmails.length > 0) {
        logger.warn('External-to-external file transfer blocked', {
          event: 'file_upload_ext_to_ext_blocked',
          ...buildAuditMeta(req, { blockedRecipients: blockedEmails }),
        });
        return res.status(403).json({
          message: 'Un utilisateur externe ne peut pas envoyer de fichier à un autre utilisateur externe. Veuillez sélectionner uniquement des destinataires internes.',
        });
      }
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
      originalName,
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
    // On ne stocke que le nom du fichier (UUID), pas le chemin absolu.
    // Cela rend le système portable en cas de changement de serveur.

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
          reference:     generateReference(),
          senderId:      req.user.id,
          receiverEmail: email,
          originalName:  originalName,
          encryptedPath: sharedFileId,
          size:          req.file.size,
          isProtected:   protected_,
          downloadCodeHash,
          iv,
          comment:       comment?.trim() || null,
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
      originalName,
      size:       req.file.size,
      isProtected: protected_,
      viaLink,
    });

    // ── Envoi des emails (hors transaction — l'upload est considéré réussi) ──

    // Récupération du prénom de l'expéditeur depuis la base de données
    let senderFirstName = req.user.firstName || '—';
    try {
      const senderUser = await User.findByPk(req.user.id, { attributes: ['firstName'] });
      if (senderUser?.firstName) senderFirstName = senderUser.firstName;
    } catch (lookupErr) {
      logger.warn('Could not fetch sender firstName from DB, using token value', { error: lookupErr.message });
    }

    for (const { record, shareLink } of createdRecords) {
      try {
        // ── Mail 1 : notification avec lien ou accès plateforme ──────────────
        if (viaLink && shareLink) {
          const shareUrl = `${FRONTEND_URL}/download/${shareLink.token}`;
          await sendShareLinkEmail({
            to:              record.receiverEmail,
            fileId:          record.id,
            senderFirstName,
            reference:       record.reference,
            isProtected:     record.isProtected,
            shareUrl,
            comment:         comment?.trim() || null,
          });
        } else {
          await sendFileReceivedEmail({
            to:              record.receiverEmail,
            fileId:          record.id,
            senderFirstName,
            originalName:    record.originalName,
            reference:       record.reference,
            size:            record.size,
            isProtected:     record.isProtected,
            comment:         comment?.trim() || null,
          });
        }

        // ── Mail 2 : code confidentiel (uniquement si fichier protégé) ───────
        if (record.isProtected && normalizedDownloadCode) {
          await sendDownloadCodeEmail({
            to:           record.receiverEmail,
            fileId:       record.id,
            senderFirstName,
            reference:    record.reference,
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
        originalName: req.file?.originalname
          ? Buffer.from(req.file.originalname, 'latin1').toString('utf8')
          : undefined,
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

    // L'expéditeur a bloqué le fichier
    if (file.isBlocked) {
      logger.warn('File download blocked by sender', {
        event: 'file_download_blocked',
        ...buildAuditMeta(req, { fileId: id }),
      });
      return res.status(403).json({ message: 'Ce fichier a été bloqué par l\'expéditeur.' });
    }

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

    // Reconstruction du chemin absolu (rétrocompat : anciens enregistrements ont déjà un chemin absolu)
    const fullEncryptedPath = path.isAbsolute(file.encryptedPath)
      ? file.encryptedPath
      : path.join(ENCRYPTED_DIR, file.encryptedPath);

    if (!fs.existsSync(fullEncryptedPath)) {
      logger.error('Encrypted file missing', {
        event: 'file_download_storage_missing',
        ...downloadMeta,
        encryptedPath: fullEncryptedPath,
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

    const readStream    = fs.createReadStream(fullEncryptedPath);
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
      attributes: { exclude: ['encryptedPath', 'downloadCodeHash', 'iv'] },
      include: [
        {
          model: User,
          as: 'sender',
          attributes: ['id', 'email', 'firstName', 'lastName', 'organisation'],
        },
      ],
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

// ─── Bloquer / Débloquer un fichier envoyé ────────────────────────────────────
const blockFile = async (req, res) => {
  try {
    const { id } = req.params;
    const file = await File.findByPk(id);

    if (!file) return res.status(404).json({ message: 'Fichier introuvable.' });
    if (file.senderId !== req.user.id)
      return res.status(403).json({ message: 'Accès refusé.' });

    file.isBlocked = !file.isBlocked;
    await file.save();

    logger.info(file.isBlocked ? 'File blocked' : 'File unblocked', {
      event: file.isBlocked ? 'file_blocked' : 'file_unblocked',
      ...buildAuditMeta(req, { fileId: id }),
    });

    return res.json({ isBlocked: file.isBlocked });
  } catch (err) {
    logger.error('blockFile error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Supprimer un fichier envoyé ─────────────────────────────────────────────
const deleteFile = async (req, res) => {
  try {
    const { id } = req.params;
    const file = await File.findByPk(id);

    if (!file) return res.status(404).json({ message: 'Fichier introuvable.' });
    if (file.senderId !== req.user.id)
      return res.status(403).json({ message: 'Accès refusé.' });

    // Reconstruction du chemin absolu (rétrocompat)
    const storedPath = file.encryptedPath;
    const encPath = path.isAbsolute(storedPath)
      ? storedPath
      : path.join(ENCRYPTED_DIR, storedPath);

    // Vérifier si d'autres fichiers partagent le même chemin physique
    const siblingsCount = await File.count({ where: { encryptedPath: storedPath } });

    await file.destroy();

    // Supprimer le fichier physique seulement si c'était le dernier lien vers lui
    if (siblingsCount <= 1 && fs.existsSync(encPath)) {
      try { fs.unlinkSync(encPath); } catch (e) {
        logger.warn('Physical file deletion failed', { encPath, error: e.message });
      }
    }

    logger.info('File deleted by sender', {
      event: 'file_deleted_by_sender',
      ...buildAuditMeta(req, { fileId: id }),
    });

    return res.json({ message: 'Fichier supprimé.' });
  } catch (err) {
    logger.error('deleteFile error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

module.exports = { uploadFile, downloadFile, getInbox, getSent, blockFile, deleteFile };

