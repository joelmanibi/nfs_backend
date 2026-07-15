'use strict';

const fs                                  = require('fs');
const path                                = require('path');
const { randomUUID }                      = require('crypto');
const { pipeline }                        = require('stream');
const { promisify }                       = require('util');
const bcrypt                              = require('bcryptjs');
const { Op }                               = require('sequelize');
const { File, ShareLink, User, DownloadLog, sequelize } = require('../models');
const { generateIv, createDecipherStream } = require('../../helpers/crypto');
const { scanAndEncrypt, sendFileArrivedEmails, safeUnlink } = require('../../helpers/uploadProcessing');
const { getQueueConfig, enqueueScanJob }  = require('../../helpers/scanQueue');
const { sendDownloadCodeEmail }           = require('../../helpers/mailer');
const logger                              = require('../../config/logger');

// Statuts non téléchargeables + message associé (fileController + shareController).
const NON_DOWNLOADABLE_STATUS = {
  pending_scan: [423, 'Ce fichier est en cours d’analyse antivirus. Réessayez dans quelques instants.'],
  infected:     [422, 'Ce fichier a été rejeté par l’antivirus et n’est plus disponible.'],
  scan_failed:  [422, 'L’analyse antivirus de ce fichier a échoué. Le fichier n’est plus disponible.'],
};

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

const FRONTEND_URL      = process.env.FRONTEND_URL || 'https://securetransport.paa.ci';
const MAX_LINK_HOURS    = 15 * 24; // 360 h
const RETENTION_DAYS    = parseInt(process.env.PURGE_RETENTION_DAYS, 10) || 15;
const RETENTION_MS      = RETENTION_DAYS * 24 * 60 * 60 * 1000;

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

const resolveSenderFirstName = async (senderId, fallback = '—') => {
  try {
    const senderUser = await User.findByPk(senderId, { attributes: ['firstName'] });
    return senderUser?.firstName || fallback;
  } catch (lookupErr) {
    logger.warn('Could not fetch sender firstName from DB, using fallback value', { error: lookupErr.message });
    return fallback;
  }
};

// ── Mail 2 : code confidentiel (envoyé immédiatement, jamais différé — seul
// son hash est persisté, impossible de le renvoyer plus tard depuis le worker) ──
const sendDownloadCodeEmails = async (createdRecords, normalizedDownloadCode, senderFirstName) => {
  if (!normalizedDownloadCode) return;

  for (const { record } of createdRecords) {
    if (!record.isProtected) continue;
    try {
      await sendDownloadCodeEmail({
        to:           record.receiverEmail,
        fileId:       record.id,
        senderFirstName,
        reference:    record.reference,
        downloadCode: normalizedDownloadCode,
      });
    } catch (mailError) {
      logger.error('Download code email failed', {
        event: 'file_download_code_email_failed',
        fileId: record.id,
        receiverEmail: record.receiverEmail,
        error: mailError.message,
      });
    }
  }
};

// ─── Upload ───────────────────────────────────────────────────────────────────
const uploadFile = async (req, res) => {
  let quarantinePath    = null;
  let encryptedDestPath = null;
  let anyPersisted      = false;

  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Aucun fichier fourni.' });
    }

    // multer a déjà streamé le fichier sur disque (assets/quarantine/<uuid>) —
    // toute erreur à partir d'ici doit nettoyer ce plaintext temporaire.
    quarantinePath = req.file.path;

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
      throw new HttpError(400, 'Au moins un email destinataire est requis.');
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
        throw new HttpError(403, 'Un utilisateur externe ne peut pas envoyer de fichier à un autre utilisateur externe. Veuillez sélectionner uniquement des destinataires internes.');
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
      throw new HttpError(400, 'downloadCode requis pour un fichier protégé.');
    }

    // ── Identifiants partagés entre tous les destinataires ─────────────────────
    // Le nom généré par multer pour la quarantaine est réutilisé comme nom du
    // blob chiffré final (un seul UUID, portable en cas de changement de serveur).
    const sharedFileId = req.file.filename;
    encryptedDestPath   = path.join(ENCRYPTED_DIR, sharedFileId);
    // L'IV est indépendant du contenu : on peut le réserver avant le scan,
    // ce qui permet de persister les lignes File même en mode asynchrone
    // (chiffrement différé après scan).
    const iv = generateIv();

    const downloadCodeHash = protected_
      ? await bcrypt.hash(normalizedDownloadCode, BCRYPT_ROUNDS)
      : null;

    const queueConfig = getQueueConfig();

    // ═══════════════════════════════════════════════════════════════════════
    // Mode synchrone (dev, queue désactivée par défaut) : scan + chiffrement
    // avant de créer les enregistrements, comme aujourd'hui.
    // ═══════════════════════════════════════════════════════════════════════
    if (!queueConfig.enabled) {
      logger.info('Antivirus scan started', { event: 'antivirus_scan_started', ...uploadMeta });

      const { scanResult, encrypted } = await scanAndEncrypt({
        quarantinePath,
        encryptedDestPath,
        ivHex: iv,
        context: { sharedFileId },
      });

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

      if (!encrypted) {
        // Seul cas restant : erreur antivirus bloquante (ANTIVIRUS_FAIL_ON_ERROR=true).
        // scanAndEncrypt n'a délibérément pas supprimé le plaintext (retry possible
        // ailleurs) — en mode synchrone sans queue, on abandonne la requête ici.
        logger.error('Antivirus scan failed', { ...scanMeta, error: scanResult.error });
        safeUnlink(quarantinePath, { reason: 'sync_scan_error' });
        return res.status(503).json({
          message: 'Le service antivirus est indisponible. Réessayez plus tard.',
        });
      }

      if (scanResult.status === 'error') {
        logger.warn('Antivirus scan failed — upload autorisé (failOnError=false)', {
          ...scanMeta,
          error: scanResult.error,
          fallbackToUpload: true,
        });
      } else if (scanResult.status === 'clean') {
        logger.info('Antivirus scan clean', { ...scanMeta, rawResponse: scanResult.rawResponse });
      } else if (scanResult.status === 'skipped') {
        logger.warn('Antivirus scan skipped', { ...scanMeta, reason: scanResult.reason });
      }

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
            originalName,
            encryptedPath: sharedFileId,
            size:          req.file.size,
            isProtected:   protected_,
            downloadCodeHash,
            iv,
            comment:       comment?.trim() || null,
            status:        'clean',
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
      const senderFirstName = await resolveSenderFirstName(req.user.id, req.user.firstName || '—');
      await sendDownloadCodeEmails(createdRecords, normalizedDownloadCode, senderFirstName);
      await sendFileArrivedEmails(createdRecords.map(({ record }) => record.id));

      return res.status(201).json({
        message: `Fichier envoyé à ${createdRecords.length} destinataire(s).`,
        files: createdRecords.map(({ record, shareLink }) => ({
          id:            record.id,
          originalName:  record.originalName,
          size:          record.size,
          isProtected:   record.isProtected,
          receiverEmail: record.receiverEmail,
          createdAt:     record.createdAt,
          status:        record.status,
          shareToken:    shareLink?.token ?? null,
          shareExpiresAt: shareLink?.expiresAt ?? null,
        })),
      });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Mode asynchrone (prod, queue activée) : persiste en pending_scan et
    // répond immédiatement — le scan + chiffrement est traité par le worker
    // (helpers/scanQueue.js → helpers/uploadProcessing.js#processScanJob).
    // ═══════════════════════════════════════════════════════════════════════
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
          originalName,
          encryptedPath: sharedFileId,
          size:          req.file.size,
          isProtected:   protected_,
          downloadCodeHash,
          iv,
          comment:       comment?.trim() || null,
          status:        'pending_scan',
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

    logger.info('File(s) uploaded — queued for antivirus scan', {
      event:      'file_upload_queued',
      sharedFileId,
      senderId:   req.user.id,
      recipients: emailList,
      originalName,
      size:       req.file.size,
      isProtected: protected_,
      viaLink,
    });

    const senderFirstName = await resolveSenderFirstName(req.user.id, req.user.firstName || '—');
    await sendDownloadCodeEmails(createdRecords, normalizedDownloadCode, senderFirstName);

    const fileIds = createdRecords.map(({ record }) => record.id);
    try {
      await enqueueScanJob({ sharedFileId, quarantinePath, iv, fileIds });
    } catch (queueErr) {
      logger.error('Scan job enqueue failed — rolling back upload', {
        event: 'scan_job_enqueue_failed',
        sharedFileId,
        error: queueErr.message,
      });
      // Les ShareLink liés sont supprimés en cascade (FK onDelete CASCADE).
      await File.destroy({ where: { id: { [Op.in]: fileIds } } });
      safeUnlink(quarantinePath, { reason: 'enqueue_failed' });
      return res.status(503).json({
        message: 'Le service de mise en file d’attente est indisponible. Réessayez plus tard.',
      });
    }

    return res.status(202).json({
      message: `Fichier reçu pour ${createdRecords.length} destinataire(s), analyse antivirus en cours.`,
      files: createdRecords.map(({ record, shareLink }) => ({
        id:            record.id,
        originalName:  record.originalName,
        size:          record.size,
        isProtected:   record.isProtected,
        receiverEmail: record.receiverEmail,
        createdAt:     record.createdAt,
        status:        record.status,
        shareToken:    shareLink?.token ?? null,
        shareExpiresAt: shareLink?.expiresAt ?? null,
      })),
    });
  } catch (err) {
    if (quarantinePath) {
      safeUnlink(quarantinePath, { reason: 'upload_error' });
    }

    if (encryptedDestPath && !anyPersisted && fs.existsSync(encryptedDestPath)) {
      try { fs.unlinkSync(encryptedDestPath); } catch (cleanupError) {
        logger.error('Encrypted upload cleanup failed', {
          event: 'file_upload_cleanup_failed',
          encryptedPath: encryptedDestPath,
          error: cleanupError.message,
        });
      }
    }

    const statusCode = err.statusCode || 500;

    if (statusCode !== 500) {
      logger.warn('Upload rejected', {
        event: 'file_upload_rejected',
        statusCode,
        error: err.message,
        ...buildAuditMeta(req, {
          originalName: req.file?.originalname
            ? Buffer.from(req.file.originalname, 'latin1').toString('utf8')
            : undefined,
        }),
      });
      return res.status(statusCode).json({ message: err.message });
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

    // Fichier expiré (durée de vie = 15 jours)
    const expiresAt = new Date(new Date(file.createdAt).getTime() + RETENTION_MS);
    if (expiresAt < new Date()) {
      logger.warn('File download denied — expired', {
        event: 'file_download_expired',
        ...downloadMeta,
        expiresAt,
      });
      return res.status(410).json({
        message: `Ce fichier a expiré le ${expiresAt.toLocaleDateString('fr-FR')}. Il a été supprimé automatiquement.`,
        expired: true,
      });
    }

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

    // Fichier pas encore scanné / rejeté / échec de scan → pas de téléchargement
    if (file.status !== 'clean') {
      const [statusCode, message] = NON_DOWNLOADABLE_STATUS[file.status] || [422, 'Ce fichier n’est pas disponible.'];
      logger.warn('File download denied — not clean', {
        event: 'file_download_not_clean',
        ...downloadMeta,
        status: file.status,
      });
      return res.status(statusCode).json({ message, status: file.status });
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

    // ── Enregistrer le statut de téléchargement + l'historique ────────────────
    await file.update({
      downloadedAt: new Date(),
      downloadedBy: req.user.email.toLowerCase(),
    });
    await DownloadLog.create({
      fileId:       file.id,
      downloadedBy: req.user.email.toLowerCase(),
      method:       'direct',
      ip:           req.ip,
      userAgent:    req.get('user-agent') || null,
    });

    logger.info('File download succeeded', {
      event: 'file_download_succeeded',
      ...downloadMeta,
      downloadedBy: req.user.email.toLowerCase(),
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

// ─── Détail d'un fichier envoyé + historique de téléchargement ───────────────
/**
 * GET /api/files/:id — réservé à l'expéditeur du fichier.
 */
const getFileDetails = async (req, res) => {
  try {
    const { id } = req.params;

    const file = await File.findByPk(id, {
      attributes: { exclude: ['encryptedPath', 'downloadCodeHash', 'iv'] },
      include: [
        { model: User, as: 'sender', attributes: ['id', 'email', 'firstName', 'lastName'] },
        { model: ShareLink, as: 'shareLinks' },
        { model: DownloadLog, as: 'downloadLogs' },
      ],
      order: [[{ model: DownloadLog, as: 'downloadLogs' }, 'createdAt', 'DESC']],
    });

    if (!file) return res.status(404).json({ message: 'Fichier introuvable.' });

    if (file.senderId !== req.user.id) {
      return res.status(403).json({ message: 'Accès refusé.' });
    }

    return res.json({ file });
  } catch (err) {
    logger.error('getFileDetails error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
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

module.exports = {
  uploadFile,
  downloadFile,
  getFileDetails,
  getInbox,
  getSent,
  blockFile,
  deleteFile,
  NON_DOWNLOADABLE_STATUS,
};
