'use strict';

const nodemailer = require('nodemailer');
const logger = require('../config/logger');
const { normalizeEmail } = require('./audit');

const APP_NAME = 'NFS';

const escapeHtml = (value) => String(value)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const formatFileSize = (size) => {
  if (!Number.isFinite(size) || size < 1024) return `${size || 0} octets`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(2)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const ensureMailConfig = () => {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    throw new Error('Configuration email manquante : GMAIL_USER/GMAIL_PASS requis.');
  }
};

const createTransporter = () => nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

const buildMailLogMeta = ({ mailType, to, subject, extra = {} }) => ({
  mailType,
  recipientEmail: normalizeEmail(to),
  subject,
  ...extra,
});

const sendMail = async (message, logContext = {}) => {
  ensureMailConfig();

  const logMeta = buildMailLogMeta({
    mailType: logContext.mailType || 'generic',
    to: message.to,
    subject: message.subject,
    extra: logContext.extra,
  });

  logger.info('Email send started', {
    event: 'email_send_started',
    ...logMeta,
  });

  try {
    const info = await createTransporter().sendMail({
      from: `"${APP_NAME}" <${process.env.GMAIL_USER}>`,
      ...message,
    });

    logger.info('Email sent', {
      event: 'email_send_succeeded',
      ...logMeta,
      messageId: info.messageId,
      acceptedCount: info.accepted?.length || 0,
      rejectedCount: info.rejected?.length || 0,
    });

    return info;
  } catch (error) {
    logger.error('Email send failed', {
      event: 'email_send_failed',
      ...logMeta,
      error: error.message,
    });

    throw error;
  }
};

const buildOTPEmail = ({ email, otp, expiryMinutes }) => ({
  to: email,
  subject: 'Votre code de connexion NFS',
  text: `Votre code OTP : ${otp}. Valide ${expiryMinutes} minutes.`,
  html: `
    <p>Votre code de connexion :</p>
    <h2 style="letter-spacing:8px">${escapeHtml(otp)}</h2>
    <p>Ce code expire dans <strong>${escapeHtml(expiryMinutes)}</strong> minutes.</p>
    <p>Si vous n'avez pas demandé ce code, ignorez cet email.</p>
  `,
});

const buildFileReceivedEmail = ({
  to,
  senderEmail,
  originalName,
  size,
  isProtected,
  downloadCode,
}) => {
  const safeFileName = escapeHtml(originalName);
  const safeSenderEmail = escapeHtml(senderEmail);
  const formattedSize = formatFileSize(size);
  const safeDownloadCode = downloadCode ? escapeHtml(downloadCode) : null;

  return {
    to,
    subject: `Nouveau fichier reçu : ${originalName}`,
    text: [
      `Vous avez reçu un fichier via ${APP_NAME}.`,
      `Expéditeur : ${senderEmail}`,
      `Nom du fichier : ${originalName}`,
      `Taille : ${formattedSize}`,
      isProtected && downloadCode
        ? `Code de téléchargement : ${downloadCode}`
        : 'Aucun code de téléchargement n’est requis pour ce fichier.',
      'Connectez-vous à la plateforme pour le télécharger.',
    ].join('\n'),
    html: `
      <p>Vous avez reçu un fichier via <strong>${APP_NAME}</strong>.</p>
      <p><strong>Expéditeur :</strong> ${safeSenderEmail}</p>
      <p><strong>Nom du fichier :</strong> ${safeFileName}</p>
      <p><strong>Taille :</strong> ${escapeHtml(formattedSize)}</p>
      ${isProtected && safeDownloadCode
        ? `<p><strong>Code de téléchargement :</strong></p><h2 style="letter-spacing:4px">${safeDownloadCode}</h2>`
        : '<p>Aucun code de téléchargement n’est requis pour ce fichier.</p>'}
      <p>Connectez-vous à la plateforme pour le télécharger.</p>
    `,
  };
};

const sendOTPEmail = ({ email, otp, expiryMinutes }) =>
  sendMail(buildOTPEmail({ email, otp, expiryMinutes }), {
    mailType: 'otp_login',
    extra: {
      expiryMinutes,
    },
  });

const sendFileReceivedEmail = (payload) =>
  sendMail(buildFileReceivedEmail(payload), {
    mailType: 'file_received_notification',
    extra: {
      senderEmail: normalizeEmail(payload.senderEmail),
      fileId: payload.fileId,
      originalName: payload.originalName,
      size: payload.size,
      isProtected: Boolean(payload.isProtected),
    },
  });

module.exports = {
  buildMailLogMeta,
  buildFileReceivedEmail,
  buildOTPEmail,
  formatFileSize,
  sendFileReceivedEmail,
  sendOTPEmail,
};