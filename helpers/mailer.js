'use strict';

const nodemailer = require('nodemailer');
const logger = require('../config/logger');
const { normalizeEmail } = require('./audit');

const APP_NAME = 'IDS Secure Transport';

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
  subject: 'Votre code de connexion IDS Secure Transport',
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
  senderName,
  senderPhone,
  senderOrganisation,
  originalName,
  size,
  isProtected,
  downloadCode,
  comment,
}) => {
  const safeName         = escapeHtml(senderName || senderEmail);
  const safePhone        = escapeHtml(senderPhone || '\u2014');
  const safeOrg          = escapeHtml(senderOrganisation || '\u2014');
  const safeFileName     = escapeHtml(originalName);
  const formattedSize    = formatFileSize(size);
  const safeDownloadCode = downloadCode ? escapeHtml(downloadCode) : null;
  const safeComment      = comment ? escapeHtml(comment) : null;

  return {
    to,
    subject: `Vous avez recu un fichier via IDS Secure Transport`,
    text: [
      'Bonjour,',
      '',
      'Vous avez recu un ou plusieurs fichiers de :',
      `<< ${senderName || senderEmail} >>`,
      `<< ${senderPhone || '\u2014'} >>`,
      `<< ${senderOrganisation || '\u2014'} >>`,
      '',
      `Nom du fichier : ${originalName} (${formattedSize})`,
      '',
      "Connectez-vous a la plateforme pour le telecharger.",
      '',
      comment ? `<< ${comment} >>` : '',
      '',
      isProtected && downloadCode ? `Code de telechargement requis : ${downloadCode}` : '',
      '',
      "Important : ce lien est susceptible d'etre valide pour une duree limitee et de requerir un mot de passe specifique.",
    ].filter((l) => l !== undefined).join('\n'),
    html: `
      <p>Bonjour,</p>
      <p>Vous avez recu un ou plusieurs fichiers de :</p>
      <p style="margin:8px 0 4px;font-weight:600">&laquo; ${safeName} &raquo;</p>
      <p style="margin:2px 0 4px;color:#555">&laquo; ${safePhone} &raquo;</p>
      <p style="margin:2px 0 12px;color:#555">&laquo; ${safeOrg} &raquo;</p>
      <p>Le fichier <strong>${safeFileName}</strong> (${escapeHtml(formattedSize)}) est disponible sur la plateforme.</p>
      <p>Connectez-vous pour le telecharger.</p>
      ${safeComment ? `<p style="margin-top:12px;font-style:italic;color:#444">&laquo; ${safeComment} &raquo;</p>` : ''}
      ${isProtected && safeDownloadCode
        ? `<p style="margin-top:12px"><strong>Code de telechargement requis :</strong></p><h2 style="letter-spacing:4px">${safeDownloadCode}</h2>`
        : ''}
      <p style="margin-top:16px;font-size:12px;color:#888">
        <strong>Important :</strong> ce lien est susceptible d&#39;etre valide pour une duree limitee et de requerir un mot de passe specifique.
      </p>
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

// ── Email avec lien de téléchargement public ─────────────────────────────────
const buildShareLinkEmail = ({
  to,
  senderEmail,
  senderName,
  senderPhone,
  senderOrganisation,
  originalName,
  size,
  isProtected,
  downloadCode,
  shareUrl,
  expiresAt,
  comment,
}) => {
  const safeName       = escapeHtml(senderName || senderEmail);
  const safePhone      = escapeHtml(senderPhone || '—');
  const safeOrg        = escapeHtml(senderOrganisation || '—');
  const safeFileName   = escapeHtml(originalName);
  const formattedSize  = formatFileSize(size);
  const safeCode       = downloadCode ? escapeHtml(downloadCode) : null;
  const safeUrl        = escapeHtml(shareUrl);
  const safeComment    = comment ? escapeHtml(comment) : null;
  const formattedDate  = new Date(expiresAt).toLocaleString('fr-FR', {
    day: '2-digit', month: 'long', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });

  return {
    to,
    subject: `Vous avez reçu un fichier via IDS Secure Transport`,
    text: [
      'Bonjour,',
      '',
      'Vous avez reçu un ou plusieurs fichiers de :',
      `« ${senderName || senderEmail} »`,
      `« ${senderPhone || '—'} »`,
      `« ${senderOrganisation || '—'} »`,
      '',
      'Le lien ci-dessous vous permet d\'accéder à un contenu en téléchargement.',
      '',
      shareUrl,
      '',
      comment ? `« ${comment} »` : '',
      '',
      isProtected && downloadCode ? `Code de téléchargement requis : ${downloadCode}` : '',
      '',
      'Important : ce lien est susceptible d\'être valide pour une durée limitée et de requérir un mot de passe spécifique.',
    ].filter((l) => l !== undefined).join('\n'),
    html: `
      <p>Bonjour,</p>
      <p>Vous avez reçu un ou plusieurs fichiers de :</p>
      <p style="margin:8px 0 4px;font-weight:600">« ${safeName} »</p>
      <p style="margin:2px 0 4px;color:#555">« ${safePhone} »</p>
      <p style="margin:2px 0 12px;color:#555">« ${safeOrg} »</p>
      <p>Le lien ci-dessous vous permet d'accéder à un contenu en téléchargement.</p>
      <p style="margin:12px 0">
        <a href="${shareUrl}" style="color:#2563eb;word-break:break-all">${safeUrl}</a>
      </p>
      ${safeComment ? `<p style="margin-top:12px;font-style:italic;color:#444">« ${safeComment} »</p>` : ''}
      ${isProtected && safeCode
        ? `<p style="margin-top:12px"><strong>Code de téléchargement requis :</strong></p><h2 style="letter-spacing:4px">${safeCode}</h2>`
        : ''}
      <p style="margin-top:16px;font-size:12px;color:#888">
        <strong>Important :</strong> ce lien est susceptible d'être valide pour une durée limitée et de requérir un mot de passe spécifique.
      </p>
    `,
  };
};

const sendShareLinkEmail = (payload) =>
  sendMail(buildShareLinkEmail(payload), {
    mailType: 'file_share_link',
    extra: {
      senderEmail: normalizeEmail(payload.senderEmail),
      fileId: payload.fileId,
      originalName: payload.originalName,
      size: payload.size,
      isProtected: Boolean(payload.isProtected),
    },
  });

// ── Email notification compte en attente (vers admins) ──────────────────────
const buildAccountPendingEmail = ({ firstName, lastName, email, organisation, country, isInternalUser }) => {
  const safeName  = escapeHtml(`${firstName} ${lastName}`);
  const safeEmail = escapeHtml(email);
  const safeOrg   = escapeHtml(organisation || '—');
  const safeCountry = escapeHtml(country || '—');
  const adminUrl  = `${process.env.FRONTEND_URL || 'http://10.112.30.143:3000'}/admin/users`;

  return {
    to: process.env.ADMIN_NOTIFICATION_EMAIL || process.env.GMAIL_USER,
    subject: `[IDS Secure Transport] Nouveau compte en attente d'approbation — ${safeEmail}`,
    text: `Un nouveau compte vient d'être créé et attend votre validation.\nNom : ${firstName} ${lastName}\nEmail : ${email}\nOrganisation : ${organisation}\nPays : ${country}\nUtilisateur interne : ${isInternalUser ? 'Oui' : 'Non'}\n\nValidez le compte ici : ${adminUrl}`,
    html: `
      <p>Un nouveau compte vient d'être créé et attend votre validation.</p>
      <table style="border-collapse:collapse;width:100%;max-width:480px">
        <tr><td style="padding:4px 8px;color:#666;font-size:13px">Nom</td><td style="padding:4px 8px;font-weight:600">${safeName}</td></tr>
        <tr><td style="padding:4px 8px;color:#666;font-size:13px">Email</td><td style="padding:4px 8px">${safeEmail}</td></tr>
        <tr><td style="padding:4px 8px;color:#666;font-size:13px">Organisation</td><td style="padding:4px 8px">${safeOrg}</td></tr>
        <tr><td style="padding:4px 8px;color:#666;font-size:13px">Pays</td><td style="padding:4px 8px">${safeCountry}</td></tr>
        <tr><td style="padding:4px 8px;color:#666;font-size:13px">Interne</td><td style="padding:4px 8px">${isInternalUser ? '✅ Oui' : '❌ Non'}</td></tr>
      </table>
      <p style="margin-top:16px">
        <a href="${adminUrl}" style="display:inline-block;padding:10px 20px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">
          Gérer les comptes en attente
        </a>
      </p>
    `,
  };
};

const buildAccountApprovedEmail = ({ firstName, email }) => ({
  to: email,
  subject: `[IDS Secure Transport] Votre compte a été approuvé`,
  text: `Bonjour ${firstName},\n\nVotre compte IDS Secure Transport a été approuvé. Vous pouvez maintenant vous connecter.\n${process.env.FRONTEND_URL || 'http://10.112.30.143:3000'}/login`,
  html: `
    <p>Bonjour <strong>${escapeHtml(firstName)}</strong>,</p>
    <p>Votre compte <strong>IDS Secure Transport</strong> a été approuvé par un administrateur. Vous pouvez maintenant accéder à la plateforme.</p>
    <p style="margin-top:16px">
      <a href="${process.env.FRONTEND_URL || 'http://10.112.30.143:3000'}/login" style="display:inline-block;padding:10px 20px;background:#16a34a;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">
        ✅ Accéder à la plateforme
      </a>
    </p>
  `,
});

const buildAccountRejectedEmail = ({ firstName, email }) => ({
  to: email,
  subject: `[IDS Secure Transport] Votre demande de compte`,
  text: `Bonjour ${firstName},\n\nNous avons examiné votre demande de compte IDS Secure Transport. Malheureusement, nous ne sommes pas en mesure de l'approuver pour le moment. Contactez l'équipe pour plus d'informations.`,
  html: `
    <p>Bonjour <strong>${escapeHtml(firstName)}</strong>,</p>
    <p>Nous avons examiné votre demande d'accès à la plateforme <strong>IDS Secure Transport</strong>. Malheureusement, nous ne sommes pas en mesure de l'approuver pour le moment.</p>
    <p style="font-size:13px;color:#666">Si vous pensez qu'il s'agit d'une erreur, veuillez contacter l'équipe d'administration.</p>
  `,
});

const sendAccountPendingEmail = (payload) =>
  sendMail(buildAccountPendingEmail(payload), { mailType: 'account_pending' });

const sendAccountApprovedEmail = (payload) =>
  sendMail(buildAccountApprovedEmail(payload), { mailType: 'account_approved' });

const sendAccountRejectedEmail = (payload) =>
  sendMail(buildAccountRejectedEmail(payload), { mailType: 'account_rejected' });

// ── Email de réinitialisation de mot de passe ────────────────────────────────
const buildPasswordResetEmail = ({ to, firstName, resetUrl, expiryMinutes }) => {
  const safeName    = escapeHtml(firstName || 'utilisateur');
  const safeUrl     = escapeHtml(resetUrl);
  const safeExpiry  = escapeHtml(String(expiryMinutes || 30));

  return {
    to,
    subject: `${APP_NAME} — Réinitialisation de votre mot de passe`,
    text: [
      `Bonjour ${firstName || ''},`,
      '',
      'Vous avez demandé la réinitialisation de votre mot de passe IDS Secure Transport.',
      `Cliquez sur le lien suivant pour en définir un nouveau (valable ${expiryMinutes} minutes) :`,
      resetUrl,
      '',
      'Si vous n\'avez pas effectué cette demande, ignorez cet email.',
    ].join('\n'),
    html: `
      <p>Bonjour <strong>${safeName}</strong>,</p>
      <p>Vous avez demandé la réinitialisation de votre mot de passe <strong>${APP_NAME}</strong>.</p>
      <p style="margin-top:16px">
        <a href="${safeUrl}" style="display:inline-block;padding:10px 20px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">
          🔑 Réinitialiser mon mot de passe
        </a>
      </p>
      <p style="font-size:12px;color:#888">
        Ce lien expire dans <strong>${safeExpiry} minutes</strong>. Si vous n'avez pas effectué cette demande, ignorez cet email.
      </p>
    `,
  };
};

const sendPasswordResetEmail = (payload) =>
  sendMail(buildPasswordResetEmail(payload), {
    mailType: 'password_reset',
    extra: { recipientEmail: normalizeEmail(payload.to) },
  });

module.exports = {
  buildMailLogMeta,
  buildFileReceivedEmail,
  buildShareLinkEmail,
  buildOTPEmail,
  buildPasswordResetEmail,
  buildAccountPendingEmail,
  buildAccountApprovedEmail,
  buildAccountRejectedEmail,
  formatFileSize,
  sendFileReceivedEmail,
  sendShareLinkEmail,
  sendOTPEmail,
  sendPasswordResetEmail,
  sendAccountPendingEmail,
  sendAccountApprovedEmail,
  sendAccountRejectedEmail,
};