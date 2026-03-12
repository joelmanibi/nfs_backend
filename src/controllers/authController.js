'use strict';

const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { Op }    = require('sequelize');

const { User, OTP } = require('../models');
const config        = require('../../config');
const logger        = require('../../config/logger');
const { buildRequestAuditMeta, normalizeEmail } = require('../../helpers/audit');
const { sendOTPEmail, sendPasswordResetEmail } = require('../../helpers/mailer');

// ─── Constants ───────────────────────────────────────────────────────────────
const OTP_EXPIRY_MS        = 10 * 60 * 1000;  // 10 min
const RESET_TOKEN_EXPIRY_MS = 30 * 60 * 1000; // 30 min
const OTP_MAX_ATTEMPTS     = 5;
const BCRYPT_ROUNDS        = 12;
const FRONTEND_URL         = process.env.FRONTEND_URL || 'http://localhost:3000';

// ─── Password strength (server-side mirror of frontend rules) ─────────────────
// Minimum acceptable: 8+ chars, at least 2 of {upper, lower, digit, special}
const PASSWORD_MIN_SCORE = 2;
const evaluatePassword = (pwd) => {
  if (!pwd || pwd.length < 8) return 0;
  let score = 0;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[a-z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)  ) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;
  return score;
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const buildAuthMeta = (req, extra = {}) => buildRequestAuditMeta(req, {
  targetEmail: normalizeEmail(req.body?.email),
  ...extra,
});

// ─── Controllers ─────────────────────────────────────────────────────────────

/**
 * POST /api/auth/register
 */
const register = async (req, res) => {
  const { firstName, lastName, email, phone, city, password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    if (!firstName?.trim() || !lastName?.trim() || !normalizedEmail) {
      logger.warn('Registration validation failed', {
        event: 'auth_register_validation_failed',
        ...buildAuthMeta(req),
      });

      return res.status(400).json({ message: 'firstName, lastName et email sont requis.' });
    }

    // Validate password if provided
    let passwordHash = null;
    if (password) {
      const score = evaluatePassword(password);
      if (score < PASSWORD_MIN_SCORE) {
        return res.status(400).json({
          message: 'Mot de passe trop faible. Utilisez au moins 8 caractères avec majuscules, minuscules, chiffres ou caractères spéciaux.',
        });
      }
      passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    }

    const exists = await User.findOne({ where: { email: normalizedEmail } });
    if (exists) {
      logger.warn('Registration rejected for duplicate email', {
        event: 'auth_register_duplicate_email',
        ...buildAuthMeta(req),
      });

      return res.status(409).json({ message: 'Cet email est déjà enregistré.' });
    }

    const user = await User.create({
      firstName: firstName.trim(),
      lastName:  lastName.trim(),
      email:     normalizedEmail,
      phone:     phone?.trim() || null,
      city:      city?.trim()  || null,
      passwordHash,
    });

    logger.info('Account created', {
      event: 'auth_register_succeeded',
      ...buildAuthMeta(req, {
        createdUserId: user.id,
        role: user.role,
      }),
    });

    return res.status(201).json({
      message: 'Compte créé avec succès.',
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    logger.error('Registration failed', {
      event: 'auth_register_failed',
      error: err.message,
      ...buildAuthMeta(req, {
        firstName: firstName?.trim(),
        lastName: lastName?.trim(),
      }),
    });

    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/login
 * Génère et envoie un OTP par email.
 */
const requestOTP = async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    if (!normalizedEmail) {
      logger.warn('OTP request validation failed', {
        event: 'auth_otp_request_validation_failed',
        ...buildAuthMeta(req),
      });

      return res.status(400).json({ message: 'Email requis.' });
    }

    logger.info('OTP request started', {
      event: 'auth_otp_request_started',
      ...buildAuthMeta(req),
    });

    const user = await User.findOne({ where: { email: normalizedEmail } });

    // Email inconnu → signaler explicitement sans exposer de détails sensibles
    if (!user) {
      logger.warn('OTP request for unknown email', {
        event: 'auth_otp_request_unknown_email',
        ...buildAuthMeta(req),
      });

      return res.status(200).json({ registered: false, message: "Aucun compte associé à cet email." });
    }

    // Supprimer tout OTP précédent pour cet email
    await OTP.destroy({ where: { email: normalizedEmail } });

    const otp     = generateOTP();
    const otpHash = await bcrypt.hash(otp, BCRYPT_ROUNDS);
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

    await OTP.create({ email: normalizedEmail, otpHash, expiresAt });
    await sendOTPEmail({
      email: normalizedEmail,
      otp,
      expiryMinutes: OTP_EXPIRY_MS / 60000,
    });

    logger.info('OTP request succeeded', {
      event: 'auth_otp_request_succeeded',
      ...buildAuthMeta(req, {
        otpUserId: user.id,
        expiryMinutes: OTP_EXPIRY_MS / 60000,
      }),
    });

    return res.status(200).json({ registered: true, message: "OTP envoyé avec succès." });
  } catch (err) {
    logger.error('OTP request failed', {
      event: 'auth_otp_request_failed',
      error: err.message,
      ...buildAuthMeta(req),
    });

    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/verify-otp
 * Valide l'OTP et retourne un JWT (2h).
 */
const verifyOTP = async (req, res) => {
  const { email, otp } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    if (!normalizedEmail || !otp?.trim()) {
      logger.warn('OTP verification validation failed', {
        event: 'auth_verify_validation_failed',
        ...buildAuthMeta(req),
      });

      return res.status(400).json({ message: 'Email et OTP requis.' });
    }

    logger.info('OTP verification started', {
      event: 'auth_verify_started',
      ...buildAuthMeta(req),
    });

    const record = await OTP.findOne({
      where: {
        email:     normalizedEmail,
        expiresAt: { [Op.gt]: new Date() },
      },
    });

    if (!record) {
      logger.warn('OTP verification failed because record is missing or expired', {
        event: 'auth_verify_record_missing',
        ...buildAuthMeta(req),
      });

      return res.status(401).json({ message: 'OTP expiré ou introuvable. Veuillez en demander un nouveau.' });
    }

    // Bloquer si le seuil de tentatives est déjà atteint
    if (record.attempts >= OTP_MAX_ATTEMPTS) {
      await record.destroy();

      logger.warn('OTP verification blocked due to too many attempts', {
        event: 'auth_verify_attempt_limit_reached',
        ...buildAuthMeta(req, {
          attempts: record.attempts,
        }),
      });

      return res.status(429).json({ message: 'Trop de tentatives. Veuillez demander un nouvel OTP.' });
    }

    // Incrémenter les tentatives AVANT la vérification
    const updated = await record.increment('attempts');
    const isValid = await bcrypt.compare(otp.trim(), record.otpHash);

    if (!isValid) {
      const attemptsLeft = Math.max(0, OTP_MAX_ATTEMPTS - updated.attempts);

      logger.warn('OTP verification failed because code is invalid', {
        event: 'auth_verify_invalid_otp',
        ...buildAuthMeta(req, {
          attempts: updated.attempts,
          attemptsLeft,
        }),
      });

      return res.status(401).json({ message: 'OTP invalide.', attemptsLeft });
    }

    // OTP valide → nettoyage immédiat
    await record.destroy();

    const user = await User.findOne({ where: { email: normalizedEmail } });
    if (!user) {
      logger.error('OTP verification succeeded but user was not found', {
        event: 'auth_verify_user_missing',
        ...buildAuthMeta(req),
      });

      return res.status(404).json({ message: 'Utilisateur introuvable.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: '2h' },
    );

    logger.info('Authentication succeeded', {
      event: 'auth_authentication_succeeded',
      ...buildAuthMeta(req, {
        authenticatedUserId: user.id,
        role: user.role,
      }),
    });

    return res.status(200).json({
      message: 'Authentification réussie.',
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    logger.error('Authentication flow failed', {
      event: 'auth_authentication_failed',
      error: err.message,
      ...buildAuthMeta(req),
    });

    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/login-password
 * Connexion par email + mot de passe → retourne un JWT.
 */
const loginWithPassword = async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    if (!normalizedEmail || !password?.trim()) {
      return res.status(400).json({ message: 'Email et mot de passe requis.' });
    }

    const user = await User.findOne({ where: { email: normalizedEmail } });

    if (!user) {
      return res.status(200).json({ registered: false, message: 'Aucun compte associé à cet email.' });
    }

    if (!user.passwordHash) {
      return res.status(400).json({
        message: 'Ce compte utilise uniquement la connexion par OTP. Veuillez utiliser cette méthode.',
        otpOnly: true,
      });
    }

    const valid = await bcrypt.compare(password.trim(), user.passwordHash);
    if (!valid) {
      logger.warn('Password login failed — invalid password', {
        event: 'auth_password_login_invalid',
        ...buildAuthMeta(req),
      });
      return res.status(401).json({ message: 'Email ou mot de passe incorrect.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: '2h' },
    );

    logger.info('Password login succeeded', {
      event: 'auth_password_login_succeeded',
      ...buildAuthMeta(req, { authenticatedUserId: user.id }),
    });

    return res.status(200).json({
      message: 'Authentification réussie.',
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    logger.error('Password login error', { event: 'auth_password_login_failed', error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/forgot-password
 * Génère un token de réinitialisation et envoie un email.
 */
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    if (!normalizedEmail) {
      return res.status(400).json({ message: 'Email requis.' });
    }

    // Toujours répondre 200 pour ne pas exposer les emails enregistrés
    const user = await User.findOne({ where: { email: normalizedEmail } });
    if (!user) {
      return res.status(200).json({ message: 'Si cet email existe, un lien de réinitialisation vous a été envoyé.' });
    }

    const { randomBytes } = require('crypto');
    const rawToken   = randomBytes(32).toString('hex');
    const tokenHash  = await bcrypt.hash(rawToken, BCRYPT_ROUNDS);
    const expiresAt  = new Date(Date.now() + RESET_TOKEN_EXPIRY_MS);

    await user.update({ resetTokenHash: tokenHash, resetTokenExpiresAt: expiresAt });

    const resetUrl = `${FRONTEND_URL}/reset-password?token=${rawToken}&email=${encodeURIComponent(normalizedEmail)}`;

    try {
      await sendPasswordResetEmail({ to: normalizedEmail, firstName: user.firstName, resetUrl, expiryMinutes: 30 });
    } catch (mailErr) {
      logger.error('Password reset email failed', { event: 'auth_reset_email_failed', error: mailErr.message });
    }

    logger.info('Password reset requested', { event: 'auth_reset_requested', ...buildAuthMeta(req) });

    return res.status(200).json({ message: 'Si cet email existe, un lien de réinitialisation vous a été envoyé.' });
  } catch (err) {
    logger.error('Forgot password error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/reset-password
 * Valide le token et met à jour le mot de passe.
 */
const resetPassword = async (req, res) => {
  const { email, token, password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    if (!normalizedEmail || !token?.trim() || !password?.trim()) {
      return res.status(400).json({ message: 'Email, token et nouveau mot de passe requis.' });
    }

    const score = evaluatePassword(password);
    if (score < PASSWORD_MIN_SCORE) {
      return res.status(400).json({
        message: 'Mot de passe trop faible. Utilisez au moins 8 caractères avec majuscules, minuscules, chiffres ou caractères spéciaux.',
      });
    }

    const user = await User.findOne({ where: { email: normalizedEmail } });
    if (!user || !user.resetTokenHash || !user.resetTokenExpiresAt) {
      return res.status(400).json({ message: 'Lien de réinitialisation invalide ou expiré.' });
    }

    if (new Date() > user.resetTokenExpiresAt) {
      await user.update({ resetTokenHash: null, resetTokenExpiresAt: null });
      return res.status(400).json({ message: 'Lien expiré. Veuillez en demander un nouveau.' });
    }

    const valid = await bcrypt.compare(token.trim(), user.resetTokenHash);
    if (!valid) {
      return res.status(400).json({ message: 'Lien de réinitialisation invalide.' });
    }

    const newHash = await bcrypt.hash(password.trim(), BCRYPT_ROUNDS);
    await user.update({ passwordHash: newHash, resetTokenHash: null, resetTokenExpiresAt: null });

    logger.info('Password reset succeeded', { event: 'auth_reset_succeeded', ...buildAuthMeta(req) });
    return res.status(200).json({ message: 'Mot de passe réinitialisé avec succès.' });
  } catch (err) {
    logger.error('Reset password error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/change-password   (authentifié)
 * Permet à l'utilisateur connecté de changer son mot de passe.
 */
const changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    if (!newPassword?.trim()) {
      return res.status(400).json({ message: 'Le nouveau mot de passe est requis.' });
    }

    const score = evaluatePassword(newPassword);
    if (score < PASSWORD_MIN_SCORE) {
      return res.status(400).json({
        message: 'Mot de passe trop faible. Utilisez au moins 8 caractères avec majuscules, minuscules, chiffres ou caractères spéciaux.',
      });
    }

    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    // Si le compte avait déjà un mot de passe, vérifier l'ancien
    if (user.passwordHash) {
      if (!currentPassword?.trim()) {
        return res.status(400).json({ message: 'Le mot de passe actuel est requis.' });
      }
      const valid = await bcrypt.compare(currentPassword.trim(), user.passwordHash);
      if (!valid) {
        return res.status(401).json({ message: 'Mot de passe actuel incorrect.' });
      }
    }

    const newHash = await bcrypt.hash(newPassword.trim(), BCRYPT_ROUNDS);
    await user.update({ passwordHash: newHash });

    logger.info('Password changed', { event: 'auth_password_changed', userId: user.id });
    return res.status(200).json({ message: 'Mot de passe mis à jour avec succès.' });
  } catch (err) {
    logger.error('Change password error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

module.exports = { register, requestOTP, verifyOTP, loginWithPassword, forgotPassword, resetPassword, changePassword };

