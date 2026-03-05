'use strict';

const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Op }    = require('sequelize');

const { User, OTP } = require('../models');
const config        = require('../../config');

// ─── Constants ───────────────────────────────────────────────────────────────
const OTP_EXPIRY_MS   = 10 * 60 * 1000; // 10 min
const OTP_MAX_ATTEMPTS = 5;
const BCRYPT_ROUNDS    = 12;

// ─── Mailer Gmail ─────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// ─── Helpers ─────────────────────────────────────────────────────────────────
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const sendOTPEmail = (email, otp) =>
  transporter.sendMail({
    from:    `"NFS" <${process.env.GMAIL_USER}>`,
    to:      email,
    subject: 'Votre code de connexion NFS',
    text:    `Votre code OTP : ${otp}. Valide ${OTP_EXPIRY_MS / 60000} minutes.`,
    html: `
      <p>Votre code de connexion :</p>
      <h2 style="letter-spacing:8px">${otp}</h2>
      <p>Ce code expire dans <strong>${OTP_EXPIRY_MS / 60000} minutes</strong>.</p>
      <p>Si vous n'avez pas demandé ce code, ignorez cet email.</p>
    `,
  });

// ─── Controllers ─────────────────────────────────────────────────────────────

/**
 * POST /api/auth/register
 */
const register = async (req, res) => {
  try {
    const { firstName, lastName, email, phone, city } = req.body;

    if (!firstName?.trim() || !lastName?.trim() || !email?.trim()) {
      return res.status(400).json({ message: 'firstName, lastName et email sont requis.' });
    }

    const exists = await User.findOne({ where: { email: email.toLowerCase() } });
    if (exists) {
      return res.status(409).json({ message: 'Cet email est déjà enregistré.' });
    }

    const user = await User.create({
      firstName: firstName.trim(),
      lastName:  lastName.trim(),
      email:     email.toLowerCase().trim(),
      phone:     phone?.trim() || null,
      city:      city?.trim()  || null,
    });

    return res.status(201).json({
      message: 'Compte créé avec succès.',
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/login
 * Génère et envoie un OTP par email.
 */
const requestOTP = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email?.trim()) {
      return res.status(400).json({ message: 'Email requis.' });
    }

    const user = await User.findOne({ where: { email: email.toLowerCase() } });

    // Email inconnu → signaler explicitement sans exposer de détails sensibles
    if (!user) {
      return res.status(200).json({ registered: false, message: "Aucun compte associé à cet email." });
    }

    // Supprimer tout OTP précédent pour cet email
    await OTP.destroy({ where: { email: email.toLowerCase() } });

    const otp     = generateOTP();
    const otpHash = await bcrypt.hash(otp, BCRYPT_ROUNDS);
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

    await OTP.create({ email: email.toLowerCase(), otpHash, expiresAt });
    await sendOTPEmail(email.toLowerCase(), otp);

    return res.status(200).json({ registered: true, message: "OTP envoyé avec succès." });
  } catch (err) {
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

/**
 * POST /api/auth/verify-otp
 * Valide l'OTP et retourne un JWT (2h).
 */
const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email?.trim() || !otp?.trim()) {
      return res.status(400).json({ message: 'Email et OTP requis.' });
    }

    const record = await OTP.findOne({
      where: {
        email:     email.toLowerCase(),
        expiresAt: { [Op.gt]: new Date() },
      },
    });

    if (!record) {
      return res.status(401).json({ message: 'OTP expiré ou introuvable. Veuillez en demander un nouveau.' });
    }

    // Bloquer si le seuil de tentatives est déjà atteint
    if (record.attempts >= OTP_MAX_ATTEMPTS) {
      await record.destroy();
      return res.status(429).json({ message: 'Trop de tentatives. Veuillez demander un nouvel OTP.' });
    }

    // Incrémenter les tentatives AVANT la vérification
    const updated = await record.increment('attempts');
    const isValid = await bcrypt.compare(otp.trim(), record.otpHash);

    if (!isValid) {
      const attemptsLeft = Math.max(0, OTP_MAX_ATTEMPTS - updated.attempts);
      return res.status(401).json({ message: 'OTP invalide.', attemptsLeft });
    }

    // OTP valide → nettoyage immédiat
    await record.destroy();

    const user = await User.findOne({ where: { email: email.toLowerCase() } });
    if (!user) {
      return res.status(404).json({ message: 'Utilisateur introuvable.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: '2h' },
    );

    return res.status(200).json({
      message: 'Authentification réussie.',
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

module.exports = { register, requestOTP, verifyOTP };

