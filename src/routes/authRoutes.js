'use strict';

const { Router }   = require('express');
const rateLimit    = require('express-rate-limit');
const { verifyToken } = require('../middleware/authMiddleware');
const {
  register, requestOTP, verifyOTP,
  loginWithPassword, forgotPassword, resetPassword, changePassword,
} = require('../controllers/authController');

const router = Router();

// ─── Rate Limiters ────────────────────────────────────────────────────────────

/** 5 demandes d'OTP max par IP sur 15 minutes */
const loginLimiter = rateLimit({
  windowMs:       15 * 60 * 1000,
  max:            5,
  standardHeaders: true,
  legacyHeaders:  false,
  message: { message: 'Trop de demandes OTP. Réessayez dans 15 minutes.' },
});

/** 10 tentatives de vérification max par IP sur 15 minutes */
const verifyLimiter = rateLimit({
  windowMs:       15 * 60 * 1000,
  max:            10,
  standardHeaders: true,
  legacyHeaders:  false,
  message: { message: 'Trop de tentatives de vérification. Réessayez dans 15 minutes.' },
});

/** 10 tentatives max par IP sur 15 min pour login/forgot */
const passwordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Trop de tentatives. Réessayez dans 15 minutes.' },
});

// ─── Routes ───────────────────────────────────────────────────────────────────

router.post('/register',         register);
router.post('/login',            loginLimiter,    requestOTP);
router.post('/verify-otp',       verifyLimiter,   verifyOTP);
router.post('/login-password',   passwordLimiter, loginWithPassword);
router.post('/forgot-password',  passwordLimiter, forgotPassword);
router.post('/reset-password',   passwordLimiter, resetPassword);
router.post('/change-password',  verifyToken,     changePassword);

module.exports = router;

