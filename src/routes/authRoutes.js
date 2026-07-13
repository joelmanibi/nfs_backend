'use strict';

const { Router }   = require('express');
const rateLimit    = require('express-rate-limit');
const { verifyToken } = require('../middleware/authMiddleware');
const {
  register, requestOTP, verifyOTP,
  loginWithPassword, forgotPassword, resetPassword, changePassword, getMe, logout,
} = require('../controllers/authController');
const { loginWithLDAP } = require('../controllers/ldapController');

const router = Router();

// ─── Rate Limiters ────────────────────────────────────────────────────────────

/** Retourne les secondes restantes avant la fin du blocage */
const retryAfterSeconds = (req) => {
  const reset = req.rateLimit?.resetTime;
  if (reset instanceof Date) return Math.max(0, Math.ceil((reset.getTime() - Date.now()) / 1000));
  return 5 * 60; // fallback : 5 minutes
};

/** 5 demandes d'OTP max par IP sur 5 minutes */
const loginLimiter = rateLimit({
  windowMs:        5 * 60 * 1000,
  max:             5,
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    res.status(429).json({
      message:    'Trop de demandes OTP. Veuillez patienter avant de réessayer.',
      retryAfter: retryAfterSeconds(req),
    });
  },
});

/** 10 tentatives de vérification max par IP sur 5 minutes */
const verifyLimiter = rateLimit({
  windowMs:        5 * 60 * 1000,
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    res.status(429).json({
      message:    'Trop de tentatives de vérification. Veuillez patienter avant de réessayer.',
      retryAfter: retryAfterSeconds(req),
    });
  },
});

/** 10 tentatives max par IP sur 5 min pour login/forgot */
const passwordLimiter = rateLimit({
  windowMs:        5 * 60 * 1000,
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    res.status(429).json({
      message:    'Trop de tentatives. Veuillez patienter avant de réessayer.',
      retryAfter: retryAfterSeconds(req),
    });
  },
});

// ─── Routes ───────────────────────────────────────────────────────────────────

router.post('/register',         register);
router.post('/login',            loginLimiter,    requestOTP);
router.post('/verify-otp',       verifyLimiter,   verifyOTP);
router.post('/login-password',   passwordLimiter, loginWithPassword);
router.post('/login-ldap',       passwordLimiter, loginWithLDAP);
router.post('/forgot-password',  passwordLimiter, forgotPassword);
router.post('/reset-password',   passwordLimiter, resetPassword);
router.post('/change-password',  verifyToken,     changePassword);
router.get('/me',                verifyToken,     getMe);
router.post('/logout',           logout);

module.exports = router;

