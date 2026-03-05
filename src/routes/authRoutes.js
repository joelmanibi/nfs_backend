'use strict';

const { Router }   = require('express');
const rateLimit    = require('express-rate-limit');
const { register, requestOTP, verifyOTP } = require('../controllers/authController');

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

// ─── Routes ───────────────────────────────────────────────────────────────────

router.post('/register',    register);
router.post('/login',       loginLimiter,  requestOTP);
router.post('/verify-otp',  verifyLimiter, verifyOTP);

module.exports = router;

