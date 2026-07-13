'use strict';

const crypto = require('crypto');

// Jeux de caractères sans caractères ambigus (I/O/0/1 etc.)
const UPPER   = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER   = 'abcdefghijkmnpqrstuvwxyz';
const DIGITS  = '23456789';
const SPECIAL = '!@#$%?*-_';
const ALL     = UPPER + LOWER + DIGITS + SPECIAL;
const PASSWORD_LENGTH = 12;

const randomChar = (charset) => charset[crypto.randomInt(charset.length)];

/**
 * Génère un mot de passe temporaire fort (12 caractères, les 4 classes
 * garanties : majuscule/minuscule/chiffre/spécial) via un générateur
 * cryptographiquement sûr (jamais Math.random). Conforme à la politique
 * de mot de passe de l'application (evaluatePassword, authController.js).
 */
const generateTempPassword = () => {
  const required = [randomChar(UPPER), randomChar(LOWER), randomChar(DIGITS), randomChar(SPECIAL)];
  const rest = Array.from({ length: PASSWORD_LENGTH - required.length }, () => randomChar(ALL));

  const chars = [...required, ...rest];

  // Mélange Fisher-Yates avec crypto.randomInt
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
};

module.exports = { generateTempPassword };
