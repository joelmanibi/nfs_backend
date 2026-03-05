'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────
const ALGORITHM      = 'aes-256-cbc';
const IV_LENGTH      = 16; // 128 bits
const KEY_HEX_LENGTH = 64; // 32 bytes = 64 hex chars

/**
 * Récupère et valide la clé de chiffrement depuis l'environnement.
 * @returns {Buffer} 32-byte key
 */
const getKey = () => {
  const keyHex = process.env.FILE_ENCRYPTION_KEY;

  if (!keyHex || keyHex.length !== KEY_HEX_LENGTH) {
    throw new Error(
      `FILE_ENCRYPTION_KEY doit être une chaîne hex de ${KEY_HEX_LENGTH} caractères (32 octets). ` +
      `Générez-en une avec : node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`,
    );
  }

  return Buffer.from(keyHex, 'hex');
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Chiffre un Buffer (AES-256-CBC) et l'écrit dans destPath.
 * Le fichier source en clair n'est JAMAIS écrit sur disque.
 *
 * @param {Buffer} buffer       Contenu du fichier en clair (depuis mémoire)
 * @param {string} destPath     Chemin de destination du fichier chiffré
 * @returns {string}            IV en hexadécimal (à stocker en DB)
 */
const encryptToFile = (buffer, destPath) => {
  const key = getKey();
  const iv  = crypto.randomBytes(IV_LENGTH);

  const cipher    = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);

  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  fs.writeFileSync(destPath, encrypted);

  return iv.toString('hex');
};

/**
 * Crée un stream de déchiffrement AES-256-CBC.
 * S'utilise en pipeline : readStream → decipherStream → res
 * La version déchiffrée n'est jamais persistée sur disque.
 *
 * @param {string} ivHex  IV en hexadécimal (stocké en DB)
 * @returns {crypto.Decipher}
 */
const createDecipherStream = (ivHex) => {
  const key = getKey();
  const iv  = Buffer.from(ivHex, 'hex');

  return crypto.createDecipheriv(ALGORITHM, key, iv);
};

module.exports = { encryptToFile, createDecipherStream };

