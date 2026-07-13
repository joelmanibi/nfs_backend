'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;
const KEY_HEX_LENGTH = 64;

const getKey = () => {
  const keyHex = process.env.FILE_ENCRYPTION_KEY;

  if (!keyHex || keyHex.length !== KEY_HEX_LENGTH) {
    throw new Error(
      `FILE_ENCRYPTION_KEY doit être une chaîne hex de ${KEY_HEX_LENGTH} caractères (32 octets).`,
    );
  }

  return Buffer.from(keyHex, 'hex');
};

const encryptSecret = (plainText) => {
  if (!plainText) return null;

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const encrypted = Buffer.concat([
    cipher.update(String(plainText), 'utf8'),
    cipher.final(),
  ]);

  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
};

const decryptSecret = (payload) => {
  if (!payload) return null;

  const [ivHex, encryptedHex] = String(payload).split(':');
  if (!ivHex || !encryptedHex) {
    throw new Error('Secret chiffré invalide.');
  }

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    getKey(),
    Buffer.from(ivHex, 'hex'),
  );

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, 'hex')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
};

module.exports = { encryptSecret, decryptSecret };