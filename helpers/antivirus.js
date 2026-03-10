'use strict';

const net = require('net');

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const CHUNK_SIZE = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_MAX_STREAM_BYTES = 25 * 1024 * 1024;

const asBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null || value === '') return defaultValue;
  return TRUE_VALUES.has(String(value).toLowerCase());
};

const asPositiveInteger = (value, defaultValue) => {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultValue;
};

const getAntivirusConfig = () => ({
  enabled: asBoolean(process.env.ANTIVIRUS_ENABLED, false),
  host: process.env.ANTIVIRUS_HOST || '127.0.0.1',
  port: asPositiveInteger(process.env.ANTIVIRUS_PORT, 3310),
  timeoutMs: asPositiveInteger(process.env.ANTIVIRUS_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
  maxStreamBytes: asPositiveInteger(process.env.ANTIVIRUS_MAX_STREAM_BYTES, DEFAULT_MAX_STREAM_BYTES),
  failOnError: asBoolean(process.env.ANTIVIRUS_FAIL_ON_ERROR, process.env.NODE_ENV === 'production'),
});

const parseScanResponse = (responseText) => {
  const message = String(responseText || '').replace(/\0/g, '').trim();

  if (!message) {
    throw new Error('Réponse antivirus vide.');
  }

  if (/FOUND$/i.test(message)) {
    const threat = message.replace(/^.*?:\s*/, '').replace(/\s+FOUND$/i, '').trim() || 'unknown';
    return { status: 'infected', threat, rawResponse: message };
  }

  if (/OK$/i.test(message)) {
    return { status: 'clean', rawResponse: message };
  }

  if (/ERROR/i.test(message)) {
    throw new Error(message);
  }

  throw new Error(`Réponse antivirus inattendue : ${message}`);
};

const sendBufferToClamd = (buffer, config) => new Promise((resolve, reject) => {
  if (!Buffer.isBuffer(buffer)) {
    reject(new Error('Le scan antivirus attend un Buffer.'));
    return;
  }

  if (buffer.length > config.maxStreamBytes) {
    reject(new Error(`Fichier trop volumineux pour le scan antivirus (${buffer.length} octets).`));
    return;
  }

  const socket = net.createConnection({ host: config.host, port: config.port });
  const responseChunks = [];
  let settled = false;
  let timeout = null;

  const cleanup = () => {
    if (timeout) clearTimeout(timeout);
    socket.removeAllListeners();
    socket.destroy();
  };

  const finish = (handler, value) => {
    if (settled) return;
    settled = true;
    cleanup();
    handler(value);
  };

  timeout = setTimeout(() => {
    finish(reject, new Error(`Timeout antivirus après ${config.timeoutMs}ms.`));
  }, config.timeoutMs);

  socket.on('connect', () => {
    socket.write('zINSTREAM\0');

    for (let offset = 0; offset < buffer.length; offset += CHUNK_SIZE) {
      const chunk = buffer.subarray(offset, Math.min(offset + CHUNK_SIZE, buffer.length));
      const sizeBuffer = Buffer.alloc(4);
      sizeBuffer.writeUInt32BE(chunk.length, 0);
      socket.write(sizeBuffer);
      socket.write(chunk);
    }

    const endBuffer = Buffer.alloc(4);
    endBuffer.writeUInt32BE(0, 0);
    socket.write(endBuffer);
  });

  socket.on('data', (chunk) => {
    responseChunks.push(chunk);
  });

  socket.on('end', () => {
    finish(resolve, Buffer.concat(responseChunks).toString('utf8'));
  });

  socket.on('close', (hadError) => {
    if (!hadError && !settled) {
      finish(resolve, Buffer.concat(responseChunks).toString('utf8'));
    }
  });

  socket.on('error', (error) => {
    finish(reject, new Error(`Connexion antivirus impossible : ${error.message}`));
  });
});

async function scanBuffer(buffer) {
  const config = getAntivirusConfig();

  if (!config.enabled) {
    return { status: 'skipped', reason: 'disabled', config };
  }

  try {
    const responseText = await sendBufferToClamd(buffer, config);
    return { ...parseScanResponse(responseText), config };
  } catch (error) {
    return { status: 'error', error: error.message, config };
  }
}

module.exports = {
  getAntivirusConfig,
  parseScanResponse,
  scanBuffer,
};