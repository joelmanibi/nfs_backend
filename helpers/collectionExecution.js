'use strict';

const fs = require('fs');
const path = require('path');
const { Writable } = require('stream');
const { randomUUID } = require('crypto');
const SftpClient = require('ssh2-sftp-client');
const ftp = require('basic-ftp');
const { Op } = require('sequelize');
const {
  File,
  User,
  CollectionConfig,
  CollectionRecipient,
  CollectionExecution,
  sequelize,
} = require('../src/models');
const { encryptToFile } = require('./crypto');
const { decryptSecret } = require('./secretCrypto');
const { scanBuffer } = require('./antivirus');
const { sendFileReceivedEmail } = require('./mailer');
const logger = require('../config/logger');

const ENCRYPTED_DIR = path.resolve('assets', 'encrypted');
const FTP_TLS_REJECT_UNAUTHORIZED = process.env.COLLECTION_FTPS_REJECT_UNAUTHORIZED !== 'false';
const HTTP_DEFAULT_PORTS = { HTTP: 80, HTTPS: 443 };
const HTTP_METHODS = new Set(['GET', 'POST']);
const HTTP_RESPONSE_MODES = new Set(['SINGLE_FILE', 'FILE_LIST']);
const HTTP_FILE_LIST_KEYS = ['files', 'items', 'results', 'entries', 'documents', 'data'];
const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
let archiverModulePromise;

const CONTENT_TYPE_EXTENSION_MAP = {
  'application/json': 'json',
  'application/pdf': 'pdf',
  'application/zip': 'zip',
  'application/xml': 'xml',
  'application/octet-stream': 'bin',
  'text/plain': 'txt',
  'text/csv': 'csv',
  'text/xml': 'xml',
};

const getArchiver = async () => {
  if (!archiverModulePromise) {
    archiverModulePromise = import('archiver').then((mod) => mod.default || mod);
  }
  return archiverModulePromise;
};

const createHttpError = (statusCode, message) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

const parseRequestQueryEntries = (rawValue) => {
  const raw = String(rawValue || '').trim();
  if (!raw) return [];

  if (raw.startsWith('{')) {
    const parsed = JSON.parse(raw);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new Error('requestQuery JSON doit être un objet clé/valeur.');
    }

    return Object.entries(parsed).flatMap(([key, value]) => {
      if (value === undefined || value === null) return [];
      if (Array.isArray(value)) return value.map((item) => [key, String(item)]);
      return [[key, String(value)]];
    });
  }

  const params = new URLSearchParams(raw.startsWith('?') ? raw.slice(1) : raw);
  return Array.from(params.entries());
};

const parseHttpHeadersEntries = (rawValue) => {
  const raw = String(rawValue || '').trim();
  if (!raw) return [];

  if (raw.startsWith('{')) {
    const parsed = JSON.parse(raw);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new Error('httpHeaders JSON doit être un objet clé/valeur.');
    }

    return Object.entries(parsed).flatMap(([key, value]) => {
      const normalizedKey = String(key || '').trim();
      if (!normalizedKey) throw new Error('Chaque header HTTP doit avoir un nom.');
      if (value === undefined || value === null) return [];
      if (Array.isArray(value)) return value.map((item) => [normalizedKey, String(item)]);
      return [[normalizedKey, String(value)]];
    });
  }

  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const separatorIndex = line.indexOf(':');
      if (separatorIndex <= 0) {
        throw new Error('Chaque header HTTP doit être au format Nom: Valeur.');
      }

      return [
        line.slice(0, separatorIndex).trim(),
        line.slice(separatorIndex + 1).trim(),
      ];
    });
};

const getHttpMethod = (config) => {
  const method = String(config.httpMethod || 'GET').toUpperCase();
  return HTTP_METHODS.has(method) ? method : 'GET';
};

const getHttpResponseMode = (config) => {
  const mode = String(config.httpResponseMode || 'SINGLE_FILE').toUpperCase();
  return HTTP_RESPONSE_MODES.has(mode) ? mode : 'SINGLE_FILE';
};

const decryptOptionalSecret = (payload) => (payload ? decryptSecret(payload) : null);

const buildHttpCollectionUrl = (config, sourceDirectory = config.sourceDirectory) => {
  const protocol = String(config.protocol || 'HTTP').toUpperCase();
  const defaultPort = HTTP_DEFAULT_PORTS[protocol];
  const baseUrl = new URL(`${protocol.toLowerCase()}://${String(config.host).trim()}`);

  if (Number.isInteger(Number(config.port)) && Number(config.port) > 0 && Number(config.port) !== defaultPort) {
    baseUrl.port = String(config.port);
  }

  const normalizedPath = String(sourceDirectory || '/').trim();
  baseUrl.pathname = normalizedPath.startsWith('/') ? normalizedPath : `/${normalizedPath}`;

  parseRequestQueryEntries(config.requestQuery).forEach(([key, value]) => {
    baseUrl.searchParams.append(key, value);
  });

  return baseUrl.toString();
};

const buildHttpHeaders = (config, { accept = '*/*' } = {}) => {
  const headers = new Headers({ Accept: accept });

  parseHttpHeadersEntries(decryptOptionalSecret(config.httpHeaders)).forEach(([key, value]) => {
    headers.append(key, value);
  });

  if (!headers.has('authorization') && config.username && config.encryptedPassword) {
    const password = decryptSecret(config.encryptedPassword);
    headers.set('Authorization', `Basic ${Buffer.from(`${config.username}:${password}`).toString('base64')}`);
  }

  return headers;
};

const buildHttpRequestBody = (config, method, headers) => {
  if (method !== 'POST') return undefined;

  const rawBody = decryptOptionalSecret(config.httpBody);
  if (!rawBody) return undefined;

  const trimmedBody = rawBody.trim();
  if ((trimmedBody.startsWith('{') || trimmedBody.startsWith('[')) && !headers.has('content-type')) {
    headers.set('Content-Type', 'application/json');
  }

  return rawBody;
};

const executeHttpRequest = async (requestUrl, config, {
  method = getHttpMethod(config),
  includeBody = method === getHttpMethod(config),
  accept = '*/*',
} = {}) => {
  const headers = buildHttpHeaders(config, { accept });
  const response = await fetch(requestUrl, {
    method,
    headers,
    body: includeBody ? buildHttpRequestBody(config, method, headers) : undefined,
  });

  if (!response.ok) {
    throw new Error(`API HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ''}`);
  }

  return response;
};

const extractFilenameFromContentDisposition = (headerValue) => {
  const raw = String(headerValue || '').trim();
  if (!raw) return null;

  const utf8Match = raw.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) return path.posix.basename(decodeURIComponent(utf8Match[1]));

  const simpleMatch = raw.match(/filename="?([^";]+)"?/i);
  if (simpleMatch?.[1]) return path.posix.basename(simpleMatch[1]);

  return null;
};

const extensionFromContentType = (contentType) => {
  const normalized = String(contentType || '').split(';')[0].trim().toLowerCase();
  return CONTENT_TYPE_EXTENSION_MAP[normalized] || 'bin';
};

const resolveHttpCollectedFileName = (response, requestUrl, config) => {
  const fromHeader = extractFilenameFromContentDisposition(response.headers.get('content-disposition'));
  if (fromHeader) return fromHeader;

  const pathname = new URL(requestUrl).pathname;
  const fromUrl = path.posix.basename(pathname);
  if (fromUrl && fromUrl !== '/') return fromUrl;

  const fallbackBase = String(config.name || 'collecte_api')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'collecte_api';

  return `${fallbackBase}.${extensionFromContentType(response.headers.get('content-type'))}`;
};

const resolveHttpRemoteUrl = (value, requestUrl) => {
  if (!String(value || '').trim()) return null;
  return new URL(String(value).trim(), requestUrl).toString();
};

const toValidDate = (value) => {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

const extractHttpFileListItems = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') {
    throw new Error('La réponse FILE_LIST doit être un tableau JSON ou un objet contenant un tableau.');
  }

  for (const key of HTTP_FILE_LIST_KEYS) {
    if (Array.isArray(payload[key])) return payload[key];
  }

  const firstArray = Object.values(payload).find(Array.isArray);
  if (firstArray) return firstArray;

  throw new Error('Aucune liste de fichiers exploitable trouvée dans la réponse HTTP.');
};

const normalizeHttpListItem = (item, requestUrl, index) => {
  const fallbackName = `api_file_${index + 1}`;

  if (typeof item === 'string') {
    const remotePath = resolveHttpRemoteUrl(item, requestUrl);
    if (!remotePath) throw new Error(`Entrée FILE_LIST invalide à l'index ${index}.`);
    const pathname = new URL(remotePath).pathname;
    return {
      name: path.posix.basename(pathname) || fallbackName,
      remotePath,
      displayPath: pathname,
      size: 0,
      modifiedAt: null,
    };
  }

  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    throw new Error(`Entrée FILE_LIST invalide à l'index ${index}.`);
  }

  const remoteValue = item.downloadUrl || item.download_url || item.url || item.href || item.remotePath || item.path;
  const remotePath = resolveHttpRemoteUrl(remoteValue, requestUrl);
  if (!remotePath) {
    throw new Error(`URL de téléchargement introuvable pour l'entrée FILE_LIST #${index + 1}.`);
  }

  const pathname = new URL(remotePath).pathname;
  return {
    name: String(item.name || item.filename || item.fileName || item.label || path.posix.basename(pathname) || fallbackName),
    remotePath,
    displayPath: String(item.displayPath || pathname),
    size: Number(item.size || item.contentLength || 0) || 0,
    modifiedAt: toValidDate(item.modifiedAt || item.updatedAt || item.lastModified || item.last_modified),
  };
};

const fetchHttpFileList = async (requestUrl, config) => {
  const response = await executeHttpRequest(requestUrl, config, {
    method: getHttpMethod(config),
    includeBody: true,
    accept: 'application/json, */*',
  });
  const payload = await response.json();
  const items = extractHttpFileListItems(payload);
  return items.map((item, index) => normalizeHttpListItem(item, requestUrl, index));
};

const generateReference = () => {
  const now = new Date();
  const YYYY = now.getFullYear();
  const MM = String(now.getMonth() + 1).padStart(2, '0');
  const DD = String(now.getDate()).padStart(2, '0');
  const HH = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const SS = String(now.getSeconds()).padStart(2, '0');
  const R1 = LETTERS[Math.floor(Math.random() * 26)];
  const R2 = LETTERS[Math.floor(Math.random() * 26)];
  return `DOC-${YYYY}-${MM}-${R1}${R2}-${DD}${HH}${mm}${SS}`;
};

const formatArchiveName = (configName) => {
  const safeName = String(configName || 'collecte')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 40) || 'collecte';

  const now = new Date();
  const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`;
  return `collecte_${safeName}_${stamp}.zip`;
};

const dedupeEntryName = (name, seen) => {
  const ext = path.posix.extname(name);
  const base = ext ? name.slice(0, -ext.length) : name;
  let candidate = name;
  let index = 1;

  while (seen.has(candidate)) {
    candidate = `${base}_${index}${ext}`;
    index += 1;
  }

  seen.add(candidate);
  return candidate;
};

const createArchiveBuffer = async (entries) => {
  const archiver = await getArchiver();

  return new Promise((resolve, reject) => {
    const chunks = [];
    const archive = archiver('zip', { zlib: { level: 9 } });
    const output = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    });

    output.on('finish', () => resolve(Buffer.concat(chunks)));
    output.on('error', reject);
    archive.on('warning', (error) => {
      if (error.code === 'ENOENT') return;
      reject(error);
    });
    archive.on('error', reject);

    archive.pipe(output);
    entries.forEach((entry) => {
      archive.append(entry.buffer, { name: entry.name });
    });

    Promise.resolve(archive.finalize()).catch(reject);
  });
};

const buildSftpClient = async (config) => {
  const client = new SftpClient();
  const options = {
    host: config.host,
    port: config.port,
    username: config.username,
    readyTimeout: 20000,
  };

  if (config.authType === 'SSH_KEY') {
    options.privateKey = decryptSecret(config.encryptedPrivateKey);
  } else {
    options.password = decryptSecret(config.encryptedPassword);
  }

  await client.connect(options);

  return {
    async listFiles(sourceDirectory) {
      const rows = await client.list(sourceDirectory);
      return rows
        .filter((row) => row.type === '-')
        .map((row) => ({
          name: row.name,
          remotePath: path.posix.join(sourceDirectory, row.name),
          size: Number(row.size) || 0,
          modifiedAt: row.modifyTime ? new Date(row.modifyTime) : null,
        }));
    },
    async downloadBuffer(remotePath) {
      const data = await client.get(remotePath);
      return Buffer.isBuffer(data) ? data : Buffer.from(data);
    },
    async close() {
      await client.end();
    },
  };
};

const buildFtpClient = async (config) => {
  const client = new ftp.Client(20000);
  client.ftp.verbose = false;

  await client.access({
    host: config.host,
    port: config.port,
    user: config.username,
    password: decryptSecret(config.encryptedPassword),
    secure: config.protocol === 'FTPS',
    secureOptions: config.protocol === 'FTPS'
      ? { rejectUnauthorized: FTP_TLS_REJECT_UNAUTHORIZED }
      : undefined,
  });

  return {
    async listFiles(sourceDirectory) {
      const rows = await client.list(sourceDirectory);
      return rows
        .filter((row) => row.isFile)
        .map((row) => ({
          name: row.name,
          remotePath: path.posix.join(sourceDirectory, row.name),
          size: Number(row.size) || 0,
          modifiedAt: row.modifiedAt || null,
        }));
    },
    async downloadBuffer(remotePath) {
      const chunks = [];
      const writable = new Writable({
        write(chunk, _encoding, callback) {
          chunks.push(Buffer.from(chunk));
          callback();
        },
      });

      await client.downloadTo(writable, remotePath);
      return Buffer.concat(chunks);
    },
    async close() {
      client.close();
    },
  };
};

const fetchHttpResource = async (requestUrl, config, options = {}) => {
  const response = await executeHttpRequest(requestUrl, config, options);
  const buffer = Buffer.from(await response.arrayBuffer());
  const modifiedAtRaw = response.headers.get('last-modified');
  const modifiedAt = modifiedAtRaw ? new Date(modifiedAtRaw) : null;

  return {
    requestUrl,
    displayPath: new URL(requestUrl).pathname,
    name: resolveHttpCollectedFileName(response, requestUrl, config),
    buffer,
    modifiedAt: modifiedAt && !Number.isNaN(modifiedAt.getTime()) ? modifiedAt : null,
  };
};

const buildHttpClient = async (config) => {
  const cache = new Map();

  return {
    async listFiles(sourceDirectory) {
      const requestUrl = buildHttpCollectionUrl(config, sourceDirectory);
      if (getHttpResponseMode(config) === 'FILE_LIST') {
        return fetchHttpFileList(requestUrl, config);
      }

      const resource = await fetchHttpResource(requestUrl, config, {
        method: getHttpMethod(config),
        includeBody: true,
      });
      cache.set(requestUrl, resource.buffer);

      return [{
        name: resource.name,
        remotePath: requestUrl,
        displayPath: resource.displayPath,
        size: resource.buffer.length,
        modifiedAt: resource.modifiedAt,
      }];
    },
    async downloadBuffer(remotePath) {
      if (cache.has(remotePath)) return cache.get(remotePath);

      const resource = await fetchHttpResource(remotePath, config, {
        method: 'GET',
        includeBody: false,
      });
      cache.set(remotePath, resource.buffer);
      return resource.buffer;
    },
    async close() {},
  };
};

const openRemoteClient = async (config) => {
  if (config.protocol === 'SFTP') return buildSftpClient(config);
  if (config.protocol === 'FTP' || config.protocol === 'FTPS') return buildFtpClient(config);
  if (config.protocol === 'HTTP' || config.protocol === 'HTTPS') return buildHttpClient(config);
  throw createHttpError(400, `Protocole non supporté : ${config.protocol}`);
};

const distributeArchive = async ({ archiveBuffer, archiveName, config, recipients }) => {
  const sender = await User.findByPk(config.createdByAdminId, {
    attributes: ['id', 'firstName', 'email'],
  });

  const senderFirstName = sender?.firstName || '—';
  const storedFileId = randomUUID();
  const destinationPath = path.join(ENCRYPTED_DIR, storedFileId);
  const iv = encryptToFile(archiveBuffer, destinationPath);
  const createdRecords = [];
  const transaction = await sequelize.transaction();

  try {
    for (const recipient of recipients) {
      const record = await File.create({
        id: randomUUID(),
        reference: generateReference(),
        senderId: config.createdByAdminId,
        receiverEmail: recipient.email.toLowerCase(),
        originalName: archiveName,
        encryptedPath: storedFileId,
        size: archiveBuffer.length,
        isProtected: false,
        downloadCodeHash: null,
        iv,
        comment: config.comment?.trim() || config.description?.trim() || null,
      }, { transaction });

      createdRecords.push(record);
    }

    await transaction.commit();
  } catch (error) {
    await transaction.rollback();
    if (fs.existsSync(destinationPath)) {
      try { fs.unlinkSync(destinationPath); } catch {}
    }
    throw error;
  }

  for (let index = 0; index < createdRecords.length; index += 1) {
    const record = createdRecords[index];
    const recipient = recipients[index];

    try {
      await sendFileReceivedEmail({
        to: recipient.email,
        fileId: record.id,
        senderFirstName,
        originalName: record.originalName,
        reference: record.reference,
        size: record.size,
        isProtected: false,
        comment: config.comment?.trim() || config.description?.trim() || null,
      });
    } catch (mailError) {
      logger.error('Collection recipient email failed', {
        event: 'collection_recipient_email_failed',
        collectionConfigId: config.id,
        fileId: record.id,
        recipientEmail: recipient.email,
        error: mailError.message,
      });
    }
  }

  return createdRecords.length;
};

const sanitizeExecution = (execution) => ({
  id: execution.id,
  collectionConfigId: execution.collectionConfigId,
  triggerType: execution.triggerType,
  status: execution.status,
  executedAt: execution.executedAt,
  finishedAt: execution.finishedAt,
  collectedFilesCount: execution.collectedFilesCount,
  distributedFilesCount: execution.distributedFilesCount,
  errorMessage: execution.errorMessage,
});

const executeCollectionConfig = async (configId, { triggerType = 'MANUAL' } = {}) => {
  const config = await CollectionConfig.findByPk(configId, {
    include: [
      {
        model: CollectionRecipient,
        as: 'recipients',
        include: [{ model: User, as: 'user', attributes: ['id', 'email'] }],
      },
      { model: User, as: 'createdBy', attributes: ['id', 'email', 'firstName'] },
    ],
  });

  if (!config) throw createHttpError(404, 'Configuration de collecte introuvable.');
  if (!config.isActive) throw createHttpError(409, 'Cette configuration de collecte est désactivée.');
  if (!config.recipients.length) throw createHttpError(400, 'Aucun destinataire configuré pour cette collecte.');

  const runningExecution = await CollectionExecution.findOne({
    where: {
      collectionConfigId: config.id,
      status: 'RUNNING',
    },
  });

  if (runningExecution) {
    throw createHttpError(409, 'Une exécution est déjà en cours pour cette collecte.');
  }

  if (triggerType === 'SCHEDULED') {
    await config.update({ lastScheduledRunAt: new Date() });
  }

  const execution = await CollectionExecution.create({
    collectionConfigId: config.id,
    triggerType,
    status: 'RUNNING',
    executedAt: new Date(),
    collectedFilesCount: 0,
    distributedFilesCount: 0,
  });

  let remoteClient;

  try {
    remoteClient = await openRemoteClient(config);
    const remoteFiles = await remoteClient.listFiles(config.sourceDirectory);
    const lastSuccess = config.lastSuccessfulRunAt ? new Date(config.lastSuccessfulRunAt) : null;

    const candidateFiles = remoteFiles.filter((file) => {
      if (!lastSuccess || !file.modifiedAt) return true;
      return file.modifiedAt > lastSuccess;
    });

    const warnings = [];
    const archiveEntries = [];
    const seenNames = new Set();

    for (const file of candidateFiles) {
      try {
        const buffer = await remoteClient.downloadBuffer(file.remotePath);
        const scanResult = await scanBuffer(buffer);

        if (scanResult.status === 'infected') {
          warnings.push(`${file.name}: rejeté par l'antivirus`);
          logger.warn('Collection remote file rejected by antivirus', {
            event: 'collection_remote_file_infected',
            collectionConfigId: config.id,
            remotePath: file.displayPath || file.remotePath,
            threat: scanResult.threat,
          });
          continue;
        }

        if (scanResult.status === 'error' && scanResult.config.failOnError) {
          throw new Error(`Analyse antivirus indisponible pour ${file.name}.`);
        }

        if (scanResult.status === 'error') {
          warnings.push(`${file.name}: antivirus indisponible, fichier conservé`);
        }

        if (scanResult.status === 'skipped') {
          warnings.push(`${file.name}: scan antivirus ignoré`);
        }

        archiveEntries.push({
          name: dedupeEntryName(file.name, seenNames),
          buffer,
        });
      } catch (fileError) {
        warnings.push(`${file.name}: ${fileError.message}`);
      }
    }

    let status = 'SUCCESS';
    let distributedFilesCount = 0;
    let errorMessage = null;

    if (!archiveEntries.length) {
      status = warnings.length ? 'FAILED' : 'SUCCESS';
      errorMessage = warnings.length ? warnings.join(' | ').slice(0, 2000) : null;
    } else {
      const archiveBuffer = await createArchiveBuffer(archiveEntries);
      const archiveName = formatArchiveName(config.name);
      const recipients = config.recipients.map((link) => link.user).filter(Boolean);

      distributedFilesCount = await distributeArchive({
        archiveBuffer,
        archiveName,
        config,
        recipients,
      });

      if (warnings.length) {
        status = 'PARTIAL';
        errorMessage = warnings.join(' | ').slice(0, 2000);
      }
    }

    await execution.update({
      status,
      collectedFilesCount: archiveEntries.length,
      distributedFilesCount,
      errorMessage,
      finishedAt: new Date(),
    });

    await config.update({
      lastRunAt: new Date(),
      lastSuccessfulRunAt: status === 'FAILED' ? config.lastSuccessfulRunAt : new Date(),
    });

    logger.info('Collection execution completed', {
      event: 'collection_execution_completed',
      collectionConfigId: config.id,
      executionId: execution.id,
      triggerType,
      status,
      collectedFilesCount: archiveEntries.length,
      distributedFilesCount,
    });

    return sanitizeExecution(execution);
  } catch (error) {
    await execution.update({
      status: 'FAILED',
      errorMessage: error.message.slice(0, 2000),
      finishedAt: new Date(),
    });

    await config.update({ lastRunAt: new Date() });

    logger.error('Collection execution failed', {
      event: 'collection_execution_failed',
      collectionConfigId: config.id,
      executionId: execution.id,
      triggerType,
      error: error.message,
    });

    return sanitizeExecution(execution);
  } finally {
    if (remoteClient) {
      try {
        await remoteClient.close();
      } catch (closeError) {
        logger.warn('Collection remote client close failed', {
          event: 'collection_client_close_failed',
          collectionConfigId: config.id,
          error: closeError.message,
        });
      }
    }
  }
};

module.exports = {
  buildHttpClient,
  buildHttpCollectionUrl,
  executeCollectionConfig,
  parseHttpHeadersEntries,
  parseRequestQueryEntries,
  resolveHttpCollectedFileName,
};