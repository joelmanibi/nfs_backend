'use strict';

const { Op } = require('sequelize');
const {
  User,
  CollectionConfig,
  CollectionRecipient,
  CollectionExecution,
  sequelize,
} = require('../models');
const { encryptSecret, decryptSecret } = require('../../helpers/secretCrypto');
const {
  executeCollectionConfig,
  parseHttpHeadersEntries,
  parseRequestQueryEntries,
} = require('../../helpers/collectionExecution');
const logger = require('../../config/logger');

const DEFAULT_PORTS = { SFTP: 22, FTP: 21, FTPS: 21, HTTP: 80, HTTPS: 443 };
const SUPPORTED_PROTOCOLS = ['SFTP', 'FTP', 'FTPS', 'HTTP', 'HTTPS'];
const HTTP_PROTOCOLS = new Set(['HTTP', 'HTTPS']);
const HTTP_METHODS = ['GET', 'POST'];
const HTTP_RESPONSE_MODES = ['SINGLE_FILE', 'FILE_LIST'];
const TIME_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;

const createHttpError = (statusCode, message) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

const parseBoolean = (value, fallback = false) => {
  if (value === undefined) return fallback;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'off'].includes(normalized)) return false;
  }
  return fallback;
};

const parseRecipientIds = (value) => {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((id) => String(id).trim()).filter(Boolean))];
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

const sanitizeConfig = (config, lastExecution = null, { includeSecrets = false } = {}) => {
  const source = config.toJSON ? config.toJSON() : config;
  const isHttpCollection = HTTP_PROTOCOLS.has(source.protocol);

  return {
    id: source.id,
    name: source.name,
    host: source.host,
    protocol: source.protocol,
    port: source.port,
    username: source.username,
    authType: source.authType,
    sourceDirectory: source.sourceDirectory,
    requestQuery: source.requestQuery,
    httpMethod: isHttpCollection ? source.httpMethod || 'GET' : null,
    httpHeaders: includeSecrets && isHttpCollection && source.httpHeaders ? decryptSecret(source.httpHeaders) : null,
    httpBody: includeSecrets && isHttpCollection && source.httpBody ? decryptSecret(source.httpBody) : null,
    httpResponseMode: isHttpCollection ? source.httpResponseMode || 'SINGLE_FILE' : null,
    scheduleType: source.scheduleType,
    scheduleTime: source.scheduleTime,
    scheduleDayOfWeek: source.scheduleDayOfWeek,
    scheduleDayOfMonth: source.scheduleDayOfMonth,
    comment: source.comment,
    description: source.description,
    isActive: source.isActive,
    createdByAdminId: source.createdByAdminId,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
    lastRunAt: source.lastRunAt,
    lastSuccessfulRunAt: source.lastSuccessfulRunAt,
    lastScheduledRunAt: source.lastScheduledRunAt,
    hasPassword: Boolean(source.encryptedPassword),
    hasSshPrivateKey: Boolean(source.encryptedPrivateKey),
    hasHttpHeaders: Boolean(source.httpHeaders),
    hasHttpBody: Boolean(source.httpBody),
    recipients: (source.recipients || []).map((recipient) => ({
      id: recipient.id,
      userId: recipient.userId,
      user: recipient.user ? {
        id: recipient.user.id,
        email: recipient.user.email,
        firstName: recipient.user.firstName,
        lastName: recipient.user.lastName,
      } : undefined,
    })),
    lastExecution,
  };
};

const validatePayload = async (payload, {
  partial = false,
  currentProtocol,
  currentAuthType,
  currentHttpMethod,
} = {}) => {
  const protocol = payload.protocol !== undefined
    ? String(payload.protocol || '').toUpperCase()
    : currentProtocol;
  const authType = payload.authType !== undefined
    ? String(payload.authType || '').toUpperCase()
    : currentAuthType;
  const scheduleType = payload.scheduleType ? String(payload.scheduleType).toUpperCase() : undefined;
  const httpMethod = payload.httpMethod !== undefined
    ? String(payload.httpMethod || '').toUpperCase()
    : (currentHttpMethod || 'GET');
  const httpResponseMode = payload.httpResponseMode !== undefined
    ? String(payload.httpResponseMode || '').toUpperCase()
    : 'SINGLE_FILE';
  const recipientUserIds = payload.recipientUserIds !== undefined
    ? parseRecipientIds(payload.recipientUserIds)
    : undefined;
  const isHttpCollection = HTTP_PROTOCOLS.has(protocol);

  if (!partial || payload.name !== undefined) {
    if (!String(payload.name || '').trim()) throw createHttpError(400, 'Le nom de la configuration est requis.');
  }

  if (!partial || payload.host !== undefined) {
    if (!String(payload.host || '').trim()) throw createHttpError(400, 'L’adresse IP ou le hostname est requis.');
  }

  if (!partial || payload.protocol !== undefined) {
    if (!SUPPORTED_PROTOCOLS.includes(protocol)) {
      throw createHttpError(400, 'Protocole invalide. Valeurs acceptées : SFTP, FTP, FTPS, HTTP, HTTPS.');
    }
  }

  if (!partial || payload.username !== undefined) {
    if (!HTTP_PROTOCOLS.has(protocol) && !String(payload.username || '').trim()) {
      throw createHttpError(400, 'Le login distant est requis.');
    }
  }

  if (!partial || payload.sourceDirectory !== undefined) {
    if (!String(payload.sourceDirectory || '').trim()) {
      throw createHttpError(400, 'Le répertoire source ou l’endpoint API est requis.');
    }
  }

  if (!partial || payload.scheduleType !== undefined) {
    if (!['MANUAL', 'DAILY', 'WEEKLY', 'MONTHLY'].includes(scheduleType)) {
      throw createHttpError(400, 'Planification invalide. Valeurs acceptées : MANUAL, DAILY, WEEKLY, MONTHLY.');
    }
  }

  if (authType && !['PASSWORD', 'SSH_KEY'].includes(authType)) {
    throw createHttpError(400, 'Type d’authentification invalide. Valeurs acceptées : PASSWORD, SSH_KEY.');
  }

  if (authType === 'SSH_KEY' && protocol && protocol !== 'SFTP') {
    throw createHttpError(400, 'Seul SFTP supporte la clé SSH dans cette implémentation.');
  }

  if (isHttpCollection && payload.requestQuery !== undefined && String(payload.requestQuery || '').trim()) {
    try {
      parseRequestQueryEntries(payload.requestQuery);
    } catch (error) {
      throw createHttpError(400, `Paramètres API invalides : ${error.message}`);
    }
  }

  if (isHttpCollection && payload.httpHeaders !== undefined && String(payload.httpHeaders || '').trim()) {
    try {
      parseHttpHeadersEntries(payload.httpHeaders);
    } catch (error) {
      throw createHttpError(400, `Headers HTTP invalides : ${error.message}`);
    }
  }

  if (isHttpCollection && (!partial || payload.httpMethod !== undefined || payload.protocol !== undefined)) {
    if (!HTTP_METHODS.includes(httpMethod)) {
      throw createHttpError(400, 'Méthode HTTP invalide. Valeurs acceptées : GET, POST.');
    }
  }

  if (isHttpCollection && (!partial || payload.httpResponseMode !== undefined || payload.protocol !== undefined)) {
    if (!HTTP_RESPONSE_MODES.includes(httpResponseMode)) {
      throw createHttpError(400, 'Mode de réponse HTTP invalide. Valeurs acceptées : SINGLE_FILE, FILE_LIST.');
    }
  }

  if (isHttpCollection && httpMethod === 'GET' && payload.httpBody !== undefined && String(payload.httpBody || '').trim()) {
    throw createHttpError(400, 'Le body HTTP est réservé aux requêtes POST.');
  }

  const port = payload.port !== undefined && payload.port !== null && payload.port !== ''
    ? Number(payload.port)
    : ((!partial || payload.protocol !== undefined) && protocol ? DEFAULT_PORTS[protocol] : undefined);

  if (port !== undefined && (!Number.isInteger(port) || port <= 0 || port > 65535)) {
    throw createHttpError(400, 'Port invalide.');
  }

  if (scheduleType && scheduleType !== 'MANUAL') {
    if (!TIME_REGEX.test(String(payload.scheduleTime || ''))) {
      throw createHttpError(400, 'scheduleTime doit être au format HH:mm.');
    }

    if (scheduleType === 'WEEKLY') {
      const day = Number(payload.scheduleDayOfWeek);
      if (!Number.isInteger(day) || day < 0 || day > 6) {
        throw createHttpError(400, 'scheduleDayOfWeek doit être compris entre 0 et 6.');
      }
    }

    if (scheduleType === 'MONTHLY') {
      const day = Number(payload.scheduleDayOfMonth);
      if (!Number.isInteger(day) || day < 1 || day > 31) {
        throw createHttpError(400, 'scheduleDayOfMonth doit être compris entre 1 et 31.');
      }
    }
  }

  let recipients = undefined;
  if (recipientUserIds !== undefined) {
    if (!recipientUserIds.length) throw createHttpError(400, 'Au moins un destinataire doit être sélectionné.');
    recipients = await User.findAll({
      where: { id: { [Op.in]: recipientUserIds } },
      attributes: ['id', 'email', 'firstName', 'lastName'],
    });
    if (recipients.length !== recipientUserIds.length) {
      throw createHttpError(400, 'Un ou plusieurs destinataires sont invalides.');
    }
  }

  return {
    protocol: !partial || payload.protocol !== undefined ? protocol : undefined,
    authType: !partial || payload.authType !== undefined ? authType : undefined,
    scheduleType,
    port,
    httpMethod: isHttpCollection && (!partial || payload.httpMethod !== undefined || payload.protocol !== undefined)
      ? httpMethod
      : undefined,
    httpResponseMode: isHttpCollection && (!partial || payload.httpResponseMode !== undefined || payload.protocol !== undefined)
      ? httpResponseMode
      : undefined,
    scheduleTime: payload.scheduleTime !== undefined ? String(payload.scheduleTime || '').trim() || null : undefined,
    scheduleDayOfWeek: payload.scheduleDayOfWeek !== undefined && payload.scheduleDayOfWeek !== null && payload.scheduleDayOfWeek !== ''
      ? Number(payload.scheduleDayOfWeek)
      : null,
    scheduleDayOfMonth: payload.scheduleDayOfMonth !== undefined && payload.scheduleDayOfMonth !== null && payload.scheduleDayOfMonth !== ''
      ? Number(payload.scheduleDayOfMonth)
      : null,
    recipientUserIds,
    recipients,
  };
};

const validateEffectiveSchedule = ({ scheduleType, scheduleTime, scheduleDayOfWeek, scheduleDayOfMonth }) => {
  if (scheduleType === 'MANUAL') return;

  if (!TIME_REGEX.test(String(scheduleTime || ''))) {
    throw createHttpError(400, 'scheduleTime doit être au format HH:mm.');
  }

  if (scheduleType === 'WEEKLY') {
    const day = Number(scheduleDayOfWeek);
    if (!Number.isInteger(day) || day < 0 || day > 6) {
      throw createHttpError(400, 'scheduleDayOfWeek doit être compris entre 0 et 6.');
    }
  }

  if (scheduleType === 'MONTHLY') {
    const day = Number(scheduleDayOfMonth);
    if (!Number.isInteger(day) || day < 1 || day > 31) {
      throw createHttpError(400, 'scheduleDayOfMonth doit être compris entre 1 et 31.');
    }
  }
};

const syncRecipients = async (collectionConfigId, recipientUserIds, transaction) => {
  await CollectionRecipient.destroy({ where: { collectionConfigId }, transaction });

  if (!recipientUserIds?.length) return;

  await CollectionRecipient.bulkCreate(
    recipientUserIds.map((userId) => ({ collectionConfigId, userId })),
    { transaction },
  );
};

const loadConfigForResponse = async (id, options = {}) => {
  const config = await CollectionConfig.findByPk(id, {
    include: [{
      model: CollectionRecipient,
      as: 'recipients',
      include: [{ model: User, as: 'user', attributes: ['id', 'email', 'firstName', 'lastName'] }],
    }],
  });

  const lastExecution = await CollectionExecution.findOne({
    where: { collectionConfigId: id },
    order: [['executedAt', 'DESC']],
  });

  return sanitizeConfig(config, lastExecution ? sanitizeExecution(lastExecution) : null, options);
};

const listCollectionConfigs = async (req, res) => {
  try {
    const rows = await CollectionConfig.findAll({
      order: [['createdAt', 'DESC']],
      include: [{
        model: CollectionRecipient,
        as: 'recipients',
        include: [{ model: User, as: 'user', attributes: ['id', 'email', 'firstName', 'lastName'] }],
      }],
    });

    const executions = await CollectionExecution.findAll({
      where: { collectionConfigId: { [Op.in]: rows.map((row) => row.id) } },
      order: [['executedAt', 'DESC']],
    });

    const lastExecutionByConfig = new Map();
    executions.forEach((execution) => {
      if (!lastExecutionByConfig.has(execution.collectionConfigId)) {
        lastExecutionByConfig.set(execution.collectionConfigId, sanitizeExecution(execution));
      }
    });

    return res.json({
      count: rows.length,
      collections: rows.map((row) => sanitizeConfig(row, lastExecutionByConfig.get(row.id) || null)),
    });
  } catch (error) {
    logger.error('Collection config list failed', { error: error.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const getCollectionConfig = async (req, res) => {
  try {
    const config = await CollectionConfig.findByPk(req.params.id);
    if (!config) return res.status(404).json({ message: 'Configuration de collecte introuvable.' });

    return res.json({ collection: await loadConfigForResponse(config.id, { includeSecrets: true }) });
  } catch (error) {
    logger.error('Collection config detail failed', { error: error.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const createCollectionConfig = async (req, res) => {
  const transaction = await sequelize.transaction();

  try {
    const normalized = await validatePayload(req.body);
    if (!normalized.recipientUserIds?.length) {
      throw createHttpError(400, 'Au moins un destinataire doit être sélectionné.');
    }

    const authType = normalized.authType || 'PASSWORD';
    const isHttpCollection = HTTP_PROTOCOLS.has(normalized.protocol);
    const trimmedUsername = String(req.body.username || '').trim();
    const trimmedPassword = String(req.body.password || '').trim();
    const trimmedHttpHeaders = String(req.body.httpHeaders || '').trim();
    const trimmedHttpBody = String(req.body.httpBody || '').trim();

    if (!isHttpCollection && authType === 'PASSWORD' && !trimmedPassword) {
      throw createHttpError(400, 'Le mot de passe distant est requis.');
    }

    if (isHttpCollection && Boolean(trimmedUsername) !== Boolean(trimmedPassword)) {
      throw createHttpError(400, 'Le login API et le mot de passe API doivent être fournis ensemble pour le Basic Auth.');
    }

    if (authType === 'SSH_KEY' && !String(req.body.sshPrivateKey || '').trim()) {
      throw createHttpError(400, 'La clé SSH est requise.');
    }

    const config = await CollectionConfig.create({
      name: String(req.body.name).trim(),
      host: String(req.body.host).trim(),
      protocol: normalized.protocol,
      port: normalized.port,
      username: trimmedUsername,
      authType,
      encryptedPassword: authType === 'PASSWORD' && trimmedPassword ? encryptSecret(trimmedPassword) : null,
      encryptedPrivateKey: authType === 'SSH_KEY' ? encryptSecret(String(req.body.sshPrivateKey)) : null,
      sourceDirectory: String(req.body.sourceDirectory).trim(),
      requestQuery: HTTP_PROTOCOLS.has(normalized.protocol) ? req.body.requestQuery?.trim() || null : null,
      httpMethod: isHttpCollection ? normalized.httpMethod : null,
      httpHeaders: isHttpCollection && trimmedHttpHeaders ? encryptSecret(trimmedHttpHeaders) : null,
      httpBody: isHttpCollection && normalized.httpMethod === 'POST' && trimmedHttpBody ? encryptSecret(trimmedHttpBody) : null,
      httpResponseMode: isHttpCollection ? normalized.httpResponseMode : null,
      scheduleType: normalized.scheduleType,
      scheduleTime: normalized.scheduleType === 'MANUAL' ? null : normalized.scheduleTime,
      scheduleDayOfWeek: normalized.scheduleType === 'WEEKLY' ? normalized.scheduleDayOfWeek : null,
      scheduleDayOfMonth: normalized.scheduleType === 'MONTHLY' ? normalized.scheduleDayOfMonth : null,
      comment: req.body.comment?.trim() || null,
      description: req.body.description?.trim() || null,
      isActive: parseBoolean(req.body.isActive, true),
      createdByAdminId: req.user.id,
    }, { transaction });

    await syncRecipients(config.id, normalized.recipientUserIds, transaction);
    await transaction.commit();

    logger.info('Collection config created', {
      event: 'collection_config_created',
      collectionConfigId: config.id,
      adminId: req.user.id,
      recipientCount: normalized.recipientUserIds.length,
    });

    return res.status(201).json({
      message: 'Configuration de collecte créée.',
      collection: await loadConfigForResponse(config.id),
    });
  } catch (error) {
    await transaction.rollback();

    if (error.statusCode) {
      return res.status(error.statusCode).json({ message: error.message });
    }

    logger.error('Collection config creation failed', { error: error.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const updateCollectionConfig = async (req, res) => {
  const transaction = await sequelize.transaction();

  try {
    const config = await CollectionConfig.findByPk(req.params.id, { transaction });
    if (!config) {
      await transaction.rollback();
      return res.status(404).json({ message: 'Configuration de collecte introuvable.' });
    }

    const normalized = await validatePayload(req.body, {
      partial: true,
      currentProtocol: config.protocol,
      currentAuthType: config.authType,
      currentHttpMethod: config.httpMethod || 'GET',
    });
    const nextProtocol = normalized.protocol || config.protocol;
    const nextAuthType = normalized.authType || config.authType;
    const nextScheduleType = normalized.scheduleType || config.scheduleType;
    const nextIsHttpCollection = HTTP_PROTOCOLS.has(nextProtocol);
    const nextHttpMethod = nextIsHttpCollection ? (normalized.httpMethod || config.httpMethod || 'GET') : null;
    const nextHttpResponseMode = nextIsHttpCollection ? (normalized.httpResponseMode || config.httpResponseMode || 'SINGLE_FILE') : null;
    const nextScheduleTime = normalized.scheduleTime !== undefined ? normalized.scheduleTime : config.scheduleTime;
    const nextScheduleDayOfWeek = normalized.scheduleDayOfWeek !== null && normalized.scheduleDayOfWeek !== undefined
      ? normalized.scheduleDayOfWeek
      : config.scheduleDayOfWeek;
    const nextScheduleDayOfMonth = normalized.scheduleDayOfMonth !== null && normalized.scheduleDayOfMonth !== undefined
      ? normalized.scheduleDayOfMonth
      : config.scheduleDayOfMonth;
    const nextUsername = req.body.username !== undefined ? String(req.body.username || '').trim() : config.username;
    const nextHasPassword = req.body.password !== undefined
      ? Boolean(String(req.body.password || '').trim())
      : Boolean(config.encryptedPassword);

    if (nextAuthType === 'SSH_KEY' && nextProtocol !== 'SFTP') {
      throw createHttpError(400, 'Seul SFTP supporte la clé SSH dans cette implémentation.');
    }

    if (nextIsHttpCollection && Boolean(nextUsername) !== nextHasPassword) {
      throw createHttpError(400, 'Le login API et le mot de passe API doivent être fournis ensemble pour le Basic Auth.');
    }

    if (!nextIsHttpCollection && nextAuthType === 'PASSWORD' && normalized.authType === 'PASSWORD' && !String(req.body.password || '').trim()) {
      throw createHttpError(400, 'Le mot de passe distant est requis.');
    }

    if (nextAuthType === 'SSH_KEY' && normalized.authType === 'SSH_KEY' && !String(req.body.sshPrivateKey || '').trim()) {
      throw createHttpError(400, 'La clé SSH est requise.');
    }

    validateEffectiveSchedule({
      scheduleType: nextScheduleType,
      scheduleTime: nextScheduleTime,
      scheduleDayOfWeek: nextScheduleDayOfWeek,
      scheduleDayOfMonth: nextScheduleDayOfMonth,
    });

    const updates = {};
    if (req.body.name !== undefined) updates.name = String(req.body.name).trim();
    if (req.body.host !== undefined) updates.host = String(req.body.host).trim();
    if (normalized.protocol) updates.protocol = normalized.protocol;
    if (normalized.port !== undefined) updates.port = normalized.port;
    if (req.body.username !== undefined) updates.username = String(req.body.username).trim();
    if (normalized.authType) updates.authType = nextAuthType;
    if (req.body.sourceDirectory !== undefined) updates.sourceDirectory = String(req.body.sourceDirectory).trim();
    if (nextIsHttpCollection) {
      if (req.body.requestQuery !== undefined) updates.requestQuery = req.body.requestQuery?.trim() || null;
      if (normalized.httpMethod !== undefined || (normalized.protocol && !HTTP_PROTOCOLS.has(config.protocol))) {
        updates.httpMethod = nextHttpMethod;
      }
      if (normalized.httpResponseMode !== undefined || (normalized.protocol && !HTTP_PROTOCOLS.has(config.protocol))) {
        updates.httpResponseMode = nextHttpResponseMode;
      }
      if (req.body.httpHeaders !== undefined) {
        const trimmedHttpHeaders = String(req.body.httpHeaders || '').trim();
        updates.httpHeaders = trimmedHttpHeaders ? encryptSecret(trimmedHttpHeaders) : null;
      }
      if (req.body.httpBody !== undefined) {
        const trimmedHttpBody = String(req.body.httpBody || '').trim();
        updates.httpBody = nextHttpMethod === 'POST' && trimmedHttpBody ? encryptSecret(trimmedHttpBody) : null;
      } else if (nextHttpMethod === 'GET' && config.httpBody) {
        updates.httpBody = null;
      }
    } else if (config.requestQuery || config.httpMethod || config.httpHeaders || config.httpBody || config.httpResponseMode) {
      updates.requestQuery = null;
      updates.httpMethod = null;
      updates.httpHeaders = null;
      updates.httpBody = null;
      updates.httpResponseMode = null;
    }
    if (normalized.scheduleType) updates.scheduleType = nextScheduleType;
    if (nextScheduleType === 'MANUAL') {
      updates.scheduleTime = null;
      updates.scheduleDayOfWeek = null;
      updates.scheduleDayOfMonth = null;
    } else {
      if (normalized.scheduleTime !== undefined) updates.scheduleTime = normalized.scheduleTime;
      updates.scheduleDayOfWeek = nextScheduleType === 'WEEKLY'
        ? (normalized.scheduleDayOfWeek ?? config.scheduleDayOfWeek)
        : null;
      updates.scheduleDayOfMonth = nextScheduleType === 'MONTHLY'
        ? (normalized.scheduleDayOfMonth ?? config.scheduleDayOfMonth)
        : null;
    }
    if (req.body.comment !== undefined) updates.comment = req.body.comment?.trim() || null;
    if (req.body.description !== undefined) updates.description = req.body.description?.trim() || null;
    if (req.body.isActive !== undefined) updates.isActive = parseBoolean(req.body.isActive, config.isActive);

    if (nextAuthType === 'PASSWORD') {
      if (req.body.password !== undefined && String(req.body.password).trim()) {
        updates.encryptedPassword = encryptSecret(String(req.body.password).trim());
      } else if (nextIsHttpCollection && req.body.password !== undefined) {
        updates.encryptedPassword = null;
      }
      updates.encryptedPrivateKey = null;
    }

    if (nextAuthType === 'SSH_KEY') {
      if (req.body.sshPrivateKey !== undefined && String(req.body.sshPrivateKey).trim()) {
        updates.encryptedPrivateKey = encryptSecret(String(req.body.sshPrivateKey));
      }
      updates.encryptedPassword = null;
    }

    await config.update(updates, { transaction });

    if (normalized.recipientUserIds !== undefined) {
      await syncRecipients(config.id, normalized.recipientUserIds, transaction);
    }

    await transaction.commit();

    logger.info('Collection config updated', {
      event: 'collection_config_updated',
      collectionConfigId: config.id,
      adminId: req.user.id,
    });

    return res.json({
      message: 'Configuration de collecte mise à jour.',
      collection: await loadConfigForResponse(config.id),
    });
  } catch (error) {
    await transaction.rollback();

    if (error.statusCode) {
      return res.status(error.statusCode).json({ message: error.message });
    }

    logger.error('Collection config update failed', { error: error.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const deleteCollectionConfig = async (req, res) => {
  try {
    const config = await CollectionConfig.findByPk(req.params.id);
    if (!config) return res.status(404).json({ message: 'Configuration de collecte introuvable.' });

    await config.destroy();
    logger.info('Collection config deleted', {
      event: 'collection_config_deleted',
      collectionConfigId: config.id,
      adminId: req.user.id,
    });
    return res.json({ message: 'Configuration de collecte supprimée.' });
  } catch (error) {
    logger.error('Collection config delete failed', { error: error.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const runCollectionConfig = async (req, res) => {
  try {
    const execution = await executeCollectionConfig(req.params.id, {
      triggerType: 'MANUAL',
    });

    const statusCode = execution.status === 'FAILED' ? 422 : 200;
    return res.status(statusCode).json({
      message: execution.status === 'FAILED'
        ? 'Exécution terminée en échec.'
        : 'Exécution terminée.',
      execution,
    });
  } catch (error) {
    if (error.statusCode) {
      return res.status(error.statusCode).json({ message: error.message });
    }

    logger.error('Collection manual run failed', { error: error.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const getCollectionExecutions = async (req, res) => {
  try {
    const config = await CollectionConfig.findByPk(req.params.id);
    if (!config) return res.status(404).json({ message: 'Configuration de collecte introuvable.' });

    const limit = Math.min(100, parseInt(req.query.limit, 10) || 50);
    const rows = await CollectionExecution.findAll({
      where: { collectionConfigId: req.params.id },
      order: [['executedAt', 'DESC']],
      limit,
    });

    return res.json({
      count: rows.length,
      executions: rows.map(sanitizeExecution),
    });
  } catch (error) {
    logger.error('Collection executions fetch failed', { error: error.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

module.exports = {
  listCollectionConfigs,
  getCollectionConfig,
  createCollectionConfig,
  updateCollectionConfig,
  deleteCollectionConfig,
  runCollectionConfig,
  getCollectionExecutions,
};