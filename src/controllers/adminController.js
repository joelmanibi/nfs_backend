'use strict';

const fs         = require('fs');
const path       = require('path');
const readline   = require('readline');
const { Op }     = require('sequelize');
const { User, File, ShareLink, sequelize } = require('../models');
const logger     = require('../../config/logger');
const { sendAccountApprovedEmail, sendAccountRejectedEmail } = require('../../helpers/mailer');

const LOG_FILE = path.resolve('logs', 'combined.log');

// ─── Stats globales ──────────────────────────────────────────────────────────
const getStats = async (req, res) => {
  try {
    const [totalUsers, totalFiles, activeLinks] = await Promise.all([
      User.count(),
      File.count(),
      ShareLink.count({ where: { expiresAt: { [Op.gt]: new Date() } } }),
    ]);

    const totalSize = await File.sum('size') || 0;

    return res.json({ totalUsers, totalFiles, activeLinks, totalSize });
  } catch (err) {
    logger.error('Admin stats error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Gestion des utilisateurs ────────────────────────────────────────────────
const getUsers = async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.min(100, parseInt(req.query.limit, 10) || 20);
    const search     = req.query.search?.trim() || '';
    const isInternal = req.query.isInternal; // 'true' | 'false' | undefined

    const where = {};

    if (search) {
      where[Op.or] = [
        { email:     { [Op.like]: `%${search}%` } },
        { firstName: { [Op.like]: `%${search}%` } },
        { lastName:  { [Op.like]: `%${search}%` } },
      ];
    }

    if (isInternal === 'true')  where.isInternalUser = true;
    if (isInternal === 'false') where.isInternalUser = false;

    const { count, rows } = await User.findAndCountAll({
      where,
      attributes: ['id', 'firstName', 'lastName', 'email', 'role', 'city', 'phone', 'organisation', 'isInternalUser', 'createdAt'],
      order: [['createdAt', 'DESC']],
      limit,
      offset: (page - 1) * limit,
    });

    const users = rows.map((u) => {
      const obj = u.toJSON();
      obj.isInternalUser = Boolean(obj.isInternalUser);
      return obj;
    });

    return res.json({ count, page, pages: Math.ceil(count / limit), users });
  } catch (err) {
    logger.error('Admin getUsers error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { role, isInternalUser } = req.body;

    // Seul SUPER_ADMIN peut attribuer le rôle SUPER_ADMIN
    if (role === 'SUPER_ADMIN' && req.user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ message: 'Seul un Super Administrateur peut attribuer ce rôle.' });
    }

    // Valider les champs fournis
    if (role !== undefined && !['SUPER_ADMIN', 'ADMIN', 'USER'].includes(role)) {
      return res.status(400).json({ message: 'Rôle invalide. Valeurs: SUPER_ADMIN, ADMIN, USER.' });
    }

    const user = await User.findByPk(id, { attributes: ['id', 'email', 'role', 'isInternalUser'] });
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    if (role !== undefined && user.id === req.user.id) {
      return res.status(400).json({ message: 'Vous ne pouvez pas modifier votre propre rôle.' });
    }

    const changes = {};
    if (role !== undefined)             changes.role           = role;
    if (isInternalUser !== undefined)   changes.isInternalUser = Boolean(isInternalUser);

    await user.update(changes);
    logger.info('Admin updated user', { adminId: req.user.id, targetId: id, changes });
    return res.json({ message: 'Utilisateur mis à jour.', user: { id: user.id, email: user.email, ...changes } });
  } catch (err) {
    logger.error('Admin updateUser error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    if (id === req.user.id) {
      return res.status(400).json({ message: 'Vous ne pouvez pas supprimer votre propre compte.' });
    }

    const user = await User.findByPk(id);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    await user.destroy();
    logger.info('Admin deleted user', { adminId: req.user.id, targetId: id, targetEmail: user.email });
    return res.json({ message: 'Utilisateur supprimé.' });
  } catch (err) {
    logger.error('Admin deleteUser error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Gestion des transferts ──────────────────────────────────────────────────
const getTransfers = async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.min(100, parseInt(req.query.limit, 10) || 20);
    const search = req.query.search?.trim() || '';

    const where = search
      ? {
          [Op.or]: [
            { originalName:  { [Op.like]: `%${search}%` } },
            { receiverEmail: { [Op.like]: `%${search}%` } },
          ],
        }
      : {};

    const { count, rows } = await File.findAndCountAll({
      where,
      attributes: { exclude: ['encryptedPath', 'downloadCodeHash', 'iv'] },
      include: [{ model: User, as: 'sender', attributes: ['id', 'email', 'firstName', 'lastName'] }],
      order: [['createdAt', 'DESC']],
      limit,
      offset: (page - 1) * limit,
    });

    // ADMIN (non SUPER_ADMIN) : masquer les emails des destinataires
    const transfers = rows.map((f) => {
      const obj = f.toJSON();
      if (req.user.role !== 'SUPER_ADMIN') {
        if (obj.receiverEmail) obj.receiverEmail = '***@***';
        if (obj.sender?.email) obj.sender.email = '***@***';
      }
      return obj;
    });

    return res.json({ count, page, pages: Math.ceil(count / limit), transfers });
  } catch (err) {
    logger.error('Admin getTransfers error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const getActiveTransfers = async (req, res) => {
  try {
    const now = new Date();
    const links = await ShareLink.findAll({
      where: { expiresAt: { [Op.gt]: now } },
      include: [{
        model: File,
        as: 'file',
        attributes: { exclude: ['encryptedPath', 'downloadCodeHash', 'iv'] },
        include: [{ model: User, as: 'sender', attributes: ['id', 'email', 'firstName', 'lastName'] }],
      }],
      order: [['createdAt', 'DESC']],
    });

    return res.json({ count: links.length, activeLinks: links });
  } catch (err) {
    logger.error('Admin getActiveTransfers error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Sanitisation des logs pour le rôle ADMIN ────────────────────────────────
const EVENT_ACTION_MAP = [
  ['file_upload',    'UPLOAD'],
  ['file_download',  'TÉLÉCHARGEMENT'],
  ['share_link',     'PARTAGE'],
  ['auth_otp',       'CONNEXION'],
  ['auth_password',  'CONNEXION'],
  ['auth_ldap',      'CONNEXION'],
  ['auth_register',  'INSCRIPTION'],
  ['auth_forgot',    'RESET MDP'],
  ['auth_reset',     'RESET MDP'],
  ['auth_change',    'CHANGEMENT MDP'],
  ['admin_',         'ADMIN'],
];

const formatBytes = (bytes) => {
  if (!bytes) return null;
  const n = parseInt(bytes, 10);
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(1)} Go`;
  if (n >= 1048576)    return `${(n / 1048576).toFixed(1)} Mo`;
  if (n >= 1024)       return `${(n / 1024).toFixed(1)} Ko`;
  return `${n} o`;
};

const sanitizeLogEntry = (entry) => {
  // Heure seulement (pas de date, pas d'IP)
  const time = entry.timestamp
    ? new Date(entry.timestamp).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—';

  // Acteur : email → prénom.nom ou partie avant @ sans domaine
  const rawEmail = entry.targetEmail || entry.email || '';
  const actor = rawEmail
    ? rawEmail.split('@')[0].toLowerCase().replace(/[^a-z0-9._-]/g, '')
    : 'système';

  // Action déduite du champ event
  let action = 'ACTION';
  for (const [key, label] of EVENT_ACTION_MAP) {
    if (entry.event?.startsWith(key)) { action = label; break; }
  }

  // Statut
  const status = entry.level === 'error' ? 'KO' : 'OK';

  // Taille (si disponible dans le log)
  const size = entry.size ? formatBytes(entry.size) : null;

  return { time, actor, action, status, size, level: entry.level };
};

// ─── Audit logs ──────────────────────────────────────────────────────────────
const getAuditLogs = async (req, res) => {
  try {
    const limit = Math.min(500, parseInt(req.query.limit, 10) || 100);
    const filter = req.query.filter?.trim() || '';

    if (!fs.existsSync(LOG_FILE)) {
      return res.json({ count: 0, logs: [] });
    }

    const lines = [];
    const rl = readline.createInterface({ input: fs.createReadStream(LOG_FILE), crlfDelay: Infinity });

    for await (const line of rl) {
      try {
        const entry = JSON.parse(line);
        if (!filter || JSON.stringify(entry).toLowerCase().includes(filter.toLowerCase())) {
          lines.push(entry);
        }
      } catch {
        // ignore malformed lines
      }
    }

    const logs = lines.slice(-limit).reverse();

    // ADMIN (non SUPER_ADMIN) : retourner uniquement les champs autorisés
    const sanitized = req.user.role !== 'SUPER_ADMIN'
      ? logs.map(sanitizeLogEntry)
      : logs;

    return res.json({ count: sanitized.length, logs: sanitized, restricted: req.user.role !== 'SUPER_ADMIN' });
  } catch (err) {
    logger.error('Admin getAuditLogs error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Delete transfer ─────────────────────────────────────────────────────────
const deleteTransfer = async (req, res) => {
  try {
    const { id } = req.params;
    const file = await File.findByPk(id);
    if (!file) return res.status(404).json({ message: 'Transfert introuvable.' });
    await file.destroy();
    logger.info('Admin deleted transfer', { adminId: req.user.id, fileId: id });
    return res.json({ message: 'Transfert supprimé.' });
  } catch (err) {
    logger.error('Admin deleteTransfer error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Comptes en attente d'approbation ────────────────────────────────────────
const getPendingUsers = async (req, res) => {
  try {
    const rows = await User.findAll({
      where: { isApproved: false },
      attributes: ['id', 'firstName', 'lastName', 'email', 'phone', 'organisation', 'country', 'isInternalUser', 'createdAt'],
      order: [['createdAt', 'ASC']],
    });
    const users = rows.map((u) => {
      const obj = u.toJSON();
      obj.isInternalUser = Boolean(obj.isInternalUser);
      return obj;
    });
    return res.json({ count: users.length, users });
  } catch (err) {
    logger.error('Admin getPendingUsers error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const approveUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByPk(id);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    if (user.isApproved) return res.status(400).json({ message: 'Ce compte est déjà approuvé.' });

    await user.update({ isApproved: true });
    logger.info('Admin approved user', { adminId: req.user.id, targetId: id, targetEmail: user.email });

    // Notifier l'utilisateur (best-effort)
    try {
      await sendAccountApprovedEmail({ firstName: user.firstName, email: user.email });
    } catch (mailErr) {
      logger.warn('Account approved email failed', { error: mailErr.message });
    }

    return res.json({ message: 'Compte approuvé.', user: { id: user.id, email: user.email } });
  } catch (err) {
    logger.error('Admin approveUser error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const rejectUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByPk(id);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    // Notifier l'utilisateur avant suppression (best-effort)
    try {
      await sendAccountRejectedEmail({ firstName: user.firstName, email: user.email });
    } catch (mailErr) {
      logger.warn('Account rejected email failed', { error: mailErr.message });
    }

    await user.destroy();
    logger.info('Admin rejected and deleted user', { adminId: req.user.id, targetId: id, targetEmail: user.email });
    return res.json({ message: 'Compte rejeté et supprimé.' });
  } catch (err) {
    logger.error('Admin rejectUser error', { error: err.message });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

module.exports = { getStats, getUsers, updateUser, deleteUser, getTransfers, getActiveTransfers, getAuditLogs, deleteTransfer, getPendingUsers, approveUser, rejectUser };

