'use strict';

const fs         = require('fs');
const path       = require('path');
const readline   = require('readline');
const bcrypt     = require('bcryptjs');
const { Op, fn, col } = require('sequelize');
const { User, File, ShareLink, sequelize } = require('../models');
const logger     = require('../../config/logger');
const { sendAccountApprovedEmail, sendAccountRejectedEmail, sendAccountCreatedEmail, sendAccountUnblockedEmail } = require('../../helpers/mailer');
const { generateTempPassword } = require('../../helpers/password');
const { normalizeEmail } = require('../../helpers/audit');
const { errorDetails } = require('../../helpers/errorDetails');

const BCRYPT_ROUNDS = 12;

const LOG_FILE = path.resolve('logs', 'combined.log');

// ─── Hiérarchie de gestion des comptes ───────────────────────────────────────
// Chaque rôle admin ne gère (création, modification, blocage, suppression,
// restauration) qu'un seul rôle : SUPER_ADMIN → ADMIN, ADMIN → USER.
// Seule exception : le SUPER_ADMIN peut basculer un compte ADMIN ↔ USER (updateUser).
const MANAGEABLE_ROLE = { SUPER_ADMIN: 'ADMIN', ADMIN: 'USER' };
const MANAGEABLE_ROLE_LABEL = { ADMIN: 'Administrateur', USER: 'Utilisateur' };

const canManage = (actor, target) => MANAGEABLE_ROLE[actor.role] === target.role;

const forbiddenRoleMessage = (actor) => {
  const label = MANAGEABLE_ROLE_LABEL[MANAGEABLE_ROLE[actor.role]];
  return label
    ? `Vous ne pouvez gérer que les comptes ${label}.`
    : 'Action non autorisée.';
};

// ─── Stats globales ──────────────────────────────────────────────────────────
const getStats = async (req, res) => {
  try {
    const [totalUsers, totalFiles, activeLinks, internalUsers] = await Promise.all([
      User.count(),
      File.count(),
      ShareLink.count({ where: { expiresAt: { [Op.gt]: new Date() } } }),
      User.count({ where: { isInternalUser: true } }),
    ]);

    const totalSize = await File.sum('size') || 0;
    const externalUsers = totalUsers - internalUsers;

    return res.json({ totalUsers, totalFiles, activeLinks, totalSize, internalUsers, externalUsers });
  } catch (err) {
    logger.error('Admin stats error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Série temporelle : fichiers envoyés vs reçus ────────────────────────────
const DEFAULT_RANGE_DAYS = 30;
const MAX_RANGE_DAYS     = 366;

const toDayKey = (value) => (value instanceof Date ? value.toISOString() : String(value)).slice(0, 10);

/**
 * Résout startDate/endDate depuis la query string, à la minute près
 * (bornes incluses). Retombe sur "les 30 derniers jours jusqu'à maintenant"
 * si absent/invalide, et plafonne l'écart à MAX_RANGE_DAYS pour éviter une
 * requête trop lourde. Le regroupement des séries reste journalier (voir
 * dayCount plus bas) même si les bornes elles-mêmes tombent en cours de
 * journée.
 */
const parseDateRange = (query) => {
  const now = new Date();

  let endDate = query.endDate ? new Date(query.endDate) : new Date(now);
  if (Number.isNaN(endDate.getTime())) endDate = new Date(now);
  if (endDate > now) endDate = new Date(now);

  let startDate = query.startDate ? new Date(query.startDate) : null;
  if (!startDate || Number.isNaN(startDate.getTime())) {
    startDate = new Date(endDate);
    startDate.setDate(startDate.getDate() - (DEFAULT_RANGE_DAYS - 1));
    startDate.setHours(0, 0, 0, 0);
  }

  if (startDate > endDate) {
    [startDate, endDate] = [endDate, startDate];
  }

  const earliestAllowed = new Date(endDate);
  earliestAllowed.setDate(earliestAllowed.getDate() - (MAX_RANGE_DAYS - 1));
  if (startDate < earliestAllowed) startDate = earliestAllowed;

  return { startDate, endDate };
};

/**
 * "Envoyé" = File créé ce jour-là (createdAt). "Reçu" = File téléchargé par
 * le destinataire ce jour-là (downloadedAt, déjà rempli par downloadFile).
 */
const getStatsTimeseries = async (req, res) => {
  try {
    const { startDate, endDate } = parseDateRange(req.query);

    const [sentRows, receivedRows] = await Promise.all([
      File.findAll({
        attributes: [[fn('DATE', col('createdAt')), 'day'], [fn('COUNT', col('id')), 'count']],
        where: { createdAt: { [Op.gte]: startDate, [Op.lte]: endDate } },
        group: [fn('DATE', col('createdAt'))],
        raw: true,
      }),
      File.findAll({
        attributes: [[fn('DATE', col('downloadedAt')), 'day'], [fn('COUNT', col('id')), 'count']],
        where: { downloadedAt: { [Op.gte]: startDate, [Op.lte]: endDate } },
        group: [fn('DATE', col('downloadedAt'))],
        raw: true,
      }),
    ]);

    const sentMap     = new Map(sentRows.map((r) => [toDayKey(r.day), Number(r.count)]));
    const receivedMap = new Map(receivedRows.map((r) => [toDayKey(r.day), Number(r.count)]));

    // Regroupement journalier — même si startDate/endDate tombent en cours
    // de journée, chaque jour calendaire couvert apparaît une fois.
    const startDay = new Date(startDate); startDay.setHours(0, 0, 0, 0);
    const endDay   = new Date(endDate);   endDay.setHours(0, 0, 0, 0);
    const dayCount = Math.round((endDay - startDay) / 86400000) + 1;

    const series = [];
    for (let i = 0; i < dayCount; i++) {
      const d = new Date(startDay);
      d.setDate(startDay.getDate() + i);
      const key = toDayKey(d);
      series.push({ date: key, sent: sentMap.get(key) || 0, received: receivedMap.get(key) || 0 });
    }

    return res.json({ startDate: startDate.toISOString(), endDate: endDate.toISOString(), series });
  } catch (err) {
    logger.error('Admin stats timeseries error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Répartition des extensions de fichiers (sur la même période) ───────────
const TOP_EXTENSIONS_LIMIT = 5;

const extractExtension = (filename) => {
  const match = /\.([a-z0-9]+)$/i.exec(filename || '');
  return match ? match[1].toLowerCase() : '—';
};

const getStatsExtensions = async (req, res) => {
  try {
    const { startDate, endDate } = parseDateRange(req.query);

    // Extraction de l'extension en JS (portable MySQL/Postgres) plutôt qu'en SQL.
    const rows = await File.findAll({
      attributes: ['originalName'],
      where: { createdAt: { [Op.gte]: startDate, [Op.lte]: endDate } },
      raw: true,
    });

    const counts = new Map();
    for (const { originalName } of rows) {
      const ext = extractExtension(originalName);
      counts.set(ext, (counts.get(ext) || 0) + 1);
    }

    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const top = sorted.slice(0, TOP_EXTENSIONS_LIMIT);
    const otherCount = sorted.slice(TOP_EXTENSIONS_LIMIT).reduce((sum, [, c]) => sum + c, 0);

    const extensions = top.map(([extension, count]) => ({ extension, count }));
    if (otherCount > 0) extensions.push({ extension: 'autres', count: otherCount });

    return res.json({ startDate: startDate.toISOString(), endDate: endDate.toISOString(), total: rows.length, extensions });
  } catch (err) {
    logger.error('Admin stats extensions error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Top 20 utilisateurs — les plus gros émetteurs de fichiers ──────────────
const TOP_SENDERS_LIMIT = 20;

const getTopSenders = async (req, res) => {
  try {
    const rows = await File.findAll({
      attributes: ['senderId', [fn('COUNT', col('id')), 'count']],
      group: ['senderId'],
      order: [[fn('COUNT', col('id')), 'DESC']],
      limit: TOP_SENDERS_LIMIT,
      raw: true,
    });

    const senderIds = rows.map((r) => r.senderId);
    const senders = await User.findAll({
      where: { id: { [Op.in]: senderIds } },
      attributes: ['id', 'firstName', 'lastName'],
      paranoid: false,
    });
    const senderMap = new Map(senders.map((u) => [u.id, u]));

    const topSenders = rows.map((r) => {
      const user = senderMap.get(r.senderId);
      return {
        userId: r.senderId,
        name: user ? `${user.firstName} ${user.lastName}` : 'Utilisateur supprimé',
        count: Number(r.count),
      };
    });

    return res.json({ topSenders });
  } catch (err) {
    logger.error('Admin top senders error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Gestion des utilisateurs ────────────────────────────────────────────────

/**
 * POST /admin/users — création d'un compte par un ADMIN/SUPER_ADMIN.
 * Le compte est immédiatement actif (pas de file d'attente d'approbation) :
 * l'admin qui le crée vouche pour lui. Un mot de passe temporaire est généré
 * et envoyé par email une seule fois (jamais renvoyé dans la réponse HTTP,
 * jamais persisté en clair) ; l'utilisateur devra le changer à sa première
 * connexion (mustChangePassword: true).
 */
const createUser = async (req, res) => {
  try {
    const { firstName, lastName, email, phone, organisation, country, city, role, isInternalUser } = req.body;
    const normalizedEmail = normalizeEmail(email);

    const missing = [];
    if (!firstName?.trim())    missing.push('prénom');
    if (!lastName?.trim())     missing.push('nom');
    if (!normalizedEmail)      missing.push('email');
    if (!phone?.trim())        missing.push('téléphone');
    if (!organisation?.trim()) missing.push('organisation');
    if (!country?.trim())      missing.push('pays');

    if (missing.length) {
      return res.status(400).json({ message: `Champs obligatoires manquants : ${missing.join(', ')}.` });
    }

    // Le rôle créé est imposé par la hiérarchie (SUPER_ADMIN → ADMIN, ADMIN → USER)
    const createdRole = MANAGEABLE_ROLE[req.user.role];
    if (!createdRole) {
      return res.status(403).json({ message: 'Action non autorisée.' });
    }
    if (role !== undefined && role !== createdRole) {
      return res.status(403).json({ message: `Vous ne pouvez créer que des comptes ${MANAGEABLE_ROLE_LABEL[createdRole]}.` });
    }

    const exists = await User.findOne({ where: { email: normalizedEmail }, paranoid: false });
    if (exists?.deletedAt) {
      return res.status(409).json({ message: 'Cet email appartient à un compte supprimé. Restaurez-le depuis l\'onglet « Comptes supprimés ».' });
    }
    if (exists) {
      return res.status(409).json({ message: 'Cet email est déjà enregistré.' });
    }

    const tempPassword = generateTempPassword();
    const passwordHash = await bcrypt.hash(tempPassword, BCRYPT_ROUNDS);

    const user = await User.create({
      firstName:      firstName.trim(),
      lastName:       lastName.trim(),
      email:          normalizedEmail,
      phone:          phone.trim(),
      city:           city?.trim() || null,
      organisation:   organisation.trim(),
      country:        country.trim(),
      role:           createdRole,
      isInternalUser: Boolean(isInternalUser),
      isApproved:     true,
      mustChangePassword: true,
      passwordHash,
    });

    logger.info('Admin created user', {
      event: 'admin_user_created',
      adminId: req.user.id,
      targetId: user.id,
      targetEmail: user.email,
      role: user.role,
    });

    try {
      await sendAccountCreatedEmail({
        to: user.email,
        firstName: user.firstName,
        email: user.email,
        password: tempPassword,
        createdByFirstName: req.user.firstName,
      });
    } catch (mailErr) {
      logger.error('Account created email failed', {
        event: 'admin_user_created_email_failed',
        targetId: user.id,
        ...errorDetails(mailErr),
      });
    }

    return res.status(201).json({
      message: 'Utilisateur créé. Un email avec son mot de passe lui a été envoyé.',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isInternalUser: user.isInternalUser,
      },
    });
  } catch (err) {
    logger.error('Admin createUser error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.', error: err.message });
  }
};

const getUsers = async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.min(100, parseInt(req.query.limit, 10) || 20);
    const search     = req.query.search?.trim() || '';
    const isInternal = req.query.isInternal; // 'true' | 'false' | undefined
    const role       = req.query.role?.trim(); // 'USER' | 'ADMIN' | 'SUPER_ADMIN' | undefined
    const deleted    = req.query.deleted === 'true'; // true → uniquement les comptes supprimés
    const blocked    = req.query.blocked; // 'true' (bloqués / inactifs) | 'false' (actifs) | undefined

    const where = {};
    if (deleted) where.deletedAt = { [Op.ne]: null };
    if (blocked === 'true')  where.isBlocked = true;
    if (blocked === 'false') where.isBlocked = false;

    if (search) {
      where[Op.or] = [
        { email:     { [Op.like]: `%${search}%` } },
        { firstName: { [Op.like]: `%${search}%` } },
        { lastName:  { [Op.like]: `%${search}%` } },
      ];
    }

    if (isInternal === 'true')  where.isInternalUser = true;
    if (isInternal === 'false') where.isInternalUser = false;

    if (role && ['USER', 'ADMIN', 'SUPER_ADMIN'].includes(role)) {
      where.role = role;
    }

    const { count, rows } = await User.findAndCountAll({
      where,
      attributes: ['id', 'firstName', 'lastName', 'email', 'role', 'city', 'phone', 'organisation', 'isInternalUser', 'isBlocked', 'createdAt', 'deletedAt', 'deletedById'],
      order: deleted ? [['deletedAt', 'DESC']] : [['createdAt', 'DESC']],
      limit,
      offset: (page - 1) * limit,
      paranoid: !deleted,
    });

    // Auteur de la suppression (lui-même éventuellement supprimé depuis)
    const deleterIds = [...new Set(rows.map((u) => u.deletedById).filter(Boolean))];
    const deleters = deleterIds.length
      ? await User.findAll({ where: { id: { [Op.in]: deleterIds } }, attributes: ['id', 'firstName', 'lastName'], paranoid: false })
      : [];
    const deleterMap = new Map(deleters.map((d) => [d.id, `${d.firstName} ${d.lastName}`]));

    const users = rows.map((u) => {
      const obj = u.toJSON();
      obj.isInternalUser = Boolean(obj.isInternalUser);
      obj.isBlocked = Boolean(obj.isBlocked);
      if (obj.deletedById) obj.deletedByName = deleterMap.get(obj.deletedById) || null;
      return obj;
    });

    return res.json({ count, page, pages: Math.ceil(count / limit), users });
  } catch (err) {
    logger.error('Admin getUsers error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { role, isInternalUser } = req.body;

    const user = await User.findByPk(id, { attributes: ['id', 'email', 'role', 'isInternalUser'] });
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    if (user.id === req.user.id) {
      return res.status(400).json({ message: 'Vous ne pouvez pas modifier votre propre compte.' });
    }

    // Changement de rôle : SUPER_ADMIN uniquement, et seulement ADMIN ↔ USER
    if (role !== undefined) {
      if (req.user.role !== 'SUPER_ADMIN') {
        return res.status(403).json({ message: 'Seul un Super Administrateur peut modifier un rôle.' });
      }
      if (!['ADMIN', 'USER'].includes(role) || !['ADMIN', 'USER'].includes(user.role)) {
        return res.status(403).json({ message: 'Seule la bascule Administrateur ↔ Utilisateur est autorisée.' });
      }
    }

    // Autres modifications : uniquement sur le rôle géré par l'acteur
    if (isInternalUser !== undefined && !canManage(req.user, user)) {
      return res.status(403).json({ message: forbiddenRoleMessage(req.user) });
    }

    const changes = {};
    if (role !== undefined)             changes.role           = role;
    if (isInternalUser !== undefined)   changes.isInternalUser = Boolean(isInternalUser);

    await user.update(changes);
    logger.info('Admin updated user', { adminId: req.user.id, targetId: id, changes });
    return res.json({ message: 'Utilisateur mis à jour.', user: { id: user.id, email: user.email, ...changes } });
  } catch (err) {
    logger.error('Admin updateUser error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Bloquer / débloquer un compte ────────────────────────────────────────
/**
 * PATCH /admin/users/:id/block — ouvert à ADMIN et SUPER_ADMIN.
 * Un compte bloqué ne peut plus se connecter (vérifié dans authController.js
 * et ldapController.js), mais une session déjà active (JWT) reste valable
 * jusqu'à son expiration — même comportement que isApproved.
 */
const blockUser = async (req, res) => {
  try {
    const { id } = req.params;

    if (id === req.user.id) {
      return res.status(400).json({ message: 'Vous ne pouvez pas bloquer votre propre compte.' });
    }

    const user = await User.findByPk(id, { attributes: ['id', 'email', 'firstName', 'role', 'isBlocked'] });
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    if (!canManage(req.user, user)) {
      return res.status(403).json({ message: forbiddenRoleMessage(req.user) });
    }

    user.isBlocked = !user.isBlocked;
    await user.save();

    logger.info(user.isBlocked ? 'Admin blocked user' : 'Admin unblocked user', {
      event: user.isBlocked ? 'admin_user_blocked' : 'admin_user_unblocked',
      adminId: req.user.id,
      targetId: id,
      targetEmail: user.email,
    });

    // Notifier l'utilisateur à chaque déblocage (best-effort)
    if (!user.isBlocked) {
      try {
        await sendAccountUnblockedEmail({ firstName: user.firstName, email: user.email });
      } catch (mailErr) {
        logger.warn('Account unblocked email failed', { ...errorDetails(mailErr) });
      }
    }

    return res.json({ isBlocked: user.isBlocked });
  } catch (err) {
    logger.error('Admin blockUser error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Supprimer / restaurer un compte ──────────────────────────────────────
/**
 * DELETE /admin/users/:id — ouvert à ADMIN et SUPER_ADMIN.
 * Suppression logique (modèle paranoid) : la ligne est conservée avec
 * deletedAt (date de suppression) et deletedById (auteur), le compte
 * disparaît des listes et ne peut plus se connecter. Ses fichiers et
 * l'historique restent intacts. Réversible via PATCH /admin/users/:id/restore.
 */
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    if (id === req.user.id) {
      return res.status(400).json({ message: 'Vous ne pouvez pas supprimer votre propre compte.' });
    }

    const user = await User.findByPk(id);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    if (!canManage(req.user, user)) {
      return res.status(403).json({ message: forbiddenRoleMessage(req.user) });
    }

    await sequelize.transaction(async (transaction) => {
      await user.update({ deletedById: req.user.id }, { transaction });
      await user.destroy({ transaction });
    });

    logger.info('Admin deleted user', {
      event: 'admin_user_deleted',
      adminId: req.user.id,
      targetId: id,
      targetEmail: user.email,
      deletedAt: user.deletedAt,
    });
    return res.json({ message: 'Utilisateur supprimé.', deletedAt: user.deletedAt });
  } catch (err) {
    logger.error('Admin deleteUser error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

/**
 * PATCH /admin/users/:id/restore — ouvert à ADMIN et SUPER_ADMIN.
 * Réactive un compte supprimé logiquement. L'état isBlocked est conservé
 * tel qu'il était au moment de la suppression.
 */
const restoreUser = async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findByPk(id, { paranoid: false });
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    if (!user.deletedAt) return res.status(400).json({ message: 'Ce compte n\'est pas supprimé.' });

    if (!canManage(req.user, user)) {
      return res.status(403).json({ message: forbiddenRoleMessage(req.user) });
    }

    const deletedAt = user.deletedAt;
    await sequelize.transaction(async (transaction) => {
      await user.restore({ transaction });
      await user.update({ deletedById: null }, { transaction });
    });

    logger.info('Admin restored user', {
      event: 'admin_user_restored',
      adminId: req.user.id,
      targetId: id,
      targetEmail: user.email,
      deletedAt,
    });
    return res.json({ message: 'Utilisateur restauré.' });
  } catch (err) {
    logger.error('Admin restoreUser error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Stats d'un utilisateur sur une période (pour le rapport PDF) ────────────
/**
 * GET /admin/users/:id/stats?startDate=&endDate=
 * "Envoyé"/"reçu" et découpage par extension suivent les mêmes définitions
 * que les stats globales (voir getStatsTimeseries/getStatsExtensions) :
 * envoyé = File créé (createdAt), reçu = File téléchargé (downloadedAt).
 * "Taux d'utilisation" = part de l'activité de cet utilisateur (envois +
 * réceptions) dans l'activité totale de la plateforme sur la même période.
 */
const getUserStats = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByPk(id, {
      attributes: ['id', 'firstName', 'lastName', 'email', 'role', 'isInternalUser', 'organisation'],
      paranoid: false,
    });
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });

    const { startDate, endDate } = parseDateRange(req.query);
    const period = { [Op.gte]: startDate, [Op.lte]: endDate };

    const [filesSent, filesReceived, volumeSent, totalSent, totalReceived, sentRows] = await Promise.all([
      File.count({ where: { senderId: id, createdAt: period } }),
      File.count({ where: { receiverEmail: user.email, downloadedAt: period } }),
      File.sum('size', { where: { senderId: id, createdAt: period } }),
      File.count({ where: { createdAt: period } }),
      File.count({ where: { downloadedAt: period } }),
      File.findAll({ attributes: ['originalName'], where: { senderId: id, createdAt: period }, raw: true }),
    ]);

    const counts = new Map();
    for (const { originalName } of sentRows) {
      const ext = extractExtension(originalName);
      counts.set(ext, (counts.get(ext) || 0) + 1);
    }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const top = sorted.slice(0, TOP_EXTENSIONS_LIMIT);
    const otherCount = sorted.slice(TOP_EXTENSIONS_LIMIT).reduce((sum, [, c]) => sum + c, 0);
    const extensions = top.map(([extension, count]) => ({ extension, count }));
    if (otherCount > 0) extensions.push({ extension: 'autres', count: otherCount });

    const userActivity  = filesSent + filesReceived;
    const totalActivity = totalSent + totalReceived;
    const usageRatePercent = totalActivity > 0 ? Math.round((userActivity / totalActivity) * 1000) / 10 : 0;

    return res.json({
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        isInternalUser: user.isInternalUser,
        organisation: user.organisation,
      },
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      filesSent,
      filesReceived,
      volumeSent: volumeSent || 0,
      usageRatePercent,
      extensions,
    });
  } catch (err) {
    logger.error('Admin getUserStats error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Gestion des transferts ──────────────────────────────────────────────────
const getTransfers = async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.min(100, parseInt(req.query.limit, 10) || 20);

    const reference     = req.query.reference?.trim();
    const originalName  = req.query.originalName?.trim();
    const receiverEmail = req.query.receiverEmail?.trim();
    const senderEmail   = req.query.senderEmail?.trim();

    const where = {};
    if (reference)     where.reference     = { [Op.like]: `%${reference}%` };
    if (originalName)  where.originalName  = { [Op.like]: `%${originalName}%` };
    if (receiverEmail) where.receiverEmail = { [Op.like]: `%${receiverEmail}%` };

    const senderInclude = { model: User, as: 'sender', attributes: ['id', 'email', 'firstName', 'lastName'], paranoid: false };
    if (senderEmail) senderInclude.where = { email: { [Op.like]: `%${senderEmail}%` } };

    const { count, rows } = await File.findAndCountAll({
      where,
      attributes: { exclude: ['encryptedPath', 'downloadCodeHash', 'iv'] },
      include: [senderInclude],
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
    logger.error('Admin getTransfers error', { ...errorDetails(err) });
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
        include: [{ model: User, as: 'sender', attributes: ['id', 'email', 'firstName', 'lastName'], paranoid: false }],
      }],
      order: [['createdAt', 'DESC']],
    });

    return res.json({ count: links.length, activeLinks: links });
  } catch (err) {
    logger.error('Admin getActiveTransfers error', { ...errorDetails(err) });
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
    logger.error('Admin getAuditLogs error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

// ─── Bloquer / débloquer un transfert ────────────────────────────────────────
/**
 * PATCH /admin/transfers/:id/block — ouvert à ADMIN et SUPER_ADMIN.
 * Bascule le blocage administrateur : le fichier reste visible mais ne peut
 * plus être téléchargé (destinataire comme lien de partage), et l'expéditeur
 * ne peut ni lever ce blocage ni créer de nouveau lien.
 */
const blockTransfer = async (req, res) => {
  try {
    const { id } = req.params;
    const file = await File.findByPk(id, { attributes: ['id', 'originalName', 'reference', 'adminBlockedAt', 'adminBlockedById'] });
    if (!file) return res.status(404).json({ message: 'Transfert introuvable.' });

    const blocking = !file.adminBlockedAt;
    await file.update({
      adminBlockedAt:   blocking ? new Date() : null,
      adminBlockedById: blocking ? req.user.id : null,
    });

    logger.info(blocking ? 'Admin blocked transfer' : 'Admin unblocked transfer', {
      event: blocking ? 'admin_file_blocked' : 'admin_file_unblocked',
      adminId: req.user.id,
      fileId: id,
      reference: file.reference,
    });

    return res.json({ adminBlockedAt: file.adminBlockedAt });
  } catch (err) {
    logger.error('Admin blockTransfer error', { ...errorDetails(err) });
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
    logger.error('Admin deleteTransfer error', { ...errorDetails(err) });
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
    logger.error('Admin getPendingUsers error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const approveUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByPk(id);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    if (user.isApproved) return res.status(400).json({ message: 'Ce compte est déjà approuvé.' });
    if (!canManage(req.user, user)) return res.status(403).json({ message: forbiddenRoleMessage(req.user) });

    await user.update({ isApproved: true });
    logger.info('Admin approved user', { adminId: req.user.id, targetId: id, targetEmail: user.email });

    // Notifier l'utilisateur (best-effort)
    try {
      await sendAccountApprovedEmail({ firstName: user.firstName, email: user.email });
    } catch (mailErr) {
      logger.warn('Account approved email failed', { ...errorDetails(mailErr) });
    }

    return res.json({ message: 'Compte approuvé.', user: { id: user.id, email: user.email } });
  } catch (err) {
    logger.error('Admin approveUser error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

const rejectUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByPk(id);
    if (!user) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    // Le rejet (suppression définitive) ne concerne que les inscriptions en attente
    if (user.isApproved) return res.status(400).json({ message: 'Ce compte n\'est pas en attente de validation.' });
    if (!canManage(req.user, user)) return res.status(403).json({ message: forbiddenRoleMessage(req.user) });

    // Notifier l'utilisateur avant suppression (best-effort)
    try {
      await sendAccountRejectedEmail({ firstName: user.firstName, email: user.email });
    } catch (mailErr) {
      logger.warn('Account rejected email failed', { ...errorDetails(mailErr) });
    }

    // Inscription jamais validée : suppression définitive (pas de restauration)
    await user.destroy({ force: true });
    logger.info('Admin rejected and deleted user', { adminId: req.user.id, targetId: id, targetEmail: user.email });
    return res.json({ message: 'Compte rejeté et supprimé.' });
  } catch (err) {
    logger.error('Admin rejectUser error', { ...errorDetails(err) });
    return res.status(500).json({ message: 'Erreur interne.' });
  }
};

module.exports = { getStats, getStatsTimeseries, getStatsExtensions, getTopSenders, createUser, getUsers, getUserStats, updateUser, blockUser, deleteUser, restoreUser, getTransfers, getActiveTransfers, getAuditLogs, blockTransfer, deleteTransfer, getPendingUsers, approveUser, rejectUser };

