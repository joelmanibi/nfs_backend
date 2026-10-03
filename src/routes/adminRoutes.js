'use strict';

const { Router } = require('express');
const { verifyToken }  = require('../middleware/authMiddleware');
const { checkRole }    = require('../middleware/roleMiddleware');
const {
  getStats,
  getStatsTimeseries,
  getStatsExtensions,
  getTopSenders,
  createUser,
  getUsers,
  getUserStats,
  updateUser,
  blockUser,
  deleteUser,
  restoreUser,
  getTransfers,
  getActiveTransfers,
  getAuditLogs,
  blockTransfer,
  deleteTransfer,
  getPendingUsers,
  approveUser,
  rejectUser,
} = require('../controllers/adminController');
const { getLogs, getLogsSummary, runHealthCheck } = require('../controllers/logsController');

const router = Router();

// Toutes les routes admin requièrent authentification + rôle ADMIN ou SUPER_ADMIN
router.use(verifyToken, checkRole('ADMIN', 'SUPER_ADMIN'));

// Stats
router.get('/stats', getStats);
router.get('/stats/timeseries', getStatsTimeseries);
router.get('/stats/extensions', getStatsExtensions);
router.get('/stats/top-senders', getTopSenders);

// Users — hiérarchie vérifiée dans le contrôleur : SUPER_ADMIN gère les ADMIN, ADMIN gère les USER
// (création, modification, blocage, suppression logique, restauration). Le SUPER_ADMIN peut en plus
// basculer un compte ADMIN ↔ USER.
router.post('/users',        createUser);
router.get('/users',         getUsers);
router.get('/users/:id/stats', getUserStats);
router.patch('/users/:id',   updateUser);
router.patch('/users/:id/block', blockUser);
router.delete('/users/:id',  deleteUser);
router.patch('/users/:id/restore', restoreUser);

// Transfers
router.get('/transfers',         getTransfers);
router.get('/transfers/active',  getActiveTransfers);
router.patch('/transfers/:id/block', blockTransfer);
router.delete('/transfers/:id',  checkRole('SUPER_ADMIN'), deleteTransfer);

// Audit logs
router.get('/audit', getAuditLogs);

// Journaux techniques (diagnostic des intégrations et erreurs applicatives) — SUPER_ADMIN uniquement
router.get('/logs',               checkRole('SUPER_ADMIN'), getLogs);
router.get('/logs/summary',       checkRole('SUPER_ADMIN'), getLogsSummary);
router.post('/logs/health-check', checkRole('SUPER_ADMIN'), runHealthCheck);

// Pending users — inscriptions de comptes USER : gérées par les ADMIN uniquement
router.get('/users/pending',          checkRole('ADMIN'), getPendingUsers);
router.patch('/users/:id/approve',    checkRole('ADMIN'), approveUser);
router.delete('/users/:id/reject',    checkRole('ADMIN'), rejectUser);

module.exports = router;

