'use strict';

const { Router } = require('express');
const { verifyToken }  = require('../middleware/authMiddleware');
const { checkRole }    = require('../middleware/roleMiddleware');
const {
  getStats,
  getUsers,
  updateUser,
  deleteUser,
  getTransfers,
  getActiveTransfers,
  getAuditLogs,
  deleteTransfer,
  getPendingUsers,
  approveUser,
  rejectUser,
} = require('../controllers/adminController');

const router = Router();

// Toutes les routes admin requièrent authentification + rôle ADMIN ou SUPER_ADMIN
router.use(verifyToken, checkRole('ADMIN', 'SUPER_ADMIN'));

// Stats
router.get('/stats', getStats);

// Users — lecture ouverte aux deux rôles; écriture réservée au SUPER_ADMIN
router.get('/users',         getUsers);
router.patch('/users/:id',   checkRole('SUPER_ADMIN'), updateUser);
router.delete('/users/:id',  checkRole('SUPER_ADMIN'), deleteUser);

// Transfers
router.get('/transfers',         getTransfers);
router.get('/transfers/active',  getActiveTransfers);
router.delete('/transfers/:id',  checkRole('SUPER_ADMIN'), deleteTransfer);

// Audit logs
router.get('/audit', getAuditLogs);

// Pending users — les deux rôles peuvent approuver/rejeter
router.get('/users/pending',          getPendingUsers);
router.patch('/users/:id/approve',    approveUser);
router.delete('/users/:id/reject',    rejectUser);

module.exports = router;

