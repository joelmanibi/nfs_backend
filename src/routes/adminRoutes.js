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

// All admin routes require authentication + ADMIN role
router.use(verifyToken, checkRole('ADMIN'));

// Stats
router.get('/stats', getStats);

// Users
router.get('/users',         getUsers);
router.patch('/users/:id',   updateUser);
router.delete('/users/:id',  deleteUser);

// Transfers
router.get('/transfers',         getTransfers);
router.get('/transfers/active',  getActiveTransfers);
router.delete('/transfers/:id',  deleteTransfer);

// Audit logs
router.get('/audit', getAuditLogs);

// Pending users
router.get('/users/pending',          getPendingUsers);
router.patch('/users/:id/approve',    approveUser);
router.delete('/users/:id/reject',    rejectUser);

module.exports = router;

