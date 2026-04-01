'use strict';

const { Router }      = require('express');
const { verifyToken } = require('../middleware/authMiddleware');
const { searchUsers } = require('../controllers/userController');

const router = Router();

// GET /api/users/search?q=...  — authentification requise
router.get('/search', verifyToken, searchUsers);

module.exports = router;

