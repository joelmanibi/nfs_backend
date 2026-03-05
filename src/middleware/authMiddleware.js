'use strict';

const jwt    = require('jsonwebtoken');
const config = require('../../config');

/**
 * Vérifie le JWT dans le header Authorization: Bearer <token>
 * Attache req.user = { id, email, role } si valide.
 */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token manquant ou mal formaté.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    req.user = jwt.verify(token, config.jwt.secret);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expiré.' });
    }
    return res.status(401).json({ message: 'Token invalide.' });
  }
};

module.exports = { verifyToken };

