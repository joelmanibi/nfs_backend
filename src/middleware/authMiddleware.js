'use strict';

const jwt    = require('jsonwebtoken');
const config = require('../../config');
const logger = require('../../config/logger');
const { buildRequestAuditMeta } = require('../../helpers/audit');

/**
 * Vérifie le JWT dans le header Authorization: Bearer <token>
 * Attache req.user = { id, email, role } si valide.
 */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn('Authentication token missing or malformed', {
      event: 'auth_token_missing',
      ...buildRequestAuditMeta(req),
    });

    return res.status(401).json({ message: 'Token manquant ou mal formaté.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    req.user = jwt.verify(token, config.jwt.secret);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      logger.warn('Authentication token expired', {
        event: 'auth_token_expired',
        ...buildRequestAuditMeta(req),
      });

      return res.status(401).json({ message: 'Token expiré.' });
    }

    logger.warn('Authentication token invalid', {
      event: 'auth_token_invalid',
      error: err.message,
      ...buildRequestAuditMeta(req),
    });

    return res.status(401).json({ message: 'Token invalide.' });
  }
};

module.exports = { verifyToken };

