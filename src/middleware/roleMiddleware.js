'use strict';

/**
 * Factory middleware de contrôle de rôle.
 * Doit être utilisé APRÈS verifyToken.
 *
 * @param {...string} roles - Rôles autorisés (ex: 'ADMIN', 'USER')
 * @returns {import('express').RequestHandler}
 *
 * @example
 * router.get('/admin', verifyToken, checkRole('ADMIN'), handler);
 * router.get('/both',  verifyToken, checkRole('ADMIN', 'USER'), handler);
 */
const checkRole = (...roles) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: 'Non authentifié.' });
  }

  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Accès refusé. Permissions insuffisantes.' });
  }

  next();
};

module.exports = { checkRole };

