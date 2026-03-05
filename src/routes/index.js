'use strict';

const authRoutes = require('./authRoutes');
const fileRoutes = require('./fileRoutes');

/**
 * Registers all application routes.
 * @param {import('express').Application} app
 */
module.exports = (app) => {
  app.use('/api/auth',  authRoutes);
  app.use('/api/files', fileRoutes);
};

