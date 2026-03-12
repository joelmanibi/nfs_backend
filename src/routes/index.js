'use strict';

const authRoutes  = require('./authRoutes');
const fileRoutes  = require('./fileRoutes');
const shareRoutes = require('./shareRoutes');
const adminRoutes = require('./adminRoutes');

/**
 * Registers all application routes.
 * @param {import('express').Application} app
 */
module.exports = (app) => {
  app.use('/api/auth',  authRoutes);
  app.use('/api/files', fileRoutes);    // inclut POST /:id/share (auth)
  app.use('/api/share', shareRoutes);   // GET /:token  +  GET /:token/download (public)
  app.use('/api/admin', adminRoutes);   // ADMIN uniquement
};