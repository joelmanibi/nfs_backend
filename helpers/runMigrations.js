'use strict';

const path = require('path');
const { spawn } = require('child_process');
const logger = require('../config/logger');

const runMigrations = async () => {
  if (process.env.AUTO_RUN_MIGRATIONS === 'false') {
    logger.info('Auto migrations skipped by configuration', {
      event: 'db_migrations_skipped',
    });
    return;
  }

  const cliPath = require.resolve('sequelize-cli/lib/sequelize');
  const args = [cliPath, 'db:migrate'];

  logger.info('Running database migrations before startup', {
    event: 'db_migrations_started',
    nodeEnv: process.env.NODE_ENV || 'development',
  });

  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: path.resolve(__dirname, '..'),
      env: process.env,
      stdio: 'inherit',
    });

    child.on('error', (error) => reject(error));
    child.on('exit', (code) => {
      if (code === 0) return resolve();
      return reject(new Error(`sequelize-cli db:migrate exited with code ${code}`));
    });
  });

  logger.info('Database migrations completed', {
    event: 'db_migrations_completed',
  });
};

module.exports = { runMigrations };