'use strict';

const logger = require('../config/logger');
const { errorDetails } = require('./errorDetails');

/**
 * Journalise les erreurs qui échappent à tout try/catch (promesse rejetée sans
 * .catch, exception levée dans un callback) : sans ce filet, elles
 * n'apparaissaient que sur la console du process et jamais dans les journaux
 * consultables depuis la console SUPER_ADMIN.
 *
 * - unhandledRejection : journalisée, le process continue.
 * - uncaughtException  : journalisée puis arrêt du process (état incertain) —
 *   le gestionnaire de process (pm2/systemd) se charge du redémarrage.
 */
const registerProcessErrorHandlers = (processName) => {
  process.on('unhandledRejection', (reason) => {
    logger.error(`[${processName}] Promesse rejetée non gérée`, {
      event: 'process_unhandled_rejection',
      processName,
      pid: process.pid,
      ...errorDetails(reason),
    });
  });

  process.on('uncaughtException', (err) => {
    logger.error(`[${processName}] Exception non capturée — arrêt du process`, {
      event: 'process_uncaught_exception',
      processName,
      pid: process.pid,
      ...errorDetails(err),
    });
    // Laisse le temps aux transports winston d'écrire sur disque
    setTimeout(() => process.exit(1), 500).unref();
  });
};

module.exports = { registerProcessErrorHandlers };
