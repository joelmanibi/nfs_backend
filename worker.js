'use strict';

const { loadVaultSecrets } = require('./config/vault');
const { getQueueConfig, ensureConsumerGroup, startScanWorker } = require('./helpers/scanQueue');
const { processScanJob } = require('./helpers/uploadProcessing');
const logger = require('./config/logger');
const { errorDetails } = require('./helpers/errorDetails');
const { registerProcessErrorHandlers } = require('./helpers/processErrors');

/**
 * Processus dédié au scan antivirus + chiffrement des fichiers uploadés.
 * Tourne séparément du serveur HTTP (voir serve.js) pour ne jamais partager
 * sa boucle d'événements : le chiffrement d'un gros fichier ne doit plus
 * ralentir les requêtes API des autres utilisateurs. Communique uniquement
 * via la queue Redis Streams (helpers/scanQueue.js) — aucun couplage direct
 * avec le process API.
 */
async function startWorker() {
  await loadVaultSecrets();

  const queueConfig = getQueueConfig();
  if (!queueConfig.enabled) {
    logger.warn('[worker] ANTIVIRUS_QUEUE_ENABLED=false — rien à consommer, arrêt.', {
      event: 'scan_worker_noop_exit',
    });
    return;
  }

  await ensureConsumerGroup();
  await startScanWorker(processScanJob);

  logger.info('[worker] Worker de scan antivirus démarré', {
    event: 'scan_worker_started',
    pid: process.pid,
    maxConcurrentScans: queueConfig.maxConcurrentScans,
  });
}

if (require.main === module) {
  registerProcessErrorHandlers('worker');
  startWorker().catch((error) => {
    console.error(`[worker] ${error.message}`);
    if (error.stack) {
      console.error(error.stack);
    }
    logger.error('[worker] Échec du démarrage du worker', { event: 'worker_startup_failed', ...errorDetails(error) });
    setTimeout(() => process.exit(1), 500);
  });
}

module.exports = { startWorker };
