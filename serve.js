'use strict';

const cron                  = require('node-cron');
const { loadVaultSecrets }  = require('./config/vault');
const { runMigrations }     = require('./helpers/runMigrations');
const { startCollectionScheduler } = require('./helpers/collectionScheduler');
const { runStartupChecks }  = require('./helpers/startupChecks');
const { runPurge }          = require('./helpers/purge');
const { getQueueConfig, ensureConsumerGroup, startScanWorker } = require('./helpers/scanQueue');
const { processScanJob }    = require('./helpers/uploadProcessing');
const { runQuarantineCleanup } = require('./helpers/quarantineCleanup');
const logger                = require('./config/logger');

function createApp() {
  const express = require('express');
  const cors = require('cors');
  const bodyParser = require('body-parser');

  const app = express();

  // Nginx agit comme reverse proxy — on lui fait confiance pour X-Forwarded-For
  // Nécessaire pour que express-rate-limit identifie correctement l'IP réelle du client
  app.set('trust proxy', 1);

  const corsOptions = {
    origin: '*',
  };

  app.use(cors(corsOptions));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use('/static', express.static('assets'));

  require('./src/routes')(app);

  return app;
}

async function startServer() {
  await loadVaultSecrets();
  await runMigrations();

  // ── Vérifications de connectivité au démarrage ────────────────────────────
  // Tests LDAPS + SMTP exécutés en parallèle — jamais bloquants
  await runStartupChecks();

  // ── Worker de scan antivirus (queue Redis) — désactivé en dev par défaut ──
  // Non bloquant : si Redis est injoignable, le serveur démarre quand même
  // (cohérent avec les checks LDAP/SMTP ci-dessus) ; les uploads échoueront
  // proprement (503) tant que Redis n'est pas revenu.
  const queueConfig = getQueueConfig();
  if (queueConfig.enabled) {
    try {
      await ensureConsumerGroup();
      startScanWorker(processScanJob);
      logger.info('[startup] Worker de scan antivirus démarré', { event: 'scan_worker_started' });
    } catch (error) {
      logger.error('[startup] Échec de démarrage du worker de scan antivirus', {
        event: 'scan_worker_startup_failed',
        error: error.message,
      });
    }
  }

  const app = createApp();
  const port = process.env.PORT || 8000;

  return new Promise((resolve, reject) => {
    const server = app.listen(port, '0.0.0.0', () => {
      logger.info(`[startup] Serveur démarré sur le port ${port}`, {
        event: 'server_started',
        port,
      });

      // ── Purge automatique — tous les jours à 02h00 ────────────────────────
      // Expression cron : seconde minute heure jour mois joursemaine
      const purgeSchedule = process.env.PURGE_CRON || '0 2 * * *';
      cron.schedule(purgeSchedule, () => {
        logger.info('[purge] Déclenchement planifié', { event: 'purge_scheduled_trigger' });
        runPurge().catch((err) =>
          logger.error('[purge] Erreur non capturée', { event: 'purge_unhandled_error', error: err.message })
        );
      }, { timezone: 'Africa/Abidjan' });

      logger.info(`[startup] Purge automatique planifiée (${purgeSchedule}) — rétention ${process.env.PURGE_RETENTION_DAYS || 15}j`, {
        event: 'purge_scheduled',
      });

      // ── Nettoyage quarantaine — filet de sécurité (toutes les 15 min par défaut) ──
      const quarantineCleanupSchedule = process.env.QUARANTINE_CLEANUP_CRON || '*/15 * * * *';
      cron.schedule(quarantineCleanupSchedule, () => {
        runQuarantineCleanup().catch((err) =>
          logger.error('[quarantine] Erreur non capturée', { event: 'quarantine_cleanup_unhandled_error', error: err.message })
        );
      }, { timezone: 'Africa/Abidjan' });

      logger.info(`[startup] Nettoyage quarantaine planifié (${quarantineCleanupSchedule})`, {
        event: 'quarantine_cleanup_scheduled',
      });

      startCollectionScheduler();

      resolve({ app, server });
    });

    server.on('error', reject);
  });
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error(`[startup] ${error.message}`);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  });
}

module.exports = {
  createApp,
  startServer,
};