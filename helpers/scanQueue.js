'use strict';

const { createClient } = require('redis');
const logger = require('../config/logger');
const { applyScanOutcomeToFiles, safeUnlink } = require('./uploadProcessing');

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);

const asBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null || value === '') return defaultValue;
  return TRUE_VALUES.has(String(value).toLowerCase());
};

const asPositiveInteger = (value, defaultValue) => {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultValue;
};

/**
 * Désactivée par défaut en dev (aucune connexion Redis nécessaire pour
 * développer en local) ; activée par défaut en prod.
 */
const getQueueConfig = () => ({
  enabled:             asBoolean(process.env.ANTIVIRUS_QUEUE_ENABLED, process.env.NODE_ENV === 'production'),
  redisUrl:            process.env.REDIS_URL || 'redis://127.0.0.1:6379',
  streamKey:           process.env.SCAN_STREAM_KEY || 'nfs:scan:jobs',
  deadLetterStreamKey: process.env.SCAN_DEADLETTER_STREAM_KEY || 'nfs:scan:deadletter',
  consumerGroup:       process.env.SCAN_CONSUMER_GROUP || 'scan-workers',
  maxConcurrentScans:  asPositiveInteger(process.env.MAX_CONCURRENT_SCANS, 4),
  claimIdleMs:         asPositiveInteger(process.env.SCAN_CLAIM_IDLE_MS, 120000),
  maxRetries:          asPositiveInteger(process.env.SCAN_JOB_MAX_RETRIES, 3),
  pollBlockMs:         asPositiveInteger(process.env.SCAN_POLL_BLOCK_MS, 5000),
});

const consumerName = `worker-${process.pid}`;
let client = null;
let workerRunning = false;

const getClient = () => {
  if (!client) {
    const config = getQueueConfig();
    client = createClient({ url: config.redisUrl });
    client.on('error', (error) => {
      logger.error('Redis connection error', { event: 'scan_queue_redis_error', error: error.message });
    });
  }
  return client;
};

const ensureConnected = async () => {
  const c = getClient();
  if (!c.isOpen) {
    await c.connect();
  }
  return c;
};

/**
 * Sémaphore in-process minimal — borne le nombre de scans concurrents
 * sans dépendance supplémentaire.
 */
class Semaphore {
  constructor(max) {
    this.max = max;
    this.current = 0;
    this.queue = [];
  }

  acquire() {
    return new Promise((resolve) => {
      const tryAcquire = () => {
        if (this.current < this.max) {
          this.current += 1;
          resolve(() => this.release());
        } else {
          this.queue.push(tryAcquire);
        }
      };
      tryAcquire();
    });
  }

  release() {
    this.current -= 1;
    const next = this.queue.shift();
    if (next) next();
  }
}

const ensureConsumerGroup = async () => {
  const config = getQueueConfig();
  const c = await ensureConnected();
  try {
    await c.xGroupCreate(config.streamKey, config.consumerGroup, '$', { MKSTREAM: true });
  } catch (error) {
    if (!/BUSYGROUP/.test(error.message)) throw error;
  }
};

/**
 * Ajoute un job de scan à la queue. Payload minimal : le worker
 * re-requête les enregistrements File par fileIds pour tout le reste.
 */
const enqueueScanJob = async ({ sharedFileId, quarantinePath, iv, fileIds }) => {
  const config = getQueueConfig();
  const c = await ensureConnected();
  return c.xAdd(config.streamKey, '*', {
    payload: JSON.stringify({ sharedFileId, quarantinePath, iv, fileIds }),
  });
};

const deadLetterJob = async (job, messageId) => {
  const config = getQueueConfig();
  const c = await ensureConnected();

  logger.error('Scan job exceeded max retries — dead-lettered', {
    event: 'scan_job_dead_lettered',
    sharedFileId: job.sharedFileId,
    fileIds: job.fileIds,
    messageId,
  });

  await c.xAdd(config.deadLetterStreamKey, '*', { payload: JSON.stringify(job) });
  await c.xAck(config.streamKey, config.consumerGroup, messageId);
  await applyScanOutcomeToFiles({ fileIds: job.fileIds, encrypted: false, scanResult: { status: 'error' } });
  safeUnlink(job.quarantinePath, { reason: 'dead_letter' });
};

/**
 * Démarre le worker de scan (boucle de consommation Redis Streams avec
 * concurrence bornée) ainsi que le mécanisme de reclaim périodique des
 * jobs orphelins (worker précédent crashé). No-op si la queue est
 * désactivée (dev par défaut).
 */
const startScanWorker = async (processFn) => {
  const config = getQueueConfig();
  if (!config.enabled) return;

  await ensureConsumerGroup();
  const c = await ensureConnected();
  const semaphore = new Semaphore(config.maxConcurrentScans);
  workerRunning = true;

  const handleMessage = async (messageId, payload) => {
    const release = await semaphore.acquire();
    try {
      const job = JSON.parse(payload);
      await processFn(job);
      await c.xAck(config.streamKey, config.consumerGroup, messageId);
    } catch (error) {
      logger.error('Scan job processing failed — left pending for retry', {
        event: 'scan_job_failed',
        messageId,
        error: error.message,
      });
    } finally {
      release();
    }
  };

  const readLoop = async () => {
    while (workerRunning) {
      try {
        const response = await c.xReadGroup(
          config.consumerGroup,
          consumerName,
          [{ key: config.streamKey, id: '>' }],
          { COUNT: config.maxConcurrentScans, BLOCK: config.pollBlockMs },
        );

        if (response) {
          for (const stream of response) {
            for (const message of stream.messages) {
              // Fire-and-forget : borné par le sémaphore, pas par la boucle de lecture.
              handleMessage(message.id, message.message.payload);
            }
          }
        }
      } catch (error) {
        logger.error('Scan queue read failed', { event: 'scan_queue_read_failed', error: error.message });
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
  };

  const reclaimLoop = async () => {
    while (workerRunning) {
      await new Promise((resolve) => setTimeout(resolve, config.claimIdleMs));
      try {
        await reclaimStuckJobs(handleMessage);
      } catch (error) {
        logger.error('Scan queue reclaim failed', { event: 'scan_queue_reclaim_failed', error: error.message });
      }
    }
  };

  readLoop();
  reclaimLoop();
};

/**
 * Réclame les jobs dont le worker précédent n'a jamais acquitté le
 * message (crash). Au-delà de maxRetries livraisons, le job est
 * dead-letter plutôt que retenté indéfiniment.
 */
const reclaimStuckJobs = async (handleMessage) => {
  const config = getQueueConfig();
  const c = await ensureConnected();

  const pending = await c.xPendingRange(
    config.streamKey, config.consumerGroup, '-', '+', 100,
  );

  for (const entry of pending) {
    if (entry.deliveriesCounter > config.maxRetries) {
      const claimed = await c.xClaim(
        config.streamKey, config.consumerGroup, consumerName, 0, [entry.id],
      );
      const message = claimed[0];
      if (message) {
        const job = JSON.parse(message.message.payload);
        await deadLetterJob(job, message.id);
      }
    }
  }

  const claimed = await c.xAutoClaim(
    config.streamKey, config.consumerGroup, consumerName, config.claimIdleMs, '0',
  );

  for (const message of claimed.messages || []) {
    handleMessage(message.id, message.message.payload);
  }
};

module.exports = {
  getQueueConfig,
  ensureConsumerGroup,
  enqueueScanJob,
  startScanWorker,
};
