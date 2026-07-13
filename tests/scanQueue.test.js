'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { getQueueConfig } = require('../helpers/scanQueue');

const withEnv = (overrides, fn) => {
  const saved = {};
  for (const key of Object.keys(overrides)) {
    saved[key] = process.env[key];
    if (overrides[key] === undefined) delete process.env[key];
    else process.env[key] = overrides[key];
  }

  try {
    return fn();
  } finally {
    for (const key of Object.keys(overrides)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
};

test('getQueueConfig defaults to disabled outside production', () => {
  const config = withEnv(
    { NODE_ENV: 'development', ANTIVIRUS_QUEUE_ENABLED: undefined },
    () => getQueueConfig(),
  );

  assert.equal(config.enabled, false);
});

test('getQueueConfig defaults to enabled in production', () => {
  const config = withEnv(
    { NODE_ENV: 'production', ANTIVIRUS_QUEUE_ENABLED: undefined },
    () => getQueueConfig(),
  );

  assert.equal(config.enabled, true);
});

test('ANTIVIRUS_QUEUE_ENABLED explicitly overrides the NODE_ENV default', () => {
  const config = withEnv(
    { NODE_ENV: 'production', ANTIVIRUS_QUEUE_ENABLED: 'false' },
    () => getQueueConfig(),
  );

  assert.equal(config.enabled, false);
});

test('getQueueConfig applies documented defaults', () => {
  const config = withEnv(
    {
      REDIS_URL: undefined,
      SCAN_STREAM_KEY: undefined,
      SCAN_DEADLETTER_STREAM_KEY: undefined,
      SCAN_CONSUMER_GROUP: undefined,
      MAX_CONCURRENT_SCANS: undefined,
      SCAN_CLAIM_IDLE_MS: undefined,
      SCAN_JOB_MAX_RETRIES: undefined,
      SCAN_POLL_BLOCK_MS: undefined,
    },
    () => getQueueConfig(),
  );

  assert.equal(config.redisUrl, 'redis://127.0.0.1:6379');
  assert.equal(config.streamKey, 'nfs:scan:jobs');
  assert.equal(config.deadLetterStreamKey, 'nfs:scan:deadletter');
  assert.equal(config.consumerGroup, 'scan-workers');
  assert.equal(config.maxConcurrentScans, 4);
  assert.equal(config.claimIdleMs, 120000);
  assert.equal(config.maxRetries, 3);
  assert.equal(config.pollBlockMs, 5000);
});
