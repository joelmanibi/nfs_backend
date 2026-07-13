'use strict';

const cron = require('node-cron');
const logger = require('../config/logger');

const DEFAULT_TIMEZONE = process.env.COLLECTION_SCHEDULER_TIMEZONE || 'Africa/Abidjan';
const runningConfigs = new Set();
let schedulerStarted = false;

const WEEKDAY_MAP = {
  Sun: 0,
  Mon: 1,
  Tue: 2,
  Wed: 3,
  Thu: 4,
  Fri: 5,
  Sat: 6,
};

const getZonedParts = (date = new Date(), timeZone = DEFAULT_TIMEZONE) => {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    weekday: 'short',
    hour12: false,
  });

  const raw = Object.fromEntries(
    formatter
      .formatToParts(date)
      .filter((part) => part.type !== 'literal')
      .map((part) => [part.type, part.value]),
  );

  return {
    year: Number(raw.year),
    month: Number(raw.month),
    day: Number(raw.day),
    hour: Number(raw.hour),
    minute: Number(raw.minute),
    dayOfWeek: WEEKDAY_MAP[raw.weekday],
  };
};

const buildScheduleKey = (scheduleType, zonedParts) => {
  const base = `${zonedParts.year}-${String(zonedParts.month).padStart(2, '0')}-${String(zonedParts.day).padStart(2, '0')}`;

  if (scheduleType === 'DAILY') return base;
  if (scheduleType === 'WEEKLY') return `${base}-W${zonedParts.dayOfWeek}`;
  if (scheduleType === 'MONTHLY') return `${zonedParts.year}-${String(zonedParts.month).padStart(2, '0')}-${String(zonedParts.day).padStart(2, '0')}`;
  return null;
};

const isCollectionDue = (config, now = new Date(), timeZone = DEFAULT_TIMEZONE) => {
  if (!config?.isActive) return false;
  if (!config.scheduleType || config.scheduleType === 'MANUAL') return false;
  if (!config.scheduleTime) return false;

  const [hourStr, minuteStr] = String(config.scheduleTime).split(':');
  const zonedNow = getZonedParts(now, timeZone);

  if (zonedNow.hour !== Number(hourStr) || zonedNow.minute !== Number(minuteStr)) {
    return false;
  }

  if (config.scheduleType === 'WEEKLY' && zonedNow.dayOfWeek !== Number(config.scheduleDayOfWeek)) {
    return false;
  }

  if (config.scheduleType === 'MONTHLY' && zonedNow.day !== Number(config.scheduleDayOfMonth)) {
    return false;
  }

  if (!config.lastScheduledRunAt) return true;

  const lastParts = getZonedParts(new Date(config.lastScheduledRunAt), timeZone);
  return buildScheduleKey(config.scheduleType, zonedNow) !== buildScheduleKey(config.scheduleType, lastParts);
};

const runDueCollections = async () => {
  const { CollectionConfig } = require('../src/models');
  const { executeCollectionConfig } = require('./collectionExecution');

  const configs = await CollectionConfig.findAll({
    where: {
      isActive: true,
    },
    attributes: [
      'id',
      'name',
      'scheduleType',
      'scheduleTime',
      'scheduleDayOfWeek',
      'scheduleDayOfMonth',
      'lastScheduledRunAt',
      'isActive',
    ],
  });

  for (const config of configs) {
    if (!isCollectionDue(config, new Date(), DEFAULT_TIMEZONE)) continue;
    if (runningConfigs.has(config.id)) continue;

    runningConfigs.add(config.id);

    executeCollectionConfig(config.id, { triggerType: 'SCHEDULED' })
      .catch((error) => {
        logger.error('Collection scheduled execution failed', {
          event: 'collection_schedule_failed',
          collectionConfigId: config.id,
          error: error.message,
        });
      })
      .finally(() => {
        runningConfigs.delete(config.id);
      });
  }
};

const startCollectionScheduler = () => {
  if (schedulerStarted) return;

  cron.schedule('* * * * *', () => {
    runDueCollections().catch((error) => {
      logger.error('Collection scheduler tick failed', {
        event: 'collection_scheduler_tick_failed',
        error: error.message,
      });
    });
  }, { timezone: DEFAULT_TIMEZONE });

  schedulerStarted = true;
  logger.info('Collection scheduler started', {
    event: 'collection_scheduler_started',
    timezone: DEFAULT_TIMEZONE,
  });
};

module.exports = {
  buildScheduleKey,
  getZonedParts,
  isCollectionDue,
  runDueCollections,
  startCollectionScheduler,
};