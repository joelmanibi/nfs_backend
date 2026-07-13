'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { getZonedParts, isCollectionDue } = require('../helpers/collectionScheduler');

test('getZonedParts returns stable UTC parts', () => {
  const parts = getZonedParts(new Date('2026-06-16T10:45:00Z'), 'UTC');

  assert.equal(parts.year, 2026);
  assert.equal(parts.month, 6);
  assert.equal(parts.day, 16);
  assert.equal(parts.hour, 10);
  assert.equal(parts.minute, 45);
  assert.equal(parts.dayOfWeek, 2);
});

test('daily collection is due only once per day', () => {
  const config = {
    isActive: true,
    scheduleType: 'DAILY',
    scheduleTime: '10:45',
    lastScheduledRunAt: '2026-06-15T10:45:00Z',
  };

  assert.equal(isCollectionDue(config, new Date('2026-06-16T10:45:00Z'), 'UTC'), true);
  assert.equal(isCollectionDue(config, new Date('2026-06-16T10:44:00Z'), 'UTC'), false);
});

test('weekly collection checks weekday', () => {
  const config = {
    isActive: true,
    scheduleType: 'WEEKLY',
    scheduleTime: '10:45',
    scheduleDayOfWeek: 2,
    lastScheduledRunAt: '2026-06-09T10:45:00Z',
  };

  assert.equal(isCollectionDue(config, new Date('2026-06-16T10:45:00Z'), 'UTC'), true);
  assert.equal(isCollectionDue(config, new Date('2026-06-17T10:45:00Z'), 'UTC'), false);
});