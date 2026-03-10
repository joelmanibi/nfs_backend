'use strict';

const normalizeEmail = (value) => {
  if (typeof value !== 'string') return undefined;

  const normalized = value.trim().toLowerCase();
  return normalized || undefined;
};

const getUserAgent = (req) => {
  if (typeof req?.get === 'function') {
    return req.get('user-agent');
  }

  return req?.headers?.['user-agent'];
};

const buildRequestAuditMeta = (req, extra = {}) => ({
  userId: req?.user?.id,
  userEmail: normalizeEmail(req?.user?.email),
  ip: req?.ip,
  userAgent: getUserAgent(req),
  ...extra,
});

module.exports = {
  buildRequestAuditMeta,
  normalizeEmail,
};