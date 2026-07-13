'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');

const AUTH_COOKIE_NAME = 'NFS_token';
const AUTH_TOKEN_EXPIRES_IN = '15m';
const AUTH_TOKEN_MAX_AGE_SECONDS = 15 * 60;

const asBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null || value === '') return defaultValue;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
};

const useSecureCookies = () => {
  if (process.env.AUTH_COOKIE_SECURE !== undefined) {
    return asBoolean(process.env.AUTH_COOKIE_SECURE, false);
  }

  return process.env.NODE_ENV === 'production';
};

const serializeCookie = (name, value, { maxAge = AUTH_TOKEN_MAX_AGE_SECONDS, httpOnly = true } = {}) => {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    `Max-Age=${maxAge}`,
    'SameSite=Strict',
  ];

  if (httpOnly) parts.push('HttpOnly');
  if (useSecureCookies()) parts.push('Secure');

  return parts.join('; ');
};

const createAuthToken = (user) => jwt.sign(
  { id: user.id, email: user.email, role: user.role },
  config.jwt.secret,
  { expiresIn: AUTH_TOKEN_EXPIRES_IN },
);

const serializeAuthUser = (user) => ({
  id: user.id,
  email: user.email,
  role: user.role,
  firstName: user.firstName || null,
  lastName: user.lastName || null,
  mustChangePassword: Boolean(user.mustChangePassword),
});

const setAuthTokenCookie = (res, token) => {
  res.setHeader('Set-Cookie', serializeCookie(AUTH_COOKIE_NAME, token));
};

const clearAuthTokenCookie = (res) => {
  res.setHeader('Set-Cookie', serializeCookie(AUTH_COOKIE_NAME, '', { maxAge: 0 }));
};

const parseCookies = (cookieHeader = '') => cookieHeader
  .split(';')
  .map((part) => part.trim())
  .filter(Boolean)
  .reduce((acc, part) => {
    const separatorIndex = part.indexOf('=');
    if (separatorIndex === -1) return acc;

    const key = part.slice(0, separatorIndex).trim();
    const value = part.slice(separatorIndex + 1).trim();
    acc[key] = decodeURIComponent(value);
    return acc;
  }, {});

const extractTokenFromRequest = (req) => {
  const authHeader = req.headers?.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }

  const cookies = parseCookies(req.headers?.cookie || '');
  return cookies[AUTH_COOKIE_NAME] || null;
};

module.exports = {
  AUTH_COOKIE_NAME,
  AUTH_TOKEN_EXPIRES_IN,
  AUTH_TOKEN_MAX_AGE_SECONDS,
  createAuthToken,
  serializeAuthUser,
  setAuthTokenCookie,
  clearAuthTokenCookie,
  extractTokenFromRequest,
};