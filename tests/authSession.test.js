'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  AUTH_COOKIE_NAME,
  serializeAuthUser,
  createAuthToken,
  clearAuthTokenCookie,
  extractTokenFromRequest,
  setAuthTokenCookie,
} = require('../helpers/authSession');
const { verifyToken } = require('../src/middleware/authMiddleware');
const { User } = require('../src/models');
const { getMe } = require('../src/controllers/authController');

const createResponse = () => ({
  statusCode: null,
  payload: null,
  headers: {},
  setHeader(name, value) {
    this.headers[name] = value;
  },
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(body) {
    this.payload = body;
    return this;
  },
});

test('setAuthTokenCookie emits a HttpOnly session cookie', () => {
  const res = createResponse();

  setAuthTokenCookie(res, 'sample-token');

  assert.match(res.headers['Set-Cookie'], new RegExp(`^${AUTH_COOKIE_NAME}=`));
  assert.match(res.headers['Set-Cookie'], /HttpOnly/);
  assert.match(res.headers['Set-Cookie'], /SameSite=Strict/);
  assert.match(res.headers['Set-Cookie'], /Max-Age=900/);
});

test('clearAuthTokenCookie expires the session cookie', () => {
  const res = createResponse();

  clearAuthTokenCookie(res);

  assert.match(res.headers['Set-Cookie'], /Max-Age=0/);
});

test('extractTokenFromRequest reads bearer token first then cookie token', () => {
  const token = createAuthToken({ id: 'u1', email: 'user@example.com', role: 'USER' });

  assert.equal(
    extractTokenFromRequest({ headers: { authorization: `Bearer ${token}` } }),
    token,
  );
  assert.equal(
    extractTokenFromRequest({ headers: { cookie: `${AUTH_COOKIE_NAME}=${encodeURIComponent(token)}` } }),
    token,
  );
});

test('verifyToken accepts JWT from HttpOnly cookie fallback', () => {
  const token = createAuthToken({ id: 'u1', email: 'user@example.com', role: 'ADMIN' });
  const req = { headers: { cookie: `${AUTH_COOKIE_NAME}=${encodeURIComponent(token)}` } };
  const res = createResponse();
  let nextCalled = false;

  verifyToken(req, res, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(req.user.email, 'user@example.com');
  assert.equal(req.user.role, 'ADMIN');
});

test('serializeAuthUser returns the minimal session profile', () => {
  assert.deepEqual(
    serializeAuthUser({
      id: 'u1',
      email: 'user@example.com',
      role: 'ADMIN',
      firstName: 'Jane',
      lastName: 'Doe',
      passwordHash: 'hidden',
    }),
    {
      id: 'u1',
      email: 'user@example.com',
      role: 'ADMIN',
      firstName: 'Jane',
      lastName: 'Doe',
    },
  );
});

test('getMe returns the current authenticated user profile', async (t) => {
  const originalFindByPk = User.findByPk;
  t.after(() => {
    User.findByPk = originalFindByPk;
  });

  User.findByPk = async (id) => {
    assert.equal(id, 'u1');
    return {
      id: 'u1',
      email: 'user@example.com',
      role: 'SUPER_ADMIN',
      firstName: 'Jane',
      lastName: 'Doe',
      isApproved: true,
    };
  };

  const req = { user: { id: 'u1' }, headers: {} };
  const res = createResponse();

  await getMe(req, res);

  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.payload, {
    user: {
      id: 'u1',
      email: 'user@example.com',
      role: 'SUPER_ADMIN',
      firstName: 'Jane',
      lastName: 'Doe',
    },
  });
});

test('getMe clears the session cookie when the user no longer exists', async (t) => {
  const originalFindByPk = User.findByPk;
  t.after(() => {
    User.findByPk = originalFindByPk;
  });

  User.findByPk = async () => null;

  const req = { user: { id: 'ghost-user' }, headers: {} };
  const res = createResponse();

  await getMe(req, res);

  assert.equal(res.statusCode, 401);
  assert.equal(res.payload.message, 'Non authentifié.');
  assert.match(res.headers['Set-Cookie'], /Max-Age=0/);
});