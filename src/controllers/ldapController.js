'use strict';

const { Client }   = require('ldapts');
const jwt          = require('jsonwebtoken');

const { User }     = require('../models');
const config       = require('../../config');
const logger       = require('../../config/logger');
const { buildRequestAuditMeta } = require('../../helpers/audit');

// ─── Config LDAP depuis .env ──────────────────────────────────────────────────
// Contrôleur PAA : A-SRV-DC-01 — LDAPS port 636 — domaine paa.local
const LDAP_URL           = process.env.LDAP_URL           || 'ldaps://10.32.15.110:636';
const LDAP_BASE_DN       = process.env.LDAP_BASE_DN       || 'OU=PAA,DC=paa,DC=local';
const LDAP_BIND_DN       = process.env.LDAP_BIND_DN       || 'idssecuremft@paa.local';
const LDAP_BIND_PASSWORD = process.env.LDAP_BIND_PASSWORD || 'S3cur3!P@@62';
const LDAP_USER_FILTER   = process.env.LDAP_USER_FILTER   || '(sAMAccountName={username})';

/**
 * POST /api/auth/login-ldap
 * Authentification via Active Directory du PAA.
 * Si l'utilisateur n'existe pas encore en base → provisioning just-in-time.
 */
const loginWithLDAP = async (req, res) => {
  const { username, password } = req.body;

  if (!username?.trim() || !password?.trim()) {
    return res.status(400).json({ message: 'Identifiant et mot de passe requis.' });
  }

  const client = new Client({
    url: LDAP_URL,
    tlsOptions: { rejectUnauthorized: false },
    timeout: 8000,
    connectTimeout: 8000,
  });

  try {
    // ── 1. Bind de service (pour pouvoir faire la recherche) ──────────────────
    await client.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD);

    // ── 2. Rechercher l'utilisateur dans l'AD ─────────────────────────────────
    const filter = LDAP_USER_FILTER.replace('{username}', username.trim());
    const { searchEntries } = await client.search(LDAP_BASE_DN, {
      scope: 'sub',
      filter,
      attributes: ['sAMAccountName', 'mail', 'givenName', 'sn', 'displayName'],
    });

    if (!searchEntries || searchEntries.length === 0) {
      logger.warn('LDAP login failed — user not found in AD', {
        event: 'auth_ldap_user_not_found',
        username: username.trim(),
        ...buildRequestAuditMeta(req),
      });
      return res.status(401).json({ message: 'Identifiant introuvable dans l\'annuaire.' });
    }

    const entry = searchEntries[0];
    const userDN = entry.dn;

    // ── 3. Bind avec les credentials de l'utilisateur pour vérifier le mot de passe ──
    await client.bind(userDN, password);

    // ── 4. Extraction des attributs AD ───────────────────────────────────────
    // Attributs PAA : mail (email), displayName (nom complet), givenName / sn (prénom / nom)
    const adEmail       = (Array.isArray(entry.mail)        ? entry.mail[0]        : entry.mail)        || `${username.trim()}@paa.ci`;
    const adDisplayName = (Array.isArray(entry.displayName) ? entry.displayName[0] : entry.displayName) || '';
    const adFirstName   = (Array.isArray(entry.givenName)   ? entry.givenName[0]   : entry.givenName)
                          || adDisplayName.split(' ')[0]
                          || username.trim();
    const adLastName    = (Array.isArray(entry.sn)          ? entry.sn[0]          : entry.sn)
                          || adDisplayName.split(' ').slice(1).join(' ')
                          || 'PAA';
    const normalizedEmail = adEmail.toLowerCase().trim();

    // ── 5. Trouver ou créer l'utilisateur en base (just-in-time provisioning) ──
    let user = await User.findOne({ where: { email: normalizedEmail } });

    if (!user) {
      user = await User.create({
        firstName:      adFirstName,
        lastName:       adLastName,
        email:          normalizedEmail,
        phone:          null,
        city:           null,
        organisation:   'Port Autonome d\'Abidjan',
        country:        'Côte d\'Ivoire',
        isInternalUser: true,
        isApproved:     true,
        passwordHash:   null,
      });

      logger.info('LDAP just-in-time provisioning — new user created', {
        event: 'auth_ldap_user_provisioned',
        userId: user.id,
        email: normalizedEmail,
        ...buildRequestAuditMeta(req),
      });
    } else {
      // Mise à jour du nom depuis l'AD (peut avoir changé)
      await user.update({ firstName: adFirstName, lastName: adLastName, isInternalUser: true });
    }

    if (!user.isApproved) {
      return res.status(403).json({ pending: true, message: 'Votre compte est en attente de validation.' });
    }

    // ── 6. Émission du JWT (même format que le reste de l'app) ───────────────
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: '2h' },
    );

    logger.info('LDAP authentication succeeded', {
      event: 'auth_ldap_succeeded',
      userId: user.id,
      ...buildRequestAuditMeta(req),
    });

    return res.status(200).json({
      message: 'Authentification PAA réussie.',
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });

  } catch (err) {
    const isCredentialError = err.message?.includes('Invalid Credentials') || err.code === 49;

    logger.warn(isCredentialError ? 'LDAP login failed — bad credentials' : 'LDAP error', {
      event: isCredentialError ? 'auth_ldap_invalid_credentials' : 'auth_ldap_error',
      username: username.trim(),
      error: err.message,
      ...buildRequestAuditMeta(req),
    });

    if (isCredentialError) {
      return res.status(401).json({ message: 'Identifiant ou mot de passe incorrect.' });
    }

    return res.status(500).json({ message: 'Erreur de connexion à l\'annuaire PAA.', error: err.message });

  } finally {
    await client.unbind().catch(() => {});
  }
};

module.exports = { loginWithLDAP };

