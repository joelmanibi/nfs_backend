'use strict';

const { Op }     = require('sequelize');
const { Client } = require('ldapts');
const { User }   = require('../models');
const logger     = require('../../config/logger');

// ─── LDAP config ──────────────────────────────────────────────────────────────
const LDAP_URL           = process.env.LDAP_URL           || 'ldaps://10.32.15.110:636';
const LDAP_BASE_DN       = process.env.LDAP_BASE_DN       || 'OU=PAA,DC=paa,DC=local';
const LDAP_BIND_DN       = process.env.LDAP_BIND_DN       || 'idssecuremft@paa.local';
const LDAP_BIND_PASSWORD = process.env.LDAP_BIND_PASSWORD || 'S3cur3!P@@62';

const MAX_RESULTS = 10;

const escapeLdap = (s) => s.replace(/[*()\\]/g, '');

/**
 * GET /api/users/search?q=...
 * Recherche des utilisateurs dans la DB locale ET dans l'Active Directory.
 * Authentification requise. Retourne max 10 suggestions fusionnées.
 * Les données DB ont priorité sur les données LDAP (déduplication par email).
 */
const searchUsers = async (req, res) => {
  const q = req.query.q?.trim() || '';

  if (q.length < 2) {
    return res.json({ users: [] });
  }

  // Map email → suggestion (DB a priorité sur LDAP)
  const results = new Map();

  // ── 1. Base de données locale ────────────────────────────────────────────────
  try {
    const dbUsers = await User.findAll({
      where: {
        isApproved: true,
        [Op.or]: [
          { email:     { [Op.like]: `%${q}%` } },
          { firstName: { [Op.like]: `%${q}%` } },
          { lastName:  { [Op.like]: `%${q}%` } },
        ],
      },
      attributes: ['email', 'firstName', 'lastName', 'isInternalUser'],
      limit: MAX_RESULTS,
    });

    for (const u of dbUsers) {
      const email = u.email.toLowerCase();
      results.set(email, {
        email,
        label:          `${u.firstName} ${u.lastName}`.trim(),
        isInternalUser: Boolean(u.isInternalUser),
        source:         'db',
      });
    }
  } catch (dbErr) {
    logger.warn('userSearch DB error', { error: dbErr.message });
  }

  // ── 2. Active Directory (LDAP) ───────────────────────────────────────────────
  if (results.size < MAX_RESULTS) {
    const client = new Client({
      url:            LDAP_URL,
      tlsOptions:     { rejectUnauthorized: false },
      timeout:        5000,
      connectTimeout: 5000,
    });

    try {
      await client.bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD);

      const safe   = escapeLdap(q);
      const filter = `(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(mail=*${safe}*)(displayName=*${safe}*)(givenName=*${safe}*)(sn=*${safe}*)(sAMAccountName=*${safe}*)))`;

      const { searchEntries } = await client.search(LDAP_BASE_DN, {
        scope:      'sub',
        filter,
        attributes: ['mail', 'givenName', 'sn', 'displayName'],
        sizeLimit:  MAX_RESULTS,
      });

      for (const entry of (searchEntries || [])) {
        if (results.size >= MAX_RESULTS) break;

        const rawMail = Array.isArray(entry.mail) ? entry.mail[0] : entry.mail;
        if (!rawMail) continue;

        const email = rawMail.toLowerCase().trim();
        if (results.has(email)) continue; // DB a priorité

        const firstName   = (Array.isArray(entry.givenName)   ? entry.givenName[0]   : entry.givenName)   || '';
        const lastName    = (Array.isArray(entry.sn)          ? entry.sn[0]          : entry.sn)          || '';
        const displayName = (Array.isArray(entry.displayName) ? entry.displayName[0] : entry.displayName) || `${firstName} ${lastName}`.trim();

        results.set(email, {
          email,
          label:          displayName || email,
          isInternalUser: true, // utilisateurs AD = toujours internes
          source:         'ldap',
        });
      }
    } catch (ldapErr) {
      // LDAP indisponible → dégradation gracieuse, résultats DB déjà présents
      logger.warn('userSearch LDAP error', { error: ldapErr.message });
    } finally {
      await client.unbind().catch(() => {});
    }
  }

  return res.json({ users: [...results.values()] });
};

module.exports = { searchUsers };

