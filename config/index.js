const path = require('path');
// .env du backend, quel que soit le dossier depuis lequel le process est lancé
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const { getJwtSecret } = require('./secrets');

module.exports = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,
  jwt: {
    // Getter : la clé est injectée par Vault APRÈS le chargement de ce module,
    // elle doit donc être lue au moment de l'utilisation, pas figée ici.
    get secret() { return getJwtSecret(); },
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  },
  pagination: {
    defaultPageSize: parseInt(process.env.DEFAULT_PAGE_SIZE) || 20,
    maxPageSize: parseInt(process.env.MAX_PAGE_SIZE) || 100
  }
};
