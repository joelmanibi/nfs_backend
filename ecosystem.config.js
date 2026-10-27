'use strict';

/**
 * PM2 — démarre l'API et le worker de scan antivirus ensemble, avec le même
 * dossier de travail et le même NODE_ENV (sinon chacun peut lire un .env ou
 * une config de base de données différente).
 *
 *   pm2 start ecosystem.config.js                    # production (défaut)
 *   pm2 start ecosystem.config.js --env development  # dépannage / sans HTTPS ni Vault
 *   pm2 reload ecosystem.config.js --update-env      # après un déploiement
 *   pm2 save                                         # persiste pour le reboot
 *
 * Les secrets (DB, SMTP, LDAP, Vault…) restent dans le .env du backend : seul
 * NODE_ENV est fixé ici. Une variable définie ici l'emporte sur le .env.
 */

const path = require('path');

const cwd = __dirname;

// Commun aux deux process
const common = {
  cwd,
  exec_mode: 'fork',
  instances: 1,           // jamais de mode cluster : crons (purge, quarantaine, collectes) en double
  autorestart: true,
  // Backoff exponentiel au lieu d'un redémarrage en boucle immédiat
  // (ex. base injoignable au démarrage) : 100 ms, 150 ms, … plafonné à 15 s
  exp_backoff_restart_delay: 100,
  time: true,             // horodatage dans les logs PM2
  env: {
    NODE_ENV: 'production',
  },
  env_development: {
    NODE_ENV: 'development',
  },
};

module.exports = {
  apps: [
    {
      ...common,
      name: 'nfs-backend',
      script: path.join(cwd, 'serve.js'),
      max_memory_restart: '1G',
      kill_timeout: 10000,   // laisse finir les requêtes en cours
    },
    {
      ...common,
      name: 'nfs-backend-worker',
      script: path.join(cwd, 'worker.js'),
      max_memory_restart: '1G',
      // Laisse le temps de terminer un chiffrement en cours avant l'arrêt ;
      // un job interrompu n'est pas perdu (non acquitté → repris via Redis).
      kill_timeout: 30000,
    },
  ],
};
