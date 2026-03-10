## Intégration Vault en production

Le backend peut maintenant charger ses secrets depuis HashiCorp Vault avant de démarrer.

### 1. Variables à définir sur le serveur applicatif

- `NODE_ENV=production`
- `VAULT_ENABLED=true`
- `VAULT_ADDR=https://vault.mon-domaine.tld`
- `VAULT_TOKEN=...`
- `VAULT_SECRET_PATH=secret/data/nfs-backend/production`
- `VAULT_KV_VERSION=2`

Variables optionnelles :

- `VAULT_NAMESPACE=...`
- `VAULT_OVERRIDE_EXISTING=true`
- `VAULT_SKIP_TLS_VERIFY=false`
- `VAULT_FAIL_ON_ERROR=false`

### 2. Secrets à stocker dans Vault

Le secret Vault doit contenir les mêmes clés que les variables d'environnement du backend, par exemple :

- `JWT_SECRET`
- `JWT_EXPIRES_IN`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `DB_HOST`
- `DB_PORT`
- `GMAIL_USER`
- `GMAIL_PASS`
- `FILE_ENCRYPTION_KEY`
- `DEFAULT_PAGE_SIZE`
- `MAX_PAGE_SIZE`
- `MAX_FILE_SIZE_MB`
- `ADMIN_EMAIL`
- `ADMIN_FIRST_NAME`
- `ADMIN_LAST_NAME`
- `ADMIN_PHONE`

### 3. Exemple de chargement KV v2

Si ton moteur KV est monté sur `secret/`, le chemin API attendu pour la prod est typiquement :

- `secret/data/nfs-backend/production`

Exemple de commande Vault :

- `vault kv put secret/nfs-backend/production JWT_SECRET="..." DB_USER="..." DB_PASSWORD="..." FILE_ENCRYPTION_KEY="..."`

### 4. Démarrage du backend

Une fois les variables Vault ci-dessus définies, le backend charge automatiquement Vault au démarrage :

- `npm start`

Si Vault n'est pas joignable et que `VAULT_FAIL_ON_ERROR=false`, le backend continue avec les variables d'environnement déjà présentes sur le serveur.

### 5. Migrations / seed avec Vault

Pour les commandes Sequelize en production :

- `npm run migrate:vault`
- `npm run seed:vault`
- `npm run migrate:undo:vault`

Le script `scripts/withVault.js` charge d'abord les secrets depuis Vault, puis lance la commande.

### 6. Notes importantes

- En local/dev, tu peux continuer à utiliser `.env`.
- `FILE_ENCRYPTION_KEY` doit rester stable dans le temps, sinon les anciens fichiers chiffrés ne pourront plus être relus.
- `VAULT_SKIP_TLS_VERIFY=true` ne doit être utilisé qu'en dépannage temporaire avec certificat autosigné.
- Pour une version plus sécurisée ensuite, on pourra remplacer `VAULT_TOKEN` par une authentification AppRole ou un Vault Agent.

## Antivirus et journalisation fichiers

Le backend peut aussi scanner les fichiers en mémoire via un serveur ClamAV `clamd`, avant chiffrement et persistance.

Variables utiles :

- `ANTIVIRUS_ENABLED=true`
- `ANTIVIRUS_HOST=127.0.0.1`
- `ANTIVIRUS_PORT=3310`
- `ANTIVIRUS_TIMEOUT_MS=10000`
- `ANTIVIRUS_MAX_STREAM_BYTES=26214400`
- `ANTIVIRUS_FAIL_ON_ERROR=true`

Comportement :

- le scan se fait avant `encryptToFile()`
- si un malware est détecté, l'upload est rejeté
- si le scan échoue et `ANTIVIRUS_FAIL_ON_ERROR=true`, l'upload est bloqué
- sinon l'erreur est journalisée et l'upload continue en mode dégradé
- tous les téléchargements et événements antivirus sont loggés dans `logs/combined.log`

Le protocole utilisé est `clamd` en mode `INSTREAM`, ce qui évite d'écrire le fichier en clair sur disque pour le scanner.