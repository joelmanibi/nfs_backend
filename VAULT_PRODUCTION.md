# IDS Secure Transport — Configuration Vault (Production)

## Stratégie

Vault ne stocke que les **2 secrets critiques et immuables** de l'application.
Toutes les autres variables (DB, SMTP, LDAP, etc.) sont gérées dans le fichier `.env` du serveur de production.

| Secret | Stocké dans |
|---|---|
| `FILE_ENCRYPTION_KEY` | **Vault** ← clé AES-256, ne change jamais |
| `SECRET_CONFIG` | **Vault** ← clé JWT, sensible |
| Tout le reste | **`.env` du serveur** |

---

## Étape 1 — Variables à définir sur le serveur (.env production)

Créer un fichier `.env` **sur le serveur de production** (non versionné) avec toutes les variables ci-dessous.
Vault viendra y ajouter uniquement `FILE_ENCRYPTION_KEY` et `SECRET_CONFIG` au démarrage.

```env
NODE_ENV=production
PORT=8000
FRONTEND_URL=http://10.112.30.143:3000

# ── Connexion à Vault ──────────────────────────────────────────────────────────
VAULT_ENABLED=true
VAULT_ADDR=https://<adresse-vault-paa>
VAULT_TOKEN=<token-vault-service>
VAULT_SECRET_PATH=secret/data/NFS-backend/production
VAULT_KV_VERSION=2
VAULT_OVERRIDE_EXISTING=false   # Vault n'écrase pas les variables déjà définies dans .env
VAULT_FAIL_ON_ERROR=true        # Bloquer le démarrage si Vault est inaccessible

# ── Base de données MySQL ──────────────────────────────────────────────────────
DB_HOST=<ip-serveur-mysql>
DB_PORT=3306
DB_NAME=nfs
DB_USER=<utilisateur-mysql>
DB_PASSWORD=<mot-de-passe-mysql>

# ── JWT (expirations seulement — la clé vient de Vault) ───────────────────────
JWT_EXPIRES_IN=2h

# ── Email ─────────────────────────────────────────────────────────────────────
MAIL_PROVIDER=smtp
SMTP_HOST=mail.paa.ci
SMTP_PORT=25
SMTP_SECURE=false
SMTP_USER=idssecuremft@paa.ci
SMTP_PASS=S3cur!P@@6
SMTP_FROM=PAA Secure Transport <idssecuremft@paa.ci>
SMTP_TLS_REJECT_UNAUTHORIZED=false

# ── LDAP / Active Directory PAA ───────────────────────────────────────────────
# Contrôleur : A-SRV-DC-01 (10.32.15.110) — LDAPS port 636
LDAP_URL=ldaps://10.32.15.110:636
LDAP_BASE_DN=OU=PAA,DC=paa,DC=local
LDAP_BIND_DN=idssecuremft@paa.local
LDAP_BIND_PASSWORD=S3cur3!P@@62
LDAP_USER_FILTER=(sAMAccountName={username})

# ── Compte administrateur (seed initial) ──────────────────────────────────────
ADMIN_EMAIL=<email-admin-paa>
ADMIN_FIRST_NAME=<prenom-admin>
ADMIN_LAST_NAME=<nom-admin>
ADMIN_PHONE=<telephone-admin>

# ── Antivirus ClamAV ──────────────────────────────────────────────────────────
ANTIVIRUS_ENABLED=true
ANTIVIRUS_HOST=127.0.0.1
ANTIVIRUS_PORT=3310
ANTIVIRUS_TIMEOUT_MS=10000
ANTIVIRUS_MAX_STREAM_BYTES=26214400
ANTIVIRUS_FAIL_ON_ERROR=true

# ── Queue de scan asynchrone (Redis Streams) ──────────────────────────────────
# Désactivée par défaut en dev (aucun Redis requis en local), activée par défaut en prod.
ANTIVIRUS_QUEUE_ENABLED=true
REDIS_URL=redis://127.0.0.1:6379
MAX_CONCURRENT_SCANS=4
SCAN_JOB_MAX_RETRIES=3
QUARANTINE_TTL_MINUTES=60
QUARANTINE_CLEANUP_CRON=*/15 * * * *
```

> `VAULT_SKIP_TLS_VERIFY` : ne pas définir (défaut = `false`). Utiliser uniquement en dépannage avec certificat autosigné.

---

## Étape 2 — Stocker les 2 secrets dans Vault

Le secret Vault ne contient que ces **2 clés** :

```
secret/NFS-backend/production
├── FILE_ENCRYPTION_KEY  = <cle-hex-64-caracteres-AES256>
└── SECRET_CONFIG        = <chaine-aleatoire-longue-256bits>
```

### Commande vault kv put

```bash
vault kv put secret/NFS-backend/production \
  FILE_ENCRYPTION_KEY="<cle-hex-64-caracteres>" \
  SECRET_CONFIG="<chaine-aleatoire-jwt>"
```

> ⚠️ **`FILE_ENCRYPTION_KEY` est permanent** : si cette clé change après la mise en production, tous les fichiers chiffrés déjà stockés deviennent définitivement illisibles.

---

## Étape 3 — Migrations et seed en production

```bash
# Appliquer toutes les migrations (charge Vault avant Sequelize)
npm run migrate:vault

# Créer le compte administrateur initial
npm run seed:vault
```

---

## Étape 4 — Démarrer le backend

```bash
npm start
```

Au démarrage, le backend :
1. Charge le `.env` du serveur
2. Se connecte à Vault et injecte `FILE_ENCRYPTION_KEY` et `SECRET_CONFIG` dans `process.env`
3. Lance le serveur Express

---

## Étape 5 — Vérifier le bon chargement

Consulter les logs au démarrage :

```
logs/combined.log
```

Chercher l'événement (2 clés chargées depuis Vault) :

```json
{ "event": "vault_secrets_loaded", "loadedKeyCount": 2 }
```

Si Vault est en fallback :

```json
{ "event": "vault_fallback_to_env" }
```

---

## Notes importantes

| Sujet | Règle |
|---|---|
| `FILE_ENCRYPTION_KEY` | Ne jamais modifier en production — clé permanente |
| `SECRET_CONFIG` | Clé JWT — ne pas exposer, stocker uniquement dans Vault |
| `VAULT_OVERRIDE_EXISTING` | Laisser à `false` : Vault injecte seulement ses 2 clés sans écraser le `.env` |
| `VAULT_TOKEN` | Remplacer par AppRole ou Vault Agent pour plus de sécurité |
| `LDAP_BIND_PASSWORD` | Compte de service AD — droits lecture seule uniquement |
| Développement local | Utiliser `.env` directement — `VAULT_ENABLED=false` en dev |