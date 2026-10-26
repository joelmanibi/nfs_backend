# IDS Secure Transport — Configuration Vault (Production)

## Stratégie

Vault ne stocke que les **2 secrets critiques et immuables** de l'application.
Toutes les autres variables (DB, SMTP, LDAP, etc.) sont gérées dans le fichier `.env` du serveur de production.

| Secret | Stocké dans |
|---|---|
| `FILE_ENCRYPTION_KEY` | **Vault** ← clé AES-256, ne change jamais |
| `JWT_SECRET` (ou `SECRET_CONFIG`, ancien nom accepté) | **Vault** ← clé de signature des sessions, ≥ 32 caractères |
| Tout le reste | **`.env` du serveur** |

**Règles appliquées par le code** (`config/vault.js`, `config/secrets.js`) :

- Ces clés critiques sont **toujours prises dans Vault**, même avec
  `VAULT_OVERRIDE_EXISTING=false`. Si une ancienne valeur traîne dans le
  `.env`, elle est ignorée et l'événement `vault_env_value_overridden` est
  journalisé → la retirer du `.env`.
- Le `.env` est lu depuis le dossier du backend, quel que soit le dossier de
  lancement : l'API (`serve.js`), le worker (`worker.js`) et les scripts de
  migration chargent exactement la même configuration.
- En production, l'API et le worker **refusent de démarrer** si
  `FILE_ENCRYPTION_KEY` (64 caractères hex) ou la clé JWT manque ou est
  invalide. Il n'existe plus de clé JWT par défaut en production.

---

## Étape 1 — Variables à définir sur le serveur (.env production)

Créer un fichier `.env` **sur le serveur de production** (non versionné) avec toutes les variables ci-dessous.
Vault viendra y ajouter `FILE_ENCRYPTION_KEY` et la clé JWT au démarrage. **Ne pas** mettre ces deux clés dans le `.env`.

```env
NODE_ENV=production
PORT=8000
FRONTEND_URL=http://10.112.30.143:3000

# ── Connexion à Vault ──────────────────────────────────────────────────────────
VAULT_ENABLED=true
VAULT_ADDR=https://10.112.30.147:8200
# Authentification AppRole (recommandé) — ou VAULT_TOKEN à la place
VAULT_ROLE_ID=<role-id>
VAULT_SECRET_ID=<secret-id>
VAULT_SECRET_PATH=secret/mft-backend/production
VAULT_SKIP_TLS_VERIFY=true      # certificat Vault autosigné
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
secret/mft-backend/production
├── FILE_ENCRYPTION_KEY  = <cle-hex-64-caracteres-AES256>
└── JWT_SECRET           = <chaine-aleatoire-longue-256bits>   (SECRET_CONFIG accepté)
```

### Commande vault kv patch

```bash
# Ajoute/modifie les clés sans effacer les autres
vault kv patch secret/mft-backend/production \
  FILE_ENCRYPTION_KEY="<cle-hex-64-caracteres>" \
  JWT_SECRET="$(openssl rand -hex 64)"
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

Ou, plus simple : console SUPER_ADMIN → **Journaux techniques**, service « Vault (secrets) » / recherche `secrets_check`.

1. Clés chargées depuis Vault (noms uniquement, jamais les valeurs) :

```json
{ "event": "vault_secrets_loaded", "authMethod": "approle", "loadedKeys": ["FILE_ENCRYPTION_KEY", "JWT_SECRET"] }
```

2. Une ligne `secrets_check` **par process** (`api`, `worker`) avec l'empreinte
   des clés. Les empreintes `fileEncryptionKey` de l'API et du worker doivent
   être **identiques** — sinon les deux process n'utilisent pas la même clé :

```json
{ "event": "secrets_check", "processName": "api",    "source": "vault", "fingerprints": { "fileEncryptionKey": "3f2a9c…", "jwtKey": "b81e04…" } }
{ "event": "secrets_check", "processName": "worker", "source": "vault", "fingerprints": { "fileEncryptionKey": "3f2a9c…" } }
```

À surveiller :

| Événement | Signification |
|---|---|
| `vault_fallback_to_env` | Vault non utilisé (impossible avec `VAULT_FAIL_ON_ERROR=true` : le process s'arrête) |
| `vault_env_value_overridden` | Une clé critique du `.env` diffère de Vault et a été ignorée → la supprimer du `.env` |
| `secrets_check` en `error` | Clé manquante/invalide → le process refuse de démarrer |

---

## Notes importantes

| Sujet | Règle |
|---|---|
| `FILE_ENCRYPTION_KEY` | Ne jamais modifier en production — clé permanente |
| `JWT_SECRET` | Clé JWT — stocker uniquement dans Vault. La changer déconnecte tous les utilisateurs (sans perte de données) |
| `VAULT_OVERRIDE_EXISTING` | Laisser à `false` : n'affecte que les clés non critiques ; les clés critiques viennent toujours de Vault |
| AppRole | Chaque process (API, worker, migrations) se connecte à Vault au démarrage : vérifier que le `secret_id` n'a pas de limite d'utilisations (`secret_id_num_uses`) ou de durée de vie trop courte, sinon les redémarrages finiront par échouer |
| `LDAP_BIND_PASSWORD` | Compte de service AD — droits lecture seule uniquement |
| Développement local | Utiliser `.env` directement — `VAULT_ENABLED=false` en dev |