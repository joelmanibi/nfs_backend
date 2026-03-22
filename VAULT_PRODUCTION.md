# IDS Secure Transport — Configuration Vault (Production)

Ce document liste **toutes les étapes et tous les secrets** à configurer dans HashiCorp Vault pour que le backend soit pleinement opérationnel en production.

---

## Étape 1 — Prérequis sur le serveur applicatif

Ces variables doivent être définies **directement sur le serveur** (pas dans Vault) car elles permettent à l'application de se connecter à Vault elle-même.

```env
NODE_ENV=production
PORT=8000

VAULT_ENABLED=true
VAULT_ADDR=https://<adresse-vault-paa>
VAULT_TOKEN=<token-vault-service>
VAULT_SECRET_PATH=secret/data/NFS-backend/production
VAULT_KV_VERSION=2
```

Variables optionnelles :

```env
VAULT_NAMESPACE=              # Si Vault Enterprise avec namespaces
VAULT_OVERRIDE_EXISTING=true  # Vault écrase les variables déjà définies
VAULT_SKIP_TLS_VERIFY=false   # true uniquement si certificat autosigné temporaire
VAULT_FAIL_ON_ERROR=false     # true = le backend refuse de démarrer si Vault est inaccessible
```

> **Recommandation** : définir ces variables via les variables d'environnement système ou un fichier `.env` restreint (non versionné), jamais en clair dans le dépôt.

---

## Étape 2 — Créer le secret dans Vault

Toutes les clés ci-dessous doivent être stockées dans un **seul secret KV v2** au chemin :

```
secret/NFS-backend/production
```

### 2.1 — Application

```
NODE_ENV          = production
PORT              = 8000
FRONTEND_URL      = http://10.112.30.143:3000
```

### 2.2 — Base de données (MySQL)

```
DB_HOST           = <ip-serveur-mysql>
DB_PORT           = 3306
DB_NAME           = nfs
DB_USER           = <utilisateur-mysql>
DB_PASSWORD       = <mot-de-passe-mysql>
```

### 2.3 — JWT

```
JWT_SECRET        = <chaine-aleatoire-longue-256bits>
JWT_EXPIRES_IN    = 2h
```

### 2.4 — Chiffrement des fichiers

```
FILE_ENCRYPTION_KEY = <cle-hex-64-caracteres-AES256>
```

> ⚠️ **Critique** : cette clé ne doit **jamais changer** après la mise en production. Si elle est modifiée, tous les fichiers déjà chiffrés deviennent illisibles.

### 2.5 — Messagerie (configurable : Gmail ou SMTP PAA)

La variable `MAIL_PROVIDER` détermine le fournisseur actif.

#### Option A — Gmail (développement / test)

```
MAIL_PROVIDER     = gmail
GMAIL_USER        = <adresse-gmail>
GMAIL_PASS        = <app-password-gmail-16-caracteres>
```

#### Option B — Serveur SMTP PAA (production recommandée)

```
MAIL_PROVIDER     = smtp
SMTP_HOST         = mail.paa.ci
SMTP_PORT         = 587
SMTP_SECURE       = false
SMTP_USER         = noreply@paa.ci
SMTP_PASS         = <mot-de-passe-smtp>
SMTP_FROM         = IDS Secure Transport <noreply@paa.ci>
SMTP_TLS_REJECT_UNAUTHORIZED = true
```

> En prod avec le serveur PAA, ne stocker que les variables `MAIL_PROVIDER=smtp` et les `SMTP_*`. Les variables Gmail ne sont pas nécessaires.

### 2.6 — Compte administrateur (seed initial)

```
ADMIN_EMAIL       = <email-admin-paa>
ADMIN_FIRST_NAME  = <prenom-admin>
ADMIN_LAST_NAME   = <nom-admin>
ADMIN_PHONE       = <telephone-admin>
```

### 2.7 — Authentification LDAP / Active Directory PAA

```
LDAP_URL          = ldap://<ip-controleur-domaine-paa>:389
LDAP_BASE_DN      = DC=paa,DC=ci
LDAP_BIND_DN      = CN=svc-nfs,OU=ServiceAccounts,DC=paa,DC=ci
LDAP_BIND_PASSWORD = <mot-de-passe-compte-service-ad>
LDAP_USER_FILTER  = (sAMAccountName={username})
```

> Le compte `svc-nfs` est un compte de service Active Directory en **lecture seule** sur l'annuaire. Il ne doit pas avoir de droits administrateur.

### 2.8 — Antivirus ClamAV (optionnel)

```
ANTIVIRUS_ENABLED         = true
ANTIVIRUS_HOST            = 127.0.0.1
ANTIVIRUS_PORT            = 3310
ANTIVIRUS_TIMEOUT_MS      = 10000
ANTIVIRUS_MAX_STREAM_BYTES= 26214400
ANTIVIRUS_FAIL_ON_ERROR   = true
```

> Si ClamAV n'est pas installé sur le serveur, laisser `ANTIVIRUS_ENABLED=false`.

### 2.9 — Pagination (optionnel)

```
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE     = 100
```

---

## Étape 3 — Charger le secret dans Vault (commande)

```bash
vault kv put secret/NFS-backend/production \
  NODE_ENV="production" \
  PORT="8000" \
  FRONTEND_URL="http://10.112.30.143:3000" \
  DB_HOST="<ip-mysql>" \
  DB_PORT="3306" \
  DB_NAME="nfs" \
  DB_USER="<user>" \
  DB_PASSWORD="<password>" \
  JWT_SECRET="<secret>" \
  JWT_EXPIRES_IN="2h" \
  FILE_ENCRYPTION_KEY="<cle-hex-64>" \
  MAIL_PROVIDER="smtp" \
  SMTP_HOST="mail.paa.ci" \
  SMTP_PORT="587" \
  SMTP_SECURE="false" \
  SMTP_USER="noreply@paa.ci" \
  SMTP_PASS="<mot-de-passe-smtp>" \
  SMTP_FROM="IDS Secure Transport <noreply@paa.ci>" \
  SMTP_TLS_REJECT_UNAUTHORIZED="true" \
  ADMIN_EMAIL="<email>" \
  ADMIN_FIRST_NAME="<prenom>" \
  ADMIN_LAST_NAME="<nom>" \
  LDAP_URL="ldap://<ip>:389" \
  LDAP_BASE_DN="DC=paa,DC=ci" \
  LDAP_BIND_DN="CN=svc-nfs,OU=ServiceAccounts,DC=paa,DC=ci" \
  LDAP_BIND_PASSWORD="<password-ad>" \
  LDAP_USER_FILTER="(sAMAccountName={username})" \
  ANTIVIRUS_ENABLED="true" \
  ANTIVIRUS_HOST="127.0.0.1" \
  ANTIVIRUS_PORT="3310" \
  ANTIVIRUS_FAIL_ON_ERROR="true"
```

---

## Étape 4 — Migrations et seed en production

Une fois Vault configuré, utiliser les commandes suivantes (qui chargent automatiquement les secrets Vault avant d'exécuter Sequelize) :

```bash
# Appliquer toutes les migrations
npm run migrate:vault

# Créer le compte administrateur initial
npm run seed:vault
```

> Ces commandes passent par `scripts/withVault.js` qui injecte les variables Vault dans l'environnement avant de lancer Sequelize.

---

## Étape 5 — Démarrer le backend

```bash
npm start
```

Au démarrage, le backend :
1. Se connecte à Vault et charge tous les secrets en mémoire (`process.env`)
2. Si Vault est inaccessible et `VAULT_FAIL_ON_ERROR=false`, il continue avec les variables système déjà définies
3. Lance le serveur Express sur le port configuré

---

## Étape 6 — Vérifier le bon chargement

Consulter les logs au démarrage :

```
logs/combined.log
```

Chercher l'événement :

```json
{ "event": "vault_secrets_loaded", "loadedKeyCount": 22 }
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
| `VAULT_SKIP_TLS_VERIFY` | Uniquement pour test avec certificat autosigné |
| `VAULT_TOKEN` | Remplacer par AppRole ou Vault Agent pour plus de sécurité |
| `LDAP_BIND_PASSWORD` | Compte de service AD — droits lecture seule uniquement |
| `MAIL_PROVIDER` | `smtp` en prod (serveur PAA), `gmail` en dev uniquement |
| `SMTP_PASS` / `GMAIL_PASS` | Ne jamais versionner — stocker exclusivement dans Vault |
| Développement local | Continuer à utiliser `.env` — Vault non requis en dev |