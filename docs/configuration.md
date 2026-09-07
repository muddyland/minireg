# Configuration

Two places, and the split is deliberate:

* **`.env`** — infrastructure. Requires a restart. Database URLs, secrets, the
  public URL, timeouts, feature switches.
* **The admin UI** — policy. Applies immediately, no restart. Upstreams, block
  rules, CVE thresholds, users.

If a setting affects *what the registry serves*, it lives in the UI. If it
affects *how the registry runs*, it lives in `.env`.

---

## Environment reference

### Identity

| Variable | Default | Notes |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:8000` | **Must** match what clients use. See [Installation](installation.md#the-one-setting-that-must-be-right). |
| `APP_NAME` | `minireg` | Used in the `User-Agent` sent to upstreams. |
| `ENVIRONMENT` | `prod` | `dev` enables CORS for the Vite dev server on `:5173`. |
| `LOG_LEVEL` | `INFO` | `DEBUG` is very chatty under load. |

### Secrets

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *required* | Signs session cookies and OIDC login state. Changing it logs everyone out. |
| `CREDENTIAL_KEY` | derived from `SECRET_KEY` | Encrypts stored upstream credentials. Set it explicitly if you ever plan to rotate `SECRET_KEY` without re-entering every upstream credential. |

Rotating `SECRET_KEY` while `CREDENTIAL_KEY` is unset makes existing upstream
credentials undecryptable — they must be re-entered. Set both from the start.

### Database and cache

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://…` | Must use the `asyncpg` driver. |
| `DB_POOL_SIZE` | `20` | Per process. With N replicas, Postgres needs `N × (pool + overflow)` connections. |
| `DB_MAX_OVERFLOW` | `20` | Burst above the pool. |
| `DB_ECHO` | `false` | Logs every SQL statement. Debugging only. |
| `REDIS_URL` | `redis://redis:6379/0` | Optional. Without it the registry still works, just slower. |
| `META_CACHE_TTL` | `60` | Seconds a rendered packument / index page stays fresh. |
| `META_NEGATIVE_CACHE_TTL` | `30` | How long a "not found" is remembered. |
| `SEARCH_CACHE_TTL` | `120` | Search result caching. |

### Storage

| Variable | Default | Notes |
|---|---|---|
| `STORAGE_PATH` | `/data/packages` | Content-addressed blob store. |
| `STORAGE_QUOTA_BYTES` | `0` | `0` disables the cap. |
| `CACHE_ARTIFACTS` | `true` | Turning this off makes every download a passthrough fetch. |
| `STREAM_CHUNK_SIZE` | `262144` | Read/write chunk size for artifact streaming. |

### Access

| Variable | Default | Notes |
|---|---|---|
| `ALLOW_ANONYMOUS_READ` | `true` | `true` = anyone who can reach it can install. The web UI always requires a login regardless. |
| `SESSION_COOKIE` | `minireg_session` | |
| `SESSION_TTL_SECONDS` | `43200` | 12 hours. |
| `TOKEN_PREFIX` | `mrg` | Leading segment of issued API tokens. Changing it invalidates every existing token, since lookup is by prefix. |
| `BOOTSTRAP_ADMIN_USERNAME` | `admin` | Created only when the database has no users at all. |
| `BOOTSTRAP_ADMIN_PASSWORD` | *(generated)* | Blank means one is generated and printed to the log exactly once. |

### Upstreams

| Variable | Default | Notes |
|---|---|---|
| `UPSTREAM_TIMEOUT_SECONDS` | `20` | Overridable per upstream in the UI. |
| `UPSTREAM_CONNECT_TIMEOUT_SECONDS` | `5` | |
| `UPSTREAM_MAX_CONNECTIONS` | `100` | Shared pool across all upstreams. |
| `UPSTREAM_RETRIES` | `2` | Retries apply to 5xx/429 and transport errors, never to a 404. |
| `UPSTREAM_TIER_PARALLEL` | `true` | Race every upstream in a tier and take the first success. Off = try them one at a time by priority (fewer upstream requests, higher latency). |

### CVE scanning

| Variable | Default | Notes |
|---|---|---|
| `OSV_ENABLED` | `true` | Master switch. |
| `OSV_API_URL` | `https://api.osv.dev` | Point at a mirror if you have one. |
| `OSV_INLINE_SCAN` | `true` | Scan a version the first time it is served. |
| `OSV_INLINE_TIMEOUT_SECONDS` | `4` | Budget for that inline scan. Exceeding it does **not** block the request. |
| `OSV_FAIL_CLOSED` | `false` | See [CVE policy](policy.md#unscanned-versions). |
| `OSV_BATCH_SIZE` | `200` | Versions per OSV batch query. |
| `OSV_REFRESH_INTERVAL_SECONDS` | `21600` | How often the background task re-scans. |
| `OSV_CVE_ONLY` | `true` | Ignore OSV records with no CVE alias (GHSA-only, MAL-only). |

### Rate limits

Per minute. Requires Redis; without it, limiting is disabled.

| Variable | Default |
|---|---|
| `RATE_LIMIT_ENABLED` | `true` |
| `RATE_LIMIT_ANONYMOUS_PER_MINUTE` | `600` |
| `RATE_LIMIT_AUTHENTICATED_PER_MINUTE` | `3000` |
| `RATE_LIMIT_PUBLISH_PER_MINUTE` | `60` |
| `RATE_LIMIT_LOGIN_PER_MINUTE` | `10` |

A CI fleet behind one NAT address shares the anonymous limit. Either raise it,
or give CI a token so it uses the authenticated limit.

### Retention

| Variable | Default | Notes |
|---|---|---|
| `DOWNLOAD_LOG_RETENTION_DAYS` | `365` | `0` disables pruning. |
| `AUDIT_LOG_RETENTION_DAYS` | `730` | Check this against your compliance requirements before lowering it. |

---

## Upstreams

**Upstreams → Add upstream.**

| Field | Meaning |
|---|---|
| **Name** | Label only; appears in logs and on package pages. |
| **Ecosystem** | npm, PyPI or cargo. Cannot be changed after creation. |
| **Type** | Plain registry, or GitLab package registry. Cargo has one type — GitLab hosts no cargo registry. |
| **URL** | Registry root. For GitLab, the instance root — `/api/v4` is appended automatically. For cargo, the sparse index root (e.g. `https://index.crates.io`) *without* the `sparse+` prefix — that is a scheme marker for the client, not part of the URL we fetch. |
| **Tier** | Lower is tried first. See [Tiering](#tiering). |
| **Priority** | Order *within* a tier. |
| **Timeout** | Per-request, overrides the global default. |
| **Authentication** | See below. |
| **Package page URL** | Optional. Where a human should click to read about a package. Placeholders `{name}`, `{normalized_name}`. Derived automatically for npmjs.com and pypi.org. |
| **Mirror local publishes** | Forward anything published here to this upstream too. |
| **Include in search** | Import this upstream's package list into the search index. |

### Tiering

```
request → tier 1 upstreams (raced) → tier 2 (raced) → … → 404
```

A tier is fully exhausted before the next is tried. A 404 from one upstream is
authoritative *for that upstream only*; the search continues.

The usual arrangement:

| Tier | Upstream | Why |
|---|---|---|
| 1 | Internal GitLab registry | Private packages resolve first and never leak a lookup to the public internet |
| 2 | Public npmjs / PyPI | Everything else |

An upstream that fails 5 times consecutively is quarantined and skipped, with a
probe every 2 minutes so recovery is automatic. The **Health** column shows the
current state and the last error.

### Authentication

| Type | Credential format | Use for |
|---|---|---|
| None | — | Public registries |
| Bearer | `<token>` | Most private npm registries |
| Basic | `user:password` | Artifactory, Nexus |
| Custom header | `<token>` | GitLab `PRIVATE-TOKEN` (default header name) |
| GitLab job token | `<token>` | CI job tokens (`JOB-TOKEN`) |

Credentials are encrypted at rest and never returned by the API — the UI shows
only whether one is set. Leave the field blank when editing to keep the
existing value.

### Cargo

The URL is the sparse index root. The download URL is not configured: it comes
from the index's own `config.json`, which is fetched once and cached.

Cargo upstreams cannot be publish targets or search-index sources. The sparse
index has no endpoint that enumerates every crate — crates.io publishes a
database dump for that, which is not something to pull through a request path —
so **Include in search** does nothing for them. Crates still appear in search
once they have been resolved through the registry.

### GitLab

Set the **project ID** (numeric or URL-encoded path) for a project-scoped
registry, or the **group ID** for a group-scoped one. Publishing requires a
project ID.

Give the token the `api` scope, or use a deploy token with
`read_package_registry` / `write_package_registry`.

If you set the project as a *path* (`mygroup%2Fmyproject`) rather than a numeric
id, the package page link can be derived automatically. With a numeric id it
cannot — GitLab's API does not expose the path — so set **Package page URL**
manually if you want the link.

---

## Users and authentication

### Local accounts

**Users → Add user.** Passwords are hashed with Argon2id, minimum 12 characters.

| Permission | Grants |
|---|---|
| *(none)* | Read the registry and use the web UI |
| Publish | Publish package versions |
| Administrator | Everything, including implicit publish |

An account with no password is SSO-only.

### OIDC / Authentik

```env
OIDC_ENABLED=true
OIDC_ISSUER=https://authentik.example.com/application/o/minireg/
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_ADMIN_GROUP=minireg-admins
OIDC_USER_GROUP=              # blank = anyone the IdP authenticates
OIDC_AUTO_CREATE_USERS=true
OIDC_GROUPS_CLAIM=groups
OIDC_USERNAME_CLAIM=preferred_username
```

In Authentik, create an **OAuth2/OpenID Provider**:

- **Redirect URI**: `https://registry.example.com/api/auth/oidc/callback`
- **Signing key**: any configured certificate
- **Scopes**: `openid`, `profile`, `email`, **plus a groups scope mapping**

That last one is the step people miss. Without a groups scope mapping, group
membership never reaches the registry, `OIDC_ADMIN_GROUP` matches nothing, and
nobody is promoted to admin. minireg reads groups from both the ID token and
the userinfo endpoint, since Authentik's placement varies by configuration.

The issuer is per-application and ends in a slash. Copy it from the provider's
*OpenID Configuration Issuer* field.

Group membership is re-applied on **every** sign-in, so removing someone from
the admin group demotes them the next time they log in — you do not have to
touch the local account.

An OIDC login whose email matches an existing local account links to it rather
than creating a duplicate.

### API tokens

**API tokens → New token.** Shown once at creation; only a SHA-256 of the
secret is stored.

| Scope | Grants |
|---|---|
| `read` | Install and search |
| `publish` | Publish versions |
| `admin` | Full administrative API |

A token can never exceed its owner's permissions — a non-admin requesting an
`admin` token is refused, and the CLI login flow silently drops scopes the
approver does not hold.

Tokens created by `minireg login` are named after the requesting machine, so
revoking a lost laptop is a matter of finding its hostname in the list.
