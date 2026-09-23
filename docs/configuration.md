# Configuration

Every environment variable and admin setting. Configuration lives in two
places, and the split is deliberate:

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
| `REDIS_URL` | `redis://redis:6379/0` | Optional. Valkey or Redis, same protocol. Without it the registry still works, just slower. |
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
| `OSV_BATCH_SIZE` | `200` | Versions per OSV batch query. |
| `OSV_REFRESH_INTERVAL_SECONDS` | `21600` | How often the background task re-scans. |
| `OSV_HOUSEKEEPING_BUDGET_SECONDS` | `600` | Wall-clock the hourly pass spends draining the scan backlog. |
| `OSV_HYDRATE_CONCURRENCY` | `8` | Concurrent advisory fetches per batch. |
| `OSV_CVE_ONLY` | `false` | Ignore advisories with no CVE alias. Malicious-package (`MAL-*`) records are **always** kept regardless. |

Fail-closed is a policy setting, not an environment variable: see
**Block versions that could not be scanned** in [CVE policy](policy.md#unscanned-versions).

### Upstream trust

Artifact URLs come out of upstream metadata, so they are chosen by whoever
controls the upstream. Fetches are restricted to the upstream's own host plus
this allowlist, and never to a private or link-local address.

| Variable | Default | Notes |
|---|---|---|
| `UPSTREAM_ARTIFACT_HOSTS` | the three public registries' CDNs | Comma-separated. Add a host when an upstream serves files from its own CDN. |
| `UPSTREAM_ALLOW_PRIVATE_ADDRESSES` | `false` | Set for a self-hosted GitLab on an internal address. |
| `UPSTREAM_ALLOW_PLAINTEXT_HTTP` | `false` | Allows `http://` upstreams and artifact URLs. |

Per upstream, **Reserved names** claims glob patterns such as `@corp/*`. When
any upstream claims a pattern, matching names are only ever resolved from
upstreams that claim it — a public registry can then never answer for an
internal package, whatever the tier order and whatever the internal upstream
is doing at the time. **Require digest** refuses to cache an artifact the
upstream published no hash for.

### Limits

| Variable | Default | Notes |
|---|---|---|
| `MAX_PUBLISH_BYTES` | `268435456` | Rejected on `Content-Length` before the body is read. |
| `MAX_METADATA_BYTES` | `100663296` | Largest upstream packument or index document. |
| `MAX_ARTIFACT_BYTES` | `2147483648` | Largest artifact streamed from an upstream. |
| `STORAGE_QUOTA_BYTES` | `0` | Stops caching new upstream artifacts above this. Publishes are exempt. `0` disables. |
| `DB_POOL_TIMEOUT_SECONDS` | `10` | Wait for a pooled connection before failing. |
| `DB_STATEMENT_TIMEOUT_SECONDS` | `30` | Server-side cap per query. |

### Rate limits

Per minute. Requires Valkey; without it, limiting is disabled.

| Variable | Default |
|---|---|
| `RATE_LIMIT_ENABLED` | `true` |
| `RATE_LIMIT_ANONYMOUS_PER_MINUTE` | `600` |
| `RATE_LIMIT_AUTHENTICATED_PER_MINUTE` | `3000` |
| `RATE_LIMIT_PUBLISH_PER_MINUTE` | `60` |
| `RATE_LIMIT_LOGIN_PER_MINUTE` | `10` |

Counts reset on a fixed one-minute boundary; a rejected request gets a `429`
whose `Retry-After` says how many seconds are left in the window, and
`X-RateLimit-Limit` / `X-RateLimit-Remaining` say which budget it hit.

Anonymous requests are counted per client IP, authenticated ones per user. A
CI fleet behind one NAT address therefore shares the anonymous limit. Either
raise it in `.env`, or give CI a token so it draws on the authenticated limit.

The client address is read from the **right** of `X-Forwarded-For`, counting
back `TRUSTED_PROXY_HOPS` (default 1). Anything further left was written by
the caller. Your reverse proxy must append rather than overwrite for this to
be correct, which is what the nginx snippet in
[installation](installation.md) does.

Login and CLI device-flow limits fall back to an in-process counter when the
cache is unreachable, rather than failing open — a cache outage should not
open the door to password guessing.
A typical `npm ci` fetches one tarball per locked package, so size the limit
to the largest lockfile times the number of jobs that can start together.

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

### OIDC

Any compliant provider — tested with [Kanidm](https://kanidm.com/) and
[Authentik](https://goauthentik.io/). Past the issuer and the client
credentials nothing is provider-specific: the endpoints, the signing keys and
the client-authentication method are read from the discovery document.

```env
OIDC_ENABLED=true
OIDC_ISSUER=https://idm.example.com/oauth2/openid/minireg
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_DISPLAY_NAME=Kanidm       # sign-in button: "Sign in with Kanidm"
OIDC_SCOPES=openid profile email groups
OIDC_ADMIN_GROUP=minireg-admins
OIDC_USER_GROUP=               # blank = anyone the IdP authenticates
OIDC_AUTO_CREATE_USERS=true
OIDC_GROUPS_CLAIM=groups
OIDC_USERNAME_CLAIM=preferred_username
```

The issuer is per-application at both providers, spelled differently — Kanidm's
has no trailing slash, Authentik's does. Copy it from the provider rather than
composing it by hand.

#### Getting group membership through

This is the step people miss, and it fails silently: without groups,
`OIDC_ADMIN_GROUP` matches nothing and nobody is promoted. What is needed
differs by provider:

| | |
|---|---|
| **Kanidm** | The `groups` scope must be requested — it is in the default `OIDC_SCOPES` — and the group must be in the client's scope map. |
| **Authentik** | A **groups scope mapping** on the provider, included in the application's scopes. The scope named `groups` plays no part; drop it from `OIDC_SCOPES` if your provider rejects scopes it does not recognise. |

minireg reads groups from both the ID token and the userinfo endpoint, since
Authentik's placement varies by configuration.

**Group names.** `OIDC_ADMIN_GROUP` and `OIDC_USER_GROUP` are matched against
each entry of the claim exactly — never as a substring, so `admins` does not
match `not-admins`. Kanidm names groups by SPN, so both forms work:

| Configured value | Matches |
|---|---|
| `minireg-admins` | `minireg-admins`, `minireg-admins@idm.example.com` |
| `minireg-admins@idm.example.com` | that SPN only — not the same name in another realm |

<details>
<summary>Kanidm client</summary>

```sh
kanidm system oauth2 create minireg "minireg" https://registry.example.com
kanidm system oauth2 add-redirect-url minireg \
    https://registry.example.com/api/auth/oidc/callback
kanidm system oauth2 update-scope-map minireg minireg-admins \
    openid profile email groups
# Hand out "alice" rather than "alice@idm.example.com" as the username.
kanidm system oauth2 prefer-short-username minireg
kanidm system oauth2 show-basic-secret minireg
```

Decide `prefer-short-username` **before** anyone signs in: accounts are keyed
on the subject, so changing it later makes a second account rather than
renaming the first.

</details>

<details>
<summary>Authentik provider</summary>

Create an **OAuth2/OpenID Provider**:

- **Redirect URI**: `https://registry.example.com/api/auth/oidc/callback`
- **Signing key**: any configured certificate
- **Scopes**: `openid`, `profile`, `email`, **plus a groups scope mapping**

The issuer ends in a slash. Copy it from the provider's *OpenID Configuration
Issuer* field.

</details>

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
