# API reference

Interactive docs: `https://registry.example.com/api/docs`
OpenAPI schema: `/api/openapi.json`

## Authentication

| Method | Header | Used by |
|---|---|---|
| Bearer token | `Authorization: Bearer mrg_…` | npm, the CLI, scripts |
| Basic (token) | `Authorization: Basic base64("__token__:mrg_…")` | pip, twine |
| Basic (password) | `Authorization: Basic base64("user:pass")` | Clients that cannot send Bearer |
| Session cookie | `minireg_session` | The web UI |

An `Authorization` header is **authoritative**: if one is present but does not
authenticate, the request is anonymous. It never falls back to a session
cookie, so a revoked token cannot appear to keep working for a browser session.

---

## npm registry API

Mounted at `/npm`. Implements the npm registry API.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/npm/{package}` | Packument. `Accept: application/vnd.npm.install-v1+json` returns the abbreviated form |
| `GET` | `/npm/{package}/{version}` | Version document; a dist-tag is accepted in place of a version |
| `GET` | `/npm/{package}/-/{filename}` | Tarball. `immutable` cache headers |
| `PUT` | `/npm/{package}` | Publish, deprecate, undeprecate |
| `DELETE` | `/npm/{package}/-rev/{rev}` | Unpublish a package |
| `DELETE` | `/npm/{package}/-/{filename}/-rev/{rev}` | Unpublish a version |
| `GET` | `/npm/-/package/{package}/dist-tags` | Read dist-tags |
| `PUT` | `/npm/-/package/{package}/dist-tags/{tag}` | Set a dist-tag (body is a bare JSON string) |
| `DELETE` | `/npm/-/package/{package}/dist-tags/{tag}` | Remove a dist-tag (`latest` cannot be removed) |
| `GET` | `/npm/-/v1/search` | Search. `text`, `size`, `from` |
| `GET` | `/npm/-/ping` | Service check |
| `GET` | `/npm/-/whoami` | Current identity |
| `POST` | `/npm/-/npm/v1/security/advisories/bulk` | `npm audit`, answered from this registry's CVE store |

Scoped names work both `%2f`-encoded (`/npm/@babel%2fcore`) and with a literal
slash (`/npm/@babel/core`).

The abbreviated packument is a strict subset: exactly four top-level keys
(`name`, `modified`, `dist-tags`, `versions`) and only npm's permitted
per-version fields.

---

## PyPI API

Mounted at `/pypi`.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/pypi/simple/` | Project index. HTML or JSON by content negotiation |
| `GET` | `/pypi/simple/{project}/` | Project detail. Non-normalized names 301 to the PEP 503 form |
| `GET` | `/pypi/files/{project}/{filename}` | Artifact |
| `GET` | `/pypi/files/{project}/{filename}.metadata` | PEP 658 metadata sidecar |
| `GET` | `/pypi/{project}/json` | Warehouse-compatible JSON (subset) |
| `POST` | `/pypi/legacy/` | twine upload |

Content negotiation per PEP 691:

```bash
curl -H 'accept: application/vnd.pypi.simple.v1+json' .../pypi/simple/requests/
curl -H 'accept: text/html' .../pypi/simple/requests/
curl '.../pypi/simple/requests/?format=application/vnd.pypi.simple.v1+json'
```

Advertised API version is **1.1** (PEP 700). Implements PEP 503, 592, 629, 658,
691, 700, and 714.

---

## Web API

### Auth

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | Password sign-in |
| `POST` | `/api/auth/logout` | Sign out |
| `GET` | `/api/auth/me` | Current identity and scopes |
| `POST` | `/api/auth/password` | Change password |
| `GET` | `/api/auth/tokens` | List your tokens |
| `POST` | `/api/auth/tokens` | Create a token (returned once) |
| `DELETE` | `/api/auth/tokens/{id}` | Revoke |
| `GET` | `/api/auth/oidc/status` | Whether SSO is enabled |
| `GET` | `/api/auth/oidc/login` | Start the SSO flow |
| `GET` | `/api/auth/oidc/callback` | SSO callback |

### Search

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/search` | `q`, `ecosystem`, `limit`, `offset`, `include_upstream` |
| `GET` | `/api/packages/{ecosystem}/{name}` | Package detail, including upstream provenance |
| `GET` | `/api/client-config` | Copy-pasteable client configuration |

### CLI

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/cli/auth/start` | none | Begin device authorization |
| `POST` | `/api/cli/auth/poll` | none | Poll for the token |
| `GET` | `/api/cli/auth/pending/{code}` | session | Details for the approval screen |
| `POST` | `/api/cli/auth/approve` | session | Approve or deny |
| `POST` | `/api/cli/audit` | token | Audit a dependency set |
| `GET` | `/api/cli/version` | none | Shipped CLI version and its SHA-256 |
| `GET` | `/api/cli/download` | none | The CLI script |
| `GET` | `/api/cli/install.sh` | none | Installer with the URL baked in |

Audit request:

```json
{
  "ecosystem": "npm",
  "packages": [{"name": "lodash", "version": "4.17.20"}],
  "scan_unknown": true
}
```

Response:

```json
{
  "ecosystem": "npm",
  "checked": 1,
  "findings": [
    {
      "name": "lodash",
      "version": "4.17.20",
      "max_cvss": 8.1,
      "blocked": true,
      "block_reason": "CVE-2021-23337 — command injection",
      "known_to_registry": true,
      "cves": [
        {
          "cve_id": "CVE-2021-23337",
          "osv_id": "GHSA-35jh-r3h4-6jhm",
          "cvss_score": 8.1,
          "severity": "high",
          "summary": "Command Injection in lodash",
          "fixed_version": "4.17.21",
          "suppressed": false,
          "url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"
        }
      ]
    }
  ],
  "unscanned": [],
  "unscanned_total": 0
}
```

Records describing the same CVE are collapsed: the highest score wins, but the
*lowest* fixed version is kept, because that is the smallest upgrade that
resolves it.

### Admin

All require an admin identity and, for token auth, the `admin` scope.

**Users** — `GET|POST /api/admin/users`, `PATCH|DELETE /api/admin/users/{id}`

**Upstreams** — `GET|POST /api/admin/upstreams`,
`PATCH|DELETE /api/admin/upstreams/{id}`,
`POST /api/admin/upstreams/{id}/test`, `POST /api/admin/upstreams/{id}/index`

**Policy** — `GET|POST /api/admin/rules`, `PATCH|DELETE /api/admin/rules/{id}`,
`POST /api/admin/rules/test`, `POST /api/admin/rules/preview-spec`

**Settings** — `GET /api/admin/settings`,
`PUT /api/admin/settings/cve-policy`, `PUT /api/admin/settings/allowlist-mode`

**Stats** — `/api/admin/stats/overview`, `/top-packages`,
`/downloads-timeline`, `/recent-logins`, `/storage`

**Logs** — `GET /api/admin/audit`, `/api/admin/audit/actions`,
`/api/admin/downloads`

**Security** — `GET /api/admin/vulnerabilities`,
`/api/admin/vulnerabilities/{id}/affected`,
`POST /api/admin/vulnerabilities/links/{id}/suppress`,
`POST /api/admin/scan`, `POST /api/admin/rescore`

**Packages** — `GET /api/admin/packages`, `/api/admin/packages/{id}`,
`DELETE /api/admin/packages/{id}`, `POST /api/admin/cache/purge`,
`POST /api/admin/cache/gc`

---

## Errors

npm endpoints return npm's shape, because the CLI prints the field verbatim:

```json
{"error": "You cannot publish over the previously published versions: 1.0.0"}
```

PyPI upload returns plain text, because twine prints the body verbatim.

Every `/api/*` response carries `x-minireg-cli-version`, the CLI version this
registry ships. The CLI reads it from responses it was already making, so it
can tell you it is out of date without spending a request to ask.

Everything else returns FastAPI's shape:

```json
{"detail": "at least one active admin must remain"}
```

| Status | Meaning |
|---|---|
| `400` | Malformed request or failed validation |
| `401` | No credential, or it did not authenticate |
| `403` | Authenticated but not permitted, **or blocked by policy** |
| `404` | Not found here or in any upstream |
| `409` | Conflict — usually republishing an existing version |
| `413` | Upload too large |
| `429` | Rate limited. `Retry-After` is set |
| `502` | Upstream failed, or an artifact failed digest verification |
| `503` | Database or storage unavailable |

---

## Examples

```bash
TOKEN=mrg_…
BASE=https://registry.example.com

# Abbreviated packument
curl -H 'accept: application/vnd.npm.install-v1+json' $BASE/npm/lodash | jq '."dist-tags"'

# PEP 691 JSON
curl -H 'accept: application/vnd.pypi.simple.v1+json' $BASE/pypi/simple/requests/ | jq '.meta'

# Block a package
curl -X POST $BASE/api/admin/rules \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"pattern":"left-pad","action":"block","reason":"use padStart"}'

# What would this rule do?
curl -X POST "$BASE/api/admin/rules/test?ecosystem=npm&name=lodash&version=4.17.20" \
  -H "authorization: Bearer $TOKEN"

# Unhealthy upstreams
curl -s $BASE/api/admin/upstreams -H "authorization: Bearer $TOKEN" |
  jq '[.upstreams[] | select(.enabled and (.healthy|not)) | {name, last_error}]'
```
