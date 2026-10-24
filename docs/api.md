# API reference

Every endpoint this registry serves. The interactive Swagger UI at
`/api/docs` and the schema at `/api/openapi.json` are available only when
`ENVIRONMENT=dev`, because in production they enumerate the whole admin
surface for anyone who asks.

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

## Cargo API

Mounted at `/cargo`. The sparse HTTP index (RFC 2789); the git index is not
supported.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/cargo/index/config.json` | Registry configuration. `api` is omitted — this is a read-only mirror |
| `GET` | `/cargo/index/{prefix}/{crate}` | Index file: newline-delimited JSON, one object per version |
| `GET` | `/cargo/api/v1/crates/{crate}/{version}/download` | Artifact (`.crate`) |

The shard `{prefix}` is fixed by cargo and computed by the client, so it must
match exactly: `1/{name}` for one-character names, `2/{name}` for two,
`3/{first}/{name}` for three, and `{name[0:2]}/{name[2:4]}/{name}` beyond that,
all lowercased. A request whose prefix disagrees with its final segment is a
404 rather than a redirect.

```bash
curl .../cargo/index/config.json
curl .../cargo/index/se/rd/serde
curl -O .../cargo/api/v1/crates/serde/1.0.197/download
```

A version blocked by policy is rendered as `"yanked": true` — the only "do not
select this" signal the index format has — and its download returns **403**.

There is no publish, yank or owners surface. See
[Using the registry](usage.md#why-cargo-is-read-only).

---

## Container registry (OCI)

Mounted at `/v2`. Implements the OCI distribution spec 1.1, so `docker`,
Podman, containerd, crane and skopeo work unmodified. Image names contain
slashes, so one catch-all route dispatches on the path suffix. Every response
carries `Docker-Distribution-API-Version: registry/2.0`, and every error is an
OCI error body (`{"errors": [{"code": "DENIED", "message": …}]}`). The whole
surface answers 404 `UNSUPPORTED` when `DOCKER_ENABLED=false`.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v2/` | Version check. Always challenges an anonymous client, so `docker push` knows to log in |
| `GET` `POST` | `/v2/token` | Docker token endpoint (GET) and OAuth2 password grant (POST, what `docker login` sends). Exchanges an API token for a short-lived registry bearer token |
| `GET` | `/v2/_catalog` | Repository list. `n`, `last`; paginates with a `Link` header. Requires a login |
| `GET` `HEAD` | `/v2/{name}/manifests/{reference}` | Manifest or index by tag or digest. Pull policy is enforced here: a refused image is `DENIED` with the reason |
| `PUT` | `/v2/{name}/manifests/{reference}` | Push a manifest (local namespace only) |
| `DELETE` | `/v2/{name}/manifests/{digest}` | Delete a pushed manifest |
| `GET` `HEAD` | `/v2/{name}/blobs/{digest}` | Layer or config blob. Fetched from the upstream and verified on first request |
| `DELETE` | `/v2/{name}/blobs/{digest}` | Unlink a blob from a pushed repository |
| `POST` | `/v2/{name}/blobs/uploads/` | Start an upload; supports monolithic (`?digest=`) and cross-repository mount (`?mount=&from=`) |
| `GET` `PATCH` `PUT` `DELETE` | `/v2/{name}/blobs/uploads/{uuid}` | Upload status, append a chunk, complete (`?digest=`), cancel |
| `GET` | `/v2/{name}/tags/list` | Tags. `n`, `last`; paginates with a `Link` header |
| `GET` | `/v2/{name}/referrers/{digest}` | OCI referrers (signatures, SBOMs, attestations). `artifactType` filters |

Authentication is the Docker token flow: the client sends Basic credentials
(any username, an **API token** as the password) to `/v2/token` and gets a
bearer token valid for `DOCKER_TOKEN_TTL_SECONDS`. Pulls need the `read`
scope, or nothing when `ALLOW_ANONYMOUS_READ=true`. Pushes need the
`docker:push` scope on an account allowed to publish, and are accepted only
under `DOCKER_LOCAL_NAMESPACE/` (default `local/`); any write to a cached
upstream repository is `DENIED`. On `DOCKER_MIRROR_HOSTNAME`, every name is a
Docker Hub name and the surface is read-only.

See [Container images](containers.md) for naming, the mirror, and policy.

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

### Documentation

Serves these pages to the **?** in the UI, so a registry with no route to the
internet still has its own documentation. Requires a signed-in user.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/help/pages` | Index: slug, title and summary per page |
| `GET` | `/api/help/pages/{slug}` | One page, as markdown |

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

### Container images

Read endpoints require a signed-in user; the rest require an admin unless
noted. Repositories are addressed by a `name` query parameter, because image
names contain slashes.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/docker/images` | user | List repositories. `q`, `scope` (`local`, `cached`, `quarantined`, `watched`), `limit`, `offset` |
| `GET` | `/api/docker/repository` | user | One repository: tags, digests, scan status. `name` |
| `GET` | `/api/docker/inspect` | user | Resolve a reference the way `docker pull` would and report its findings and whether a pull would be allowed. `ref`, `platform` (default `linux/amd64`), `findings`. Used by `minireg audit --image` and `minireg info --ecosystem docker` |
| `GET` | `/api/docker/manifest/{digest}` | user | Manifest detail: layers, platforms, repositories that reference it, latest scan |
| `GET` | `/api/docker/manifest/{digest}/findings` | user | Trivy findings. `severity` (comma-separated), `fixable`, `kev`, `q`, `limit`, `offset` |
| `GET` | `/api/docker/manifest/{digest}/config` | user | Entrypoint, env, labels, ports and build history, each layer paired with its step |
| `GET` | `/api/docker/manifest/{digest}/packages` | user | The SBOM as a package list |
| `GET` | `/api/docker/manifest/{digest}/sbom` | user | The raw CycloneDX SBOM, as a download |
| `GET` | `/api/docker/vulnerabilities` | user | Which images contain a CVE (or package, or severity). `cve`, `package`, `severity`, `kev`, `limit` |
| `GET` | `/api/docker/client-config` | user | Copy-pasteable `docker login`, pull and mirror configuration |
| `PATCH` | `/api/docker/repository` | admin | Pin, quarantine (with a reason) or watch tags. `name` |
| `POST` | `/api/docker/repository/refresh` | admin | Revalidate one watched tag now. `name` |
| `DELETE` | `/api/docker/repository` | admin | Forget a cached repository; files go at the next GC. Pushed repositories are refused (delete them through `/v2`). `name` |
| `POST` | `/api/docker/manifest/{digest}/rescan` | admin | Queue a rescan. `full=true` re-pulls the layers instead of rescanning the stored SBOM |
| `GET` `PUT` | `/api/docker/policy` | admin | Read or replace the image policy |
| `GET` | `/api/docker/stats` | admin | Disk use against the budget, pulls in the last 24 hours, scan queue, counts of KEV, critical and push-blocked images, upstream rate-limit headroom, when each scanner was last seen |
| `GET` | `/api/docker/presets` | admin | Well-known registries (Docker Hub, ghcr, Quay, …) and whether each is configured |
| `POST` | `/api/docker/presets/{name}` | admin | Add a well-known registry as an upstream |
| `POST` | `/api/docker/upstreams/{id}/index` | admin | List a GitLab container registry's repositories into search |

The scanner worker uses its own routes, which accept **only** a token with
exactly the `scanner` scope (an admin token is refused):

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/docker/scanner/claim` | Claim the next scan job; `204` when there is none or scanning is off |
| `POST` | `/api/docker/scanner/jobs/{id}/heartbeat` | Extend the job's lease while Trivy runs. `worker` |
| `GET` | `/api/docker/scanner/jobs/{id}/sbom` | The stored SBOM, for an SBOM-only rescan |
| `POST` | `/api/docker/scanner/jobs/{id}/result` | Upload the Trivy report (and SBOM) as multipart form data |
| `POST` | `/api/docker/scanner/jobs/{id}/fail` | Report a failure; `permanent` skips the image instead of retrying |
| `GET` | `/api/docker/scanner/config` | Where to fetch the Trivy database from (through the `ghcr` upstream when one exists) |

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

**Package requests** — `GET /api/admin/downloads` for the paged log, and
`GET /api/admin/downloads/stream` for a live tail as server-sent events.

The tail takes the same `ecosystem`, `package_name` and `username` filters as
the list, plus `since_id`. Omit `since_id` and it starts from the newest row,
because the page already shows the history and replaying it would duplicate
the table; pass the last id you saw to resume without a gap. Events are
`downloads` (a JSON array of rows), `expired` when the server closes a tail
that has reached its age cap, and `:` comments as keepalives. Reconnect on
`expired`, passing `since_id`.

Eight tails may be open at once; beyond that the endpoint answers `429`. Each
one polls rather than holding a database connection open, so a page left open
costs a query a second, not a connection.

Rows from either carry `max_cvss` and `scanned` for the exact version that was
requested: `max_cvss` is the worst score known to affect that release, and
`scanned` says whether it has been scanned at all, so a release known to be
clean is distinguishable from one nothing has looked at. A request naming no
version -- a metadata lookup -- gets `null` and `false`, rather than the
package's worst score across its history.

**Metrics** — `GET /api/metrics`. Request counts by status class, and counters
for the failures that are otherwise silent: CVE scans that timed out and were
served unscanned, and OSV batches that failed.

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
