# Troubleshooting

Symptoms and their causes, ordered roughly by how often they come up.

## Start here

```bash
docker compose ps                        # all three healthy?
docker compose logs --tail=100 minireg  # what did it say?
curl -fsS http://localhost:8000/api/health/detailed | jq
```

Then check **Upstreams → Health** and **Audit log** in the UI. Most problems
have already explained themselves in one of those two places.

---

## Installs fail

### `404` for a package that definitely exists

1. **Is an upstream configured for that ecosystem?** A registry with no npm
   upstream serves only locally published npm packages. **Upstreams** should
   list at least one enabled entry per ecosystem you use.
2. **Are they all quarantined?** Five consecutive failures marks an upstream
   unhealthy; it is retried every 2 minutes. The **Health** column shows the
   last error. Hit *Test*.
3. **Is the name right?** PyPI normalizes names (PEP 503): `Foo.Bar`,
   `foo-bar`, and `foo_bar` are one project. npm is case-sensitive for display
   but lowercase for lookup.

### `403` with a message

Policy did that, and the message says which. Confirm with **Package policy →
Test a package against the policy** — it names the rule.

If it is the CVE policy, **Vulnerabilities** shows which CVE pushed the version
into the blocked range.

### `ETARGET`, "No matching version found", "Could not find a version"

```
npm error code ETARGET
npm error notarget No matching version found for lodash@4.17.20.
ERROR: Could not find a version that satisfies the requirement requests==2.19.0
error: failed to select a version for the requirement `time = "=0.3.20"`
```

The version almost always exists upstream: it is **blocked by policy** — a
CVE score in the blocked range, a version-range block rule, or allowlist mode
— and blocked versions are left out of the metadata the registry serves (cargo
sees them as yanked). The client therefore reports "no such version" rather
than a `403`. Pins and lockfiles written against public npm or PyPI hit this
first.

To see which versions are blocked and why:

- **The package page in the web UI** (**Search**, then the package) marks
  every blocked version with a **blocked** badge and the reason.
- **`minireg info <package>`** lists the blocked versions with their reasons
  and the versions that carry CVEs (it looks in npm, PyPI and cargo unless
  you pass `--ecosystem`), and `minireg audit` checks a whole lockfile
  against the policy.

Then upgrade to an allowed version, or ask an admin for a rule change or a
risk acceptance.

A package blocked outright by name does not appear in **Search** for
non-admins (see [Browsing](usage.md#browsing)). Installing it fails with a
`403` whose message names the reason, and `minireg info <name>` or opening
`/packages/<ecosystem>/<name>` in the web UI shows it as well.

### `401` on install

- `ALLOW_ANONYMOUS_READ=false` and the client sent no token.
- The npm `_authToken` key does not match the registry **host and path**:

  ```ini
  # correct
  //registry.example.com/npm/:_authToken=mrg_…
  # wrong — missing the /npm/ path
  //registry.example.com/:_authToken=mrg_…
  ```
- The token was revoked. Check **API tokens**.

### Metadata resolves but downloads fail

`PUBLIC_URL` does not match the address the client uses. The packument is
correct; the tarball URLs inside it point somewhere unreachable.

```bash
curl -s https://registry.example.com/npm/lodash | jq -r '.versions["4.17.21"].dist.tarball'
```

If that host or port is not what your clients use, fix `PUBLIC_URL` and
restart.

### pip finds no versions at all (pip older than 22.2)

```
ERROR: Could not find a version that satisfies the requirement requests (from versions: none)
```

pip before 22.2 — Ubuntu 22.04 ships 22.0.2 — accepts a simple page only
when it is labelled `text/html`. Earlier releases of this registry labelled it
`application/vnd.pypi.simple.v1+html`, which such a pip discards without
complaint, so every project appeared to have no versions. The registry now
answers `text/html` unless a client asks for the PEP 691 type by name, so
upgrading the registry fixes it. To see what a client gets:

```bash
curl -sI https://registry.example.com/pypi/simple/requests/ | grep -i content-type
```

If that says `text/html` and pip still sees nothing, check for a caching proxy
in front that ignores `Vary: Accept`.

### An internal upstream stopped resolving after an upgrade

Metadata requests now obey `UPSTREAM_ALLOW_PRIVATE_ADDRESSES` and
`UPSTREAM_ALLOW_PLAINTEXT_HTTP`, as artifact downloads already did. An
upstream on a private address or plain `http://` shows as unhealthy, and the
log has a line such as `upstream gitlab: refused …: 'gitlab.internal'
resolves to a private or link-local address`. Set the flag that applies. See
[Upstream trust](configuration.md#upstream-trust).

### npm ignores the registry

A closer `.npmrc` wins. `npm config list` shows which file provided each
setting. Project-level beats user-level beats global.

### cargo tries to clone the index

```
error: failed to load source for dependency `serde`
Caused by: Unable to update registry `minireg`
```

The `sparse+` prefix is missing from the registry URL. Without it cargo treats
the URL as a **git** index and tries to clone it. The value must be
`sparse+https://…/cargo/index/`, prefix and trailing slash both.

### Every crate 404s but `config.json` works

The trailing slash is missing from the index URL. Cargo joins the shard path
against the last segment, so `…/cargo/index` + `se/rd/serde` resolves to
`…/cargo/se/rd/serde`. Add the slash.

### `checksum for X did not match what is in Cargo.lock`

Source replacement requires the replacement to serve the *same bytes* as
crates.io, which a caching mirror does. If this appears, the mirror served
something else — check the registry logs for a digest-mismatch 502, which is
what it emits when an upstream hands it an artifact whose hash disagrees with
the `cksum` in the index.

If it appears only for a crate that is **not** on crates.io, that crate cannot
be resolved through a replaced source at all — see
[why cargo is read-only](usage.md#why-cargo-is-read-only).

### `registry does not support API commands`

Expected. This is a read-only mirror: `cargo publish`, `cargo yank`,
`cargo search` and `cargo login` are not implemented, and `config.json` omits
the `api` key so cargo says so up front rather than failing deeper in.

### `ECONNREFUSED` / `ETIMEDOUT` behind a proxy

Package tarballs are large. If nginx has a default `client_max_body_size`,
publishes fail; if `proxy_read_timeout` is short, large downloads truncate. See
[Installation](installation.md#behind-a-reverse-proxy).

---

## Publishing fails

### npm: `400` with `integrity mismatch` or `shasum mismatch`

The `dist` the client declared does not describe the tarball it uploaded:
something changed the package between `npm pack` and the upload. Pack and
publish again from a clean tree. The registry refuses rather than correcting
it, because a lockfile written against the declared digest would fail later
with `EINTEGRITY`.

### `409 Conflict`

That version already exists. Registries never overwrite a published version.
Bump it.

### `403` on publish

- The token lacks the `publish` scope, or the account is not permitted to
  publish (**Users**).
- The package name is blocked. Blocks apply to publishing so a blocked name
  cannot be squatted locally.
- CVE policy is enforcing and the version scores inside the blocked range.

### npm asks for a password

Password authentication is refused for publishing, deliberately. Create a token
and set `_authToken`. `npm login` will print the same instruction.

### twine: `400 File already exists`

PyPI semantics — the same filename is never accepted twice, even after a
delete. Rebuild with a new version.

### twine: `filename does not match the declared project name`

The distribution filename must agree with the metadata. Usually a stale `dist/`
directory:

```bash
rm -rf dist/ && python -m build
```

---

## Authentication

### The generated admin password is not in the logs

Only printed when `BOOTSTRAP_ADMIN_PASSWORD` is blank, and only on the run that
created the account. If it has scrolled away and you cannot sign in, reset it
directly:

```bash
docker compose exec minireg python -c "
from app.core.security import hash_password
print(hash_password('new-password-at-least-12-chars'))"

docker compose exec postgres psql -U minireg -d minireg -c \
  \"update users set password_hash='<paste the hash>' where username='admin'\"
```

### SSO signs in but nobody is an admin

Either no groups reached the registry, or they arrived under names that do not
look like the one configured. Check what actually arrived first — the OIDC
login audit entry records the groups:

```bash
curl -s -H "authorization: Bearer $TOKEN" \
  "https://registry.example.com/api/admin/audit?action=auth.login.oidc&limit=1" |
  jq '.entries[0].detail'
```

An **empty `groups` array** means the provider is not sending them. On Kanidm
the `groups` scope is missing from `OIDC_SCOPES` or from the client's scope
map; on Authentik the provider has no groups scope mapping, or the application
does not include it.

**Groups present but still nobody is an admin** means the names do not match.
Kanidm sends SPNs (`minireg-admins@idm.example.com`) and group UUIDs, so an
`OIDC_ADMIN_GROUP` of `minireg-admins` matches the SPN, but one written for a
*different* realm matches nothing — a configured SPN is compared whole.
Matching is exact either way: `admins` never matches `not-admins`.

### SSO fails with HTTP 401 at the token endpoint

This reads like a wrong client secret and usually is not. Some providers
(Kanidm) accept only HTTP Basic at the token endpoint, and answer a
body-posted secret with the same 401 as a bad one. minireg reads
`token_endpoint_auth_methods_supported` from the discovery document and uses
Basic unless the provider says otherwise. The browser shows only a generic
"single sign-on failed"; the server log line `OIDC callback failed:` and the
`auth.login.failed` audit entry carry the provider's response and name the
method that was used — check that before rotating anything.

### SSO redirect fails

The redirect URI must be exactly
`{PUBLIC_URL}/api/auth/oidc/callback` and registered at the provider verbatim,
including scheme and any port.

### `403 cross-site request refused`

A write (`POST`, `PUT`, `PATCH`, `DELETE`) carried the session cookie but did
not come from the registry's own pages: the browser marked it cross-site, or
its `Origin` or `Referer` is not `PUBLIC_URL`. If it came from the web UI
itself, `PUBLIC_URL` does not match the address in the browser's address bar.
If it came from a script, use an API token instead of a session cookie.

### `403` listing or revoking tokens with a token

Listing, creating and revoking tokens needs a browser session or an
admin-scoped token. A `read` or `publish` token is refused there on purpose.

### CLI login never completes

- The code expired — they last 10 minutes. Run `minireg login` again.
- You approved a *different* code. Each run generates a new one.
- The CLI cannot reach the registry: `minireg whoami --url https://…` will say
  so.

---

## Performance

### Everything is slow

Check Valkey. `/api/health/detailed` reports it. Without Valkey there is no
metadata cache and no request coalescing, so every request hits Postgres and
concurrent cold requests each hit the upstream. An outage does not add a
timeout to every request: the app backs off from Valkey for 2–30 seconds at a
time and reconnects on its own, and the log says `cache unreachable`.

### First request for a package is slow

Expected — it fetches from upstream and, with inline scanning on, waits up to 4
seconds for OSV. Subsequent requests come from cache.

To reduce it: lower `OSV_INLINE_TIMEOUT_SECONDS`, or turn off
`OSV_INLINE_SCAN` and rely on the background scan.

### Cache hit rate dropped

- `META_CACHE_TTL` was lowered.
- Valkey is evicting under memory pressure — raise `REDIS_MAXMEMORY`.
- Traffic genuinely shifted to packages that were not cached.

### The database is growing

Almost always `download_log`. Check retention:

```sql
select pg_size_pretty(pg_total_relation_size('download_log'));
```

Lower `DOWNLOAD_LOG_RETENTION_DAYS`; the hourly task prunes on the next run.

---

## Data

### A CVE score looks wrong

Scores come from the CVSS vectors OSV publishes. v3 is computed exactly; **v4
is approximated** because its real model is a lookup table. When a record has
both, v3 is used.

After any scoring change, **Vulnerabilities → Recompute scores** re-scores
stored records without re-fetching. If a score still looks wrong, compare
against the vector:

```sql
select cve_id, severity_type, cvss_score, cvss_vector
from vulnerabilities where cve_id = 'CVE-2024-12345';
```

### A package shows no CVEs but should

- It has never been scanned — **Vulnerabilities → Scan new versions**.
- The advisory has no CVE alias and `OSV_CVE_ONLY` is on. It defaults to off.
  Malicious-package records (`MAL-*`) are kept either way and scored critical,
  so this never hides malware.
- OSV genuinely has nothing for that version.

A version that was scanned and found clean and one that could not be scanned
are different states, and the admin UI shows which. Only the second is
affected by **Block versions that could not be scanned**.

### Versions disappeared after an upstream change

Deleting an upstream removes every cached version only it supplied — see
[Changing, disabling and deleting upstreams](configuration.md#changing-disabling-and-deleting-upstreams).
The `admin.upstream.deleted` audit entry records `retired_versions`. Disabling
one removes nothing.

Versions also go when a higher tier starts answering for a name, with at least
one version, and does not list them. The log line is
`pruned N version(s) of …`.

### Package count jumped into the hundreds of thousands

Somebody clicked **Index** on an unscoped public upstream, importing every
project name. The audit log has it:

```bash
curl -s -H "authorization: Bearer $TOKEN" \
  "https://registry.example.com/api/admin/audit?action=admin.upstream.indexed" | jq
```

Those are name-only rows for search. The Dashboard counts them separately from
packages with real content.

---

## Recovery

### Corrupt or missing artifact

The blob store is content-addressed and every download is verified against the
digest the upstream advertised, so corruption is caught rather than served. If
a file is missing, purge it and let it re-download:

**Manage packages → Purge cache** for that package.

### Reset everything except data

```bash
docker compose down
docker compose up -d --build
```

### Start completely fresh

```bash
docker compose down -v      # deletes the database and every cached artifact
docker compose up -d --build
```

Locally published packages are not recoverable this way. Restore from backup.

### The app will not start

```bash
docker compose logs minireg | tail -50
```

| Message | Cause |
|---|---|
| `required variable SECRET_KEY is missing` | No `.env`, or the key is unset |
| `could not translate host name "postgres"` | Postgres is not up; check `docker compose ps` |
| `password authentication failed` | `POSTGRES_PASSWORD` changed after the volume was created. Either restore the old value or `docker compose down -v` |
| Permission errors on `/data` | The storage volume is owned by the wrong uid; the container runs as uid 10001 |

---

## Reporting a problem

Include:

```bash
docker compose logs --tail=200 minireg
curl -s http://localhost:8000/api/health/detailed | jq
docker compose exec minireg python -c "
from app.config import settings
print('public_url', settings.public_url)
print('oidc', settings.oidc_enabled)
print('osv', settings.osv_enabled, settings.osv_inline_scan)
print('anon_read', settings.allow_anonymous_read)"
```

Never paste `.env` — it has your secrets.
