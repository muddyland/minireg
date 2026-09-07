# Troubleshooting

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

The groups scope mapping is missing from the Authentik provider. Without it,
group membership never reaches the registry and `OIDC_ADMIN_GROUP` matches
nothing.

Check what actually arrived — the OIDC login audit entry records the groups:

```bash
curl -s -H "authorization: Bearer $TOKEN" \
  "https://registry.example.com/api/admin/audit?action=auth.login.oidc&limit=1" |
  jq '.entries[0].detail'
```

An empty `groups` array confirms it. Add a groups scope mapping to the provider
and include it in the application's scopes.

### SSO redirect fails

The redirect URI must be exactly
`{PUBLIC_URL}/api/auth/oidc/callback` and registered in Authentik verbatim,
including scheme and any port.

### CLI login never completes

- The code expired — they last 10 minutes. Run `minireg login` again.
- You approved a *different* code. Each run generates a new one.
- The CLI cannot reach the registry: `minireg whoami --url https://…` will say
  so.

---

## Performance

### Everything is slow

Check Redis. `/api/health/detailed` reports it. Without Redis there is no
metadata cache and no request coalescing, so every request hits Postgres and
concurrent cold requests each hit the upstream.

### First request for a package is slow

Expected — it fetches from upstream and, with inline scanning on, waits up to 4
seconds for OSV. Subsequent requests come from cache.

To reduce it: lower `OSV_INLINE_TIMEOUT_SECONDS`, or turn off
`OSV_INLINE_SCAN` and rely on the background scan.

### Cache hit rate dropped

- `META_CACHE_TTL` was lowered.
- Redis is evicting under memory pressure — raise `REDIS_MAXMEMORY`.
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
- The advisory has no CVE alias. GHSA-only and MAL-only records are ignored by
  design (`OSV_CVE_ONLY`).
- OSV genuinely has nothing for that version.

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

**Packages → Purge cache** for that package.

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
