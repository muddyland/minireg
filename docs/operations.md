# Operations

Running the registry day to day: what to watch, what to back up, and what to
tune when it is slow.

## Watching traffic

**Package requests** in the admin UI lists every metadata lookup and artifact
download, with the user, the address, the size and whether it was a cache hit.
Turning on **Live** tails it as requests arrive, which is the quickest way to
see what a CI fleet is actually pulling, or to confirm a client is pointed
here at all.

The tail is server-sent events over the same connection the UI already uses.
It needs no extra port, but it does need a proxy that will not buffer the
response -- the shipped nginx config sets `proxy_buffering off`, and the
endpoint also sends `X-Accel-Buffering: no` for configs that do not.

## Health

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness. Used by the container healthcheck |
| `GET /api/health/detailed` | Database, Valkey, and storage status |

```bash
curl -fsS https://registry.example.com/api/health/detailed | jq
```

`degraded` means the database or storage is unreachable — the registry cannot
serve. Valkey being down reports `ok` overall, because it is an accelerator: the
registry gets slower, not broken. While it is unreachable the app stops asking
it for 2 seconds at a time, doubling up to 30, rather than paying a connection
timeout on every call, and reconnects on its own once it is back. The login
throttle keeps working through an outage on an in-process counter.

The **Dashboard** shows the same information plus upstream health.

---

## What runs in the background

An hourly loop inside the app handles:

| Task | What it does |
|---|---|
| Log retention | Prunes `download_log` and `audit_log` past their retention windows |
| Orphan collection | Deletes blobs no package file references, and blob files with no database row once they are 24 hours old |
| Quota | With `STORAGE_QUOTA_BYTES` set, evicts cached upstream artifacts back down to 90% of it. See [Eviction](#eviction) |
| Temp cleanup | Removes staging files orphaned by a crash |
| Container images | Garbage collection, eviction, watched tags, and the `orphans` step, which reconciles image blob files that have had no database row for 6 hours (see [Container images](containers.md#storage)) |
| CVE refresh | Re-scans versions older than `OSV_REFRESH_INTERVAL_SECONDS`, and drops the cached rendered documents of every package whose verdict changed |

The first run is delayed 60 seconds so a restart storm does not converge. Each
pass takes a renewable lease in Valkey, so only one replica runs it at a time.

---

## Storage

Artifacts are content-addressed by SHA-256, with a two-level directory fan-out:

```
/data/packages/blobs/ab/cd/abcd…    the artifact
/data/packages/tmp/                 staging
/data/packages/partial/             downloads in progress that clients are reading
```

Two packages shipping byte-identical files store one copy. **Storage** shows
how much that saves.

Writes stage to a temp file on the same filesystem and `os.replace` into place,
so a crash or a concurrent write can never expose a truncated artifact.

A cold artifact whose download is still running after about 5 seconds is
streamed to the client while it downloads, provided the upstream announced
its length; concurrent requests for it, from any replica, share that one
download through `partial/`. The digest is verified before the final bytes are
released. On a mismatch the connection is cut, so the client sees a failed
download rather than a truncated "success", and nothing is cached. Smaller or
faster downloads are verified in full before the first byte is sent, as
before.

### Eviction

**Storage → Purge cached artifacts.** Filter by ecosystem, age, and whether
anything ever downloaded it.

Evicted artifacts re-download from their upstream on next request. **Files
published directly to this registry are never evicted** — there is nowhere to
fetch them from.

With `STORAGE_QUOTA_BYTES` set, eviction is also automatic. When a download
would take the store over the quota, and again at each housekeeping pass, the
least recently accessed cached upstream artifacts are evicted until usage is
back to 90% of it. Artifacts read in the last 10 minutes are spared, and so
are artifacts from a disabled upstream, which cannot be fetched again while it
is paused. A
download fails only when nothing evictable is left. Before this release,
reaching the quota failed every uncached download until someone purged by
hand.

### Garbage collection

**Storage → Run garbage collection** removes orphaned blobs and stale temp
files. Runs hourly anyway; the button is for when you have just deleted a lot.

### Capacity

Rough numbers for a mirror serving a mid-sized organisation:

| Packages cached | Disk |
|---|---|
| 1,000 | 2–5 GB |
| 10,000 | 20–50 GB |
| 100,000 | 200–500 GB |

Highly variable — a few ML wheels will outweigh thousands of npm packages.
Watch the trend on **Storage** rather than trusting a table.

---

## Monitoring

Worth alerting on:

| Signal | Where | Alert when |
|---|---|---|
| Upstream health | Dashboard, `/api/admin/upstreams` | Any enabled upstream unhealthy |
| Disk free | `/api/health/detailed` → `storage.disk_free` | Below 15% |
| Cache hit rate | Dashboard | Sustained drop — usually a `META_CACHE_TTL` or Valkey problem |
| Failed logins | Audit log, `auth.login.failed` | Spike |
| Valkey | `/api/health/detailed` | Down (degrades performance) |

```bash
# Unhealthy upstreams
curl -s -H "authorization: Bearer $TOKEN" \
  https://registry.example.com/api/admin/upstreams |
  jq '[.upstreams[] | select(.enabled and (.healthy | not))]'
```

---

## Backups

Three things matter, in order:

### 1. The database

Everything except artifact bytes: users, tokens, policy, CVE data, audit log.

```bash
docker compose exec -T postgres \
  pg_dump -U minireg -Fc minireg > minireg-$(date +%F).dump
```

Restore:

```bash
docker compose exec -T postgres \
  pg_restore -U minireg -d minireg --clean --if-exists < minireg-2026-08-15.dump
```

### 2. Locally published artifacts

**These cannot be recovered from an upstream.** Everything else in the blob
store can be re-fetched; anything published directly here cannot.

```bash
docker run --rm -v minireg_package-storage:/data:ro \
  alpine tar czf - -C /data . > minireg-storage-$(date +%F).tar.gz

# Always check it actually contains something.
tar tzf minireg-storage-$(date +%F).tar.gz | head
```

Restore:

```bash
docker compose stop minireg
docker run --rm -i -v minireg_package-storage:/data \
  alpine sh -c 'rm -rf /data/* && tar xzf - -C /data' < minireg-storage-2026-08-15.tar.gz
docker compose start minireg
```

This streams through stdout rather than bind-mounting a host directory into the
container. That is deliberate: where the Docker daemon has a different
filesystem view from your shell — Docker Desktop, rootless, a remote or
VM-backed daemon — a bind mount to a host path can silently write into the
daemon's namespace instead, and you get an empty backup with no error at all.
Streaming has no such failure mode, which is why the verification step above is
worth keeping anyway.

### 3. `.env`

Losing `SECRET_KEY` logs everyone out. Losing `CREDENTIAL_KEY` (or `SECRET_KEY`
when `CREDENTIAL_KEY` is derived from it) makes stored upstream credentials
undecryptable and they must be re-entered. Keep it in your secret manager.

### Restore drill

Restoring the database without the storage volume leaves rows pointing at blobs
that are gone. Locally published packages 404; cached upstream packages
re-download silently. If you only back up one thing, back up the database — but
test the pair together at least once.

---

## Scaling

Run one worker per container and scale with replicas. The download-log batcher
is per-process. Housekeeping runs in every process but takes a lease in Valkey
first, so one pass runs at a time across all replicas; without Valkey each
process runs its own.

```yaml
minireg:
  deploy:
    replicas: 3
```

All replicas share the database, Valkey, and the storage volume — which must be
a shared filesystem (NFS, EFS) for multi-host deployments.

Valkey matters more as you scale: it holds the distributed lock that collapses
concurrent cold-cache fetches into one upstream request. Without it, N replicas
make N upstream requests for the same cold package. Long artifact downloads
hold a lease that is renewed while they run, so a multi-minute download is
never started a second time by another replica half way through.

Postgres connections: each replica opens up to `DB_POOL_SIZE + DB_MAX_OVERFLOW`
(default 40). Three replicas need 120, plus headroom. Raise
`max_connections` or lower the pool.

---

## Performance tuning

### Metadata cache TTL

`META_CACHE_TTL` (default 60s) is the main lever.

| Value | Trade |
|---|---|
| 30s | Fresher, more upstream traffic |
| 60s | Default |
| 300s | Much less upstream traffic; new versions take up to 5 min to appear |

Locally published packages are authoritative and never go stale regardless.

A refresh after the TTL is a conditional request to the upstream that served
the document (`If-None-Match` / `If-Modified-Since`). An unchanged document
costs one round trip and a `304`, not a re-download, and when it has changed
only the versions that differ are rewritten. A PyPI page merged from several
upstreams has no single validator and is always refetched in full.

Rendered npm packuments over 1 MiB are not stored in Valkey; they are
rendered from the database on each request.

### Upstream racing

`UPSTREAM_TIER_PARALLEL=true` (default) races every upstream in a tier and
takes the first success. Lower latency, more upstream requests. Turn it off if
an upstream rate-limits you.

### Inline CVE scanning

`OSV_INLINE_SCAN=true` scans a version the first time it is served, within a
4-second budget. If OSV latency is hurting first-request times, either lower
`OSV_INLINE_TIMEOUT_SECONDS` or turn inline scanning off and rely on the hourly
background scan — versions are then briefly unscanned, which matters only if
you have fail-closed on.

### Postgres

The compose defaults suit a modest host. On a dedicated database machine:

```
shared_buffers      = 25% of RAM
effective_cache_size = 75% of RAM
work_mem            = 16MB
```

The download log is the table that grows. `DOWNLOAD_LOG_RETENTION_DAYS`
controls it; it is BRIN-indexed on time, so pruning is cheap.

---

## Audit log

Every login and administrative action, append-only.

**Audit log** in the UI, filterable by action, user, outcome, and window.
Expand a row for the full JSON detail.

Actions worth knowing:

| Action | Meaning |
|---|---|
| `auth.login.success` / `.failed` | Web sign-in |
| `auth.login.oidc` | SSO sign-in, with the groups that were applied |
| `auth.cli.approved` / `.denied` | CLI device authorization |
| `auth.token.created` / `.revoked` | API token lifecycle |
| `admin.user.*` | User management |
| `admin.upstream.*` | Upstream changes, including `indexed` |
| `admin.rule.*` | Policy rule changes |
| `admin.setting.updated` | CVE policy, allowlist mode |
| `admin.package.deleted` | Package deletion |
| `admin.cache.purged` | Cache eviction |
| `registry.publish` | A package version was published |
| `registry.publish.denied` | A publish was refused by policy |

Export:

```bash
curl -s -H "authorization: Bearer $TOKEN" \
  "https://registry.example.com/api/admin/audit?days=90&limit=1000" | jq
```

Set `AUDIT_LOG_RETENTION_DAYS` to match your compliance requirements before you
need it, not after.

---

## Common tasks

### Rotate a compromised token

**API tokens**, revoke it. Effective immediately — the next request with it
fails. Then issue a replacement.

### Remove a package entirely

**Manage packages → Delete**. For an upstream package this only clears local state; it
re-downloads on next request. Block it if you want it gone for good.

For a locally published package, deletion is permanent.

### Force a re-scan

**Vulnerabilities → Rescan all** re-queries OSV.
**Vulnerabilities → Recompute scores** re-scores stored records without any
network access — use it after a scoring change. Both drop the cached
documents of every package whose verdict changed, so the new verdict is
served at once.

### Index an upstream for search

**Upstreams → Index**. For a scoped GitLab registry this is quick and useful.
For public PyPI it imports ~870,000 bare project names; the UI warns you first.
Metadata is still fetched on demand — the names only populate search.

### Move to a new host

1. Back up the database and the storage volume.
2. Copy `.env`, updating `PUBLIC_URL` if the address changed.
3. Restore both on the new host.
4. `docker compose up -d --build`.

If `PUBLIC_URL` changed, every cached packument holds old tarball URLs. They
expire within `META_CACHE_TTL`. Restarting the app does not clear them, because
they live in Valkey, a separate container; flush it to clear them at once:

```bash
docker compose exec redis valkey-cli FLUSHDB
```
