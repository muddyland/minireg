# Architecture

```
                     ┌──────────────────────────────┐
   npm ──────────────▶│  FastAPI                     │
   pip / uv / poetry  │    /npm/*    registry API    │
   twine              │    /pypi/*   simple + upload │
   minireg CLI       │    /api/*    web + admin     │
   browser            │    /         Vue SPA         │
                     └───┬──────────────┬───────────┘
                         │              │
              ┌──────────▼───┐   ┌──────▼──────────┐
              │ PostgreSQL   │   │ Redis           │
              │ metadata     │   │ hot metadata    │
              │ policy, CVEs │   │ locks, limits   │
              │ audit, stats │   │ (optional)      │
              └──────────────┘   └─────────────────┘
                         │
              ┌──────────▼────────────┐        ┌──────────────┐
              │ content-addressed     │        │  upstreams   │
              │ blob store (/data)    │◀───────│ npm, PyPI,   │
              └───────────────────────┘  fetch │ GitLab       │
                                                └──────────────┘
```

One container serves the registry APIs, the admin API, and the built SPA.
Postgres holds everything except artifact bytes; Redis is an accelerator;
artifacts live on disk keyed by content hash.

---

## Why these components

**PostgreSQL.** The read path needs one indexed lookup to render a packument,
JSONB to store upstream documents verbatim (which matters for serving npm
metadata back 1:1), trigram indexes for substring search without a full scan,
and cheap append-only writes for the download log. Postgres does all four well.
The append-only tables use BRIN indexes on their timestamps — roughly a
thousandth the size of a b-tree for a monotonic column.

**Redis.** Caches rendered documents with a short TTL, which absorbs a CI fleet
asking for the same hundred packages at once. It also provides the distributed
lock that collapses concurrent cold-cache fetches into one upstream request,
and the rate limiter. Everything degrades to a no-op when Redis is unavailable:
the registry gets slower, not broken.

**Local disk, content-addressed.** Artifacts are immutable, so the SHA-256 of
the bytes *is* the identity. Two packages shipping byte-identical files store
one copy.

---

## Request paths

### Metadata

```
request
  → policy: is the name blocked?           (before any network access)
  → Redis: rendered document?              short TTL
  → Postgres: local rows, fresh?           local publishes never go stale
  → upstream resolver                      tiered, raced
  → persist
  → CVE scan for unseen versions           bounded, inline
  → render + filter blocked versions
  → cache + serve
```

The block check runs **before** the upstream fetch, so a blocked package never
generates outbound traffic.

### Artifact

```
request
  → policy: blocked package or version?
  → blob store: present?                   serve immediately
  → herd guard                             one fetch, not N
  → upstream fetch (streamed)
  → verify every advertised digest
  → store atomically
  → serve
```

A digest mismatch is treated as a poisoned upstream: the bytes are discarded
and the request fails loudly rather than caching bad content.

---

## Upstream resolution

```
local (published here)     authoritative, never hits the network
tier 1 upstreams (raced)   first success wins
tier 2 upstreams (raced)
…
404
```

- A 404 from one upstream is authoritative **for that upstream only**.
- Five consecutive failures quarantine an upstream; a probe every 2 minutes
  makes recovery automatic.
- **PyPI merges within the winning tier** — the Simple API is file-oriented and
  a project's files can legitimately be split across indexes. Earlier tiers win
  filename collisions.
- **npm does not merge** — a packument is a single authoritative document.
- Locally published versions are never overwritten by upstream data, so a
  private package shadowing a public name keeps its own content.

---

## Data model

| Table | Holds |
|---|---|
| `users`, `api_tokens` | Identity. Tokens stored as SHA-256 of the secret half |
| `device_authorizations` | In-flight CLI logins. Short-lived |
| `upstreams` | Remote registries, credentials encrypted at rest |
| `packages` | One row per name per ecosystem, plus the cached upstream document |
| `package_versions` | Per-version metadata, CVE verdict, scan time |
| `package_files` | Distributable artifacts, digests, blob pointer |
| `dist_tags` | npm dist-tags |
| `blobs` | Content-addressed store entries, refcounted |
| `package_rules` | Allow/block rules |
| `vulnerabilities` | CVE records from OSV, with the raw document |
| `package_vulnerabilities` | Version ↔ CVE, with the fixed version |
| `settings` | Runtime-editable policy |
| `audit_log` | Every login and admin action. Append-only |
| `download_log` | Every package request. Append-only, no foreign keys |

`download_log` carries no foreign keys deliberately: it is the highest-volume
table and referential checks on insert would be pure overhead for data that is
only ever aggregated.

### Denormalization

`package_versions.max_cvss` is denormalized from `package_vulnerabilities` so
the policy engine can decide without a join on every request. It is recomputed
by a scan, or by **Recompute scores**.

---

## Performance decisions

**Rendered documents are cached, not just source rows.** A large packument
costs real CPU to serialize; caching the finished bytes skips that entirely.

**Policy is baked into the cached document.** Blocked versions are filtered out
before caching, so the hot path does no policy work. The cost is that a policy
change must invalidate the rendered cache — which it does.

**Download logging is batched.** Every metadata hit from every CI job would be
a synchronous INSERT otherwise. Events go through a bounded in-process queue
drained every 2 seconds. Under extreme load a dropped row is preferable to
slowing every download.

**Digests are computed in one pass.** sha256, sha1, md5, blake2b, and sha512
are all computed while streaming, because npm needs sha1, PyPI needs sha256,
and legacy uploads carry md5/blake2b.

**Connection reuse.** One pooled HTTP client process-wide. The single biggest
win when a fleet asks for hundreds of packages at once.

---

## Security decisions

| Decision | Reason |
|---|---|
| Argon2id for passwords | Memory-hard |
| Tokens stored as SHA-256 of the secret; public prefix indexed | O(1) lookup with one constant-time compare, no per-row hashing |
| An `Authorization` header is authoritative | A revoked token must not appear to work because a browser session exists |
| Upstream credentials encrypted at rest, never returned | The API can say *whether* one is set, never what it is |
| Publishing always requires a token | Passwords are refused for publishing |
| Digests verified before serving | A compromised upstream cannot poison the cache |
| Login limited per IP **and** per username | Neither a single source nor a single account can be brute-forced |
| CLI login via device authorization | No password reaches the terminal; SSO works unchanged |
| Blocks enforced on metadata, artifacts, and publish | No path bypasses policy |

---

## Known limitations

**CVSS v4 is approximated.** v4 scores via a 270-entry macrovector lookup table
that cannot be reproduced from equations. When a record publishes both v3 and
v4, v3 is used because it is computed exactly. A v4 vector declaring any impact
never scores below 2.0, so an approximation error cannot present a real
vulnerability as harmless.

**No migration framework.** Tables are created at startup and new *additive*
columns are applied from a list in `backend/app/db.py`. Anything destructive
would need to be handled manually.

**The PyPI simple index lists only known projects.** Enumerating an upstream's
entire index on demand would be enormous and is not something pip needs. Use
**Upstreams → Index** to populate search.

**npm search is local-first.** The public registry's search endpoint is queried
only when explicitly requested, because it is slow and rate-limited.

**Yanked npm versions.** npm has no yank concept — only unpublish and
deprecate — so `yanked` is PyPI-only.

---

## Layout

```
backend/app/
  api/            HTTP layer
    npm.py        npm registry endpoints
    pypi.py       PyPI endpoints
    auth.py       login, tokens, OIDC
    cli.py        device auth, audit, CLI distribution
    search.py     user-facing search
    admin/        admin API
  core/
    naming.py     PEP 503/440, npm names, filename grammar
    semver.py     node-semver versions and ranges
    security.py   hashing, tokens, JWTs, credential encryption
    deps.py       identity resolution, RBAC, rate limiting
    cache.py      Redis, herd guard, rate limiter
  services/
    resolver.py   tiered upstream routing
    packages.py   persistence and the shared read path
    artifacts.py  fetch, verify, cache
    storage.py    content-addressed blob store
    policy.py     allow/block and CVE policy
    osv.py        OSV scanning and CVSS scoring
    provenance.py which upstreams have a package
    npm_render.py, npm_publish.py
    pypi_render.py, pypi_publish.py
    oidc.py, audit.py
  upstreams/      provider implementations
  models.py       SQLAlchemy models
cli/minireg.py   the CLI, served from /api/cli/download
frontend/src/     Vue 3 SPA
```

---

## Tests

```bash
cd backend && .venv/bin/python -m pytest
```

| File | Covers |
|---|---|
| `test_naming.py` | PEP 503/440, wheel and sdist filenames, npm names |
| `test_semver_ranges.py` | node-semver, run against npm's own fixtures |
| `test_npm_spec.py` | Packument formats, publish document grammar |
| `test_pypi_spec.py` | PEP 503/592/691/700/714, upload validation |
| `test_osv.py` | CVSS scoring against published reference vectors |
| `test_upstreams.py` | Provider parsing, GitLab addressing, tier grouping |
| `test_proxy.py` | The full proxy path against mocked upstreams |
| `test_integration.py` | Request-level: auth, publish, policy, admin |
| `test_version_policy.py` | Version-scoped blocking end to end |
| `test_provenance.py` | Upstream attribution and link derivation |
| `test_cli.py` | Device flow, audit, lockfile parsers |

Spec compliance is tested against the specs' own examples where they publish
them — node-semver's fixture tables, the FIRST.org CVSS reference vectors, and
the PEP-documented formats — rather than against our own reading of them.
