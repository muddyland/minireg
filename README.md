# minireg

A caching **npm**, **PyPI** and **cargo** package registry with tiered
upstreams, OIDC single sign-on, CVE-based blocking, an admin UI, and a CLI.

The npm and PyPI APIs are implemented to spec, including publishing, so the
real clients work unmodified: `npm install`, `npm publish`, `pip install`,
`twine upload`, `uv`, and `poetry`. Cargo is supported as a **read-only
mirror** — see [Spec compliance](#spec-compliance) for why publishing is not
part of it.

```bash
cp .env.example .env     # set SECRET_KEY and PUBLIC_URL
docker compose up -d --build
```

Then [read the setup guide](docs/installation.md).

---

## Documentation

| | |
|---|---|
| **[Installation](docs/installation.md)** | Requirements, first run, reverse proxies, upgrading |
| **[Configuration](docs/configuration.md)** | Every environment variable, upstreams, users, OIDC |
| **[Using the registry](docs/usage.md)** | npm, pip, uv, poetry, twine, CI |
| **[The CLI](docs/cli.md)** | Install, login, configure, audit |
| **[Package policy](docs/policy.md)** | Block rules, version ranges, CVE thresholds |
| **[Operations](docs/operations.md)** | Monitoring, backups, scaling, tuning |
| **[Troubleshooting](docs/troubleshooting.md)** | When something does not work |
| **[API reference](docs/api.md)** | Every endpoint |
| **[Architecture](docs/architecture.md)** | How it works and why |

---

## What it does

- **Caches** packages from upstream registries onto local disk. Artifacts are
  content-addressed and immutable, so identical files are stored once and
  served without re-fetching.
- **Tiers upstreams.** Any number per ecosystem, grouped into tiers. Tier 1 is
  exhausted before tier 2; within a tier the upstreams are raced and the first
  success wins. A failing upstream is quarantined and recovers on its own.
- **Publishes.** `npm publish` and `twine upload` work against it, gated on an
  API token, and can be mirrored to a GitLab package registry. Cargo is
  read-only.
- **Indexes GitLab.** A GitLab npm or PyPI registry can be an upstream for
  reads, a publish target, or both.
- **Scans for CVEs** against [OSV.dev](https://osv.dev) — CVE records only. New
  versions are scanned inline, before they are served.
- **Blocks packages** by name glob, by version range, or by CVSS score range.
  Enforced on metadata, downloads, and publishes, without exception.
- **Audits everything.** Every login and admin action is recorded; every
  package request is logged with user, IP, size, and cache outcome.
- **Ships a CLI** that configures your package managers, audits a project's
  lockfile against the same CVE data the registry blocks with, and can rewrite
  your dependency declarations to versions that clear the findings.

---

## Configure a client

The **Client setup** page generates these with your URL filled in. The short
version:

```bash
# The CLI does all of this for you
curl -fsSL https://registry.example.com/api/cli/install.sh | sh
minireg login && minireg configure
```

```bash
# npm, by hand
npm config set registry https://registry.example.com/npm/
npm config set //registry.example.com/npm/:_authToken "<token>"

# pip, by hand
pip config set global.index-url https://registry.example.com/pypi/simple/
```

```toml
# cargo, by hand — ~/.cargo/config.toml
[source.crates-io]
replace-with = "minireg"

[source.minireg]
registry = "sparse+https://registry.example.com/cargo/index/"
```

> **`PUBLIC_URL` must match the address clients actually use.** Every tarball
> and file URL is rendered against it, so if it is wrong the metadata looks
> perfect while installs fail.

---

## Spec compliance

**npm** — packuments (full and abbreviated), version documents, tarballs,
publish, unpublish, deprecate, dist-tags, search, ping, whoami, and `npm audit`
answered from this registry's own CVE store. The abbreviated packument is a
strict field whitelist. Scoped names work encoded or not.

**PyPI**

| Spec | |
|---|---|
| PEP 503 — HTML simple API, name normalization | ✅ |
| PEP 592 — yanked | ✅ |
| PEP 629 — repository version | ✅ |
| PEP 658 — `.metadata` sidecars | ✅ |
| PEP 691 — JSON simple API | ✅ |
| PEP 700 — `versions`, `size`, `upload-time` | ✅ |
| PEP 714 — `core-metadata` | ✅ |
| Legacy upload (twine) | ✅ |

Advertised API version **1.1**.

**Cargo** — the sparse HTTP index (RFC 2789): `config.json`, the sharded
per-crate index files, and artifact downloads. Read-only, and deliberately so.

Cargo mirrors a registry through *source replacement*, and source replacement
requires the replacement to serve content identical to crates.io — cargo
verifies each crate against the checksum in `Cargo.lock`. A crate that is not
on crates.io therefore cannot be resolved through a replaced source no matter
what the registry serves, so a publish surface here would be a surface nobody
could use. `config.json` omits the `api` key for the same reason: without it
cargo says "registry does not support API commands" instead of failing deeper
in `cargo publish`.

The older **git** index is not supported. Cloning and maintaining a repository
the size of the crates.io index is a different operational shape than an HTTP
cache, and every registry worth mirroring now serves sparse.

Verified against the real thing: `pip install requests` resolves and installs
its whole dependency tree through the registry, including PEP 658 metadata
sidecars; `twine upload` publishes and `pip install` retrieves the result;
proxied npm tarballs match npmjs' published `shasum` byte for byte; the cargo
provider reads `index.crates.io` and the artifact it resolves hashes to the
`cksum` the index published.

---

## Stack

FastAPI · PostgreSQL 16 · Valkey · Vue 3 · Docker Compose

Postgres because the read path needs one indexed lookup per packument, JSONB
for verbatim upstream documents, trigram indexes for search, and cheap
append-only writes for telemetry. Valkey is strictly an accelerator — losing it
costs speed, not correctness. See [Architecture](docs/architecture.md).

---

## Development

```bash
# Backend
cd backend
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest          # 641 tests

# Frontend
cd frontend
npm install && npm run dev          # proxies to :8000
```

Spec compliance is tested against the specs' own examples where they publish
them — node-semver's fixture tables, the FIRST.org CVSS reference vectors, the
PEP-documented formats — rather than against our own reading of them.

---

## Security

- Argon2id password hashing; API tokens stored as SHA-256 of the secret half
  and shown exactly once.
- Upstream credentials encrypted at rest, never returned by the API.
- An `Authorization` header is authoritative — a rejected token never falls
  back to a session cookie, so revocation is immediate.
- Publishing always requires a token; passwords are refused.
- Downloads verified against every digest the upstream advertised before being
  served or cached.
- Login attempts limited per IP **and** per username; both outcomes audited.
- The CLI authenticates by OAuth device flow, so no password reaches the
  terminal and SSO works unchanged.

---

## Known limitations

- **CVSS v4 is approximated** — its real model is a lookup table. v3 is used
  when a record publishes both, and a v4 vector declaring any impact never
  scores below 2.0 so an error cannot understate a vulnerability to harmless.
- **No migration framework.** Additive columns are applied at startup;
  destructive changes would need handling manually.
- **The PyPI index lists only known projects.** Use **Upstreams → Index** to
  populate search from an upstream.
- **`yanked` is PyPI-only** — npm has no equivalent concept.
