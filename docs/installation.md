# Installation

## Requirements

| | Minimum | Notes |
|---|---|---|
| Docker | 24+ with Compose v2 | `docker compose version` |
| RAM | 2 GB | 4 GB+ if you enable inline CVE scanning under load |
| Disk | 10 GB | Grows with cached artifacts; see [Operations](operations.md#storage) |
| CPU | 2 cores | The registry is I/O bound, not CPU bound |

Nothing else is needed on the host. Postgres, Valkey, and the application are
all containers, and the application image is built locally from the included
`Dockerfile` — nothing is pulled from an image registry.

The app container runs unprivileged, on a read-only root filesystem, with all
Linux capabilities dropped and a PID limit. Only the data volume and a small
tmpfs are writable. If you add a sidecar or change the entrypoint, expect to
adjust that rather than assume a writable filesystem.

---

## Quick start

```bash
git clone <your-fork> minireg
cd minireg
cp .env.example .env

# Generate the two secrets
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python3 -c "import secrets; print('CREDENTIAL_KEY=' + secrets.token_urlsafe(48))"

$EDITOR .env          # paste those in, and set PUBLIC_URL
chmod 600 .env        # it holds every secret this deployment has

docker compose up -d --build
```

**The app refuses to start in production with a placeholder or short
`SECRET_KEY`.** It signs session cookies and, unless `CREDENTIAL_KEY` is set
separately, derives the key that encrypts stored upstream credentials — so a
guessable value lets anyone mint an admin session and read every credential you
have saved. The startup check inspects the value rather than merely testing
that one is present, because the shipped example would pass that.

Setting `CREDENTIAL_KEY` separately is what lets you rotate `SECRET_KEY` later
without losing every stored upstream credential.

Then read the initial admin password. If you left `BOOTSTRAP_ADMIN_PASSWORD`
blank, one is generated and written to a `0600` file on the data volume:

```bash
docker compose exec minireg cat /data/initial-admin-password
```

It is deliberately not printed to the container log: Docker's json-file driver
keeps stdout for the life of the container, so anyone with the docker socket
or a log shipper could read it indefinitely. Sign in, change the password, then
delete the file:

```bash
docker compose exec minireg rm /data/initial-admin-password
```

Open the `PUBLIC_URL` you configured and sign in.

---

## The one setting that must be right

**`PUBLIC_URL`.**

Every tarball URL in an npm packument and every file URL in a PyPI simple-index
page is rendered against it. If it doesn't match the address clients actually
use — scheme, host, *and* port — then metadata will look perfectly correct while
`npm install` fails with connection errors, because the client is being told to
fetch artifacts from an address that doesn't resolve.

| Deployment | `PUBLIC_URL` |
|---|---|
| Local testing | `http://localhost:8000` |
| Behind a TLS proxy | `https://registry.example.com` |
| Non-standard port | `https://registry.example.com:8443` |

Change it later and you must restart the app and purge the metadata cache
(**Storage → Run garbage collection** is not enough; cached packuments expire on
their own within `META_CACHE_TTL`, 60s by default).

---

## First-run checklist

1. **Sign in** and change the admin password (**Account**).
2. **Add upstreams** (**Upstreams → Add upstream**):

   | Ecosystem | Type | URL | Tier |
   |---|---|---|---|
   | npm | npm registry | `https://registry.npmjs.org` | 1 |
   | PyPI | PyPI simple index | `https://pypi.org/simple` | 1 |
   | cargo | cargo sparse index | `https://index.crates.io` | 1 |

   Without at least one upstream, only packages published directly to this
   registry will resolve.

   These three serve their files from separate CDN hosts, which are already in
   the default `UPSTREAM_ARTIFACT_HOSTS`. If you add an upstream that serves
   artifacts from somewhere else, add that host too or downloads will fail with
   a 502 naming it — artifact URLs come out of upstream metadata, so they are
   only fetched from hosts you have allowed.
3. **Test each upstream** with the *Test* button.
4. **Reserve your internal namespaces** if you have an internal upstream. On
   that upstream, set **Reserved names** to something like `@corp/*`. Names
   matching it are then only ever resolved from upstreams that claim them, so a
   public registry cannot answer for an internal package — which is the shape
   of a dependency-confusion attack.
5. **Create an API token** (**API tokens → New token**). Scope it: a token can
   never grant scopes it does not itself hold, so a `read` token stays a read
   token even if it leaks.
6. **Point a client at it** — see [Using the registry](usage.md).

### Publishing your own packages

Publishing is refused for any name an upstream already serves — that is what
stops one leaked publish token replacing `lodash` for everyone using the
mirror. For genuinely private packages, either use a namespace no public
registry has (`@yourcompany/*`), or have an admin add the name to the
`publish_namespaces` setting.

The first person to publish a name owns it. Only they, or an admin with an
admin-scoped credential, can publish further versions, move dist-tags,
deprecate, or unpublish it. A version that is unpublished cannot be republished
with different content.

---

## Behind a reverse proxy

Client addresses drive rate limiting, the login throttle, the CLI approval
screen and every audit record, so the registry is careful about where it gets
them from.

Two settings govern it, and the defaults are right for the shipped topology
(proxy on the same host, app bound to loopback):

| Variable | Default | Meaning |
|---|---|---|
| `TRUSTED_PROXY_IPS` | the private ranges plus loopback | Peers whose forwarding headers are read at all |
| `TRUSTED_PROXY_HOPS` | `1` | How many proxies are in front |

A request from anywhere outside `TRUSTED_PROXY_IPS` is treated as coming
straight from the client and its `X-Forwarded-For` is ignored entirely. From a
trusted peer, the address is taken **`TRUSTED_PROXY_HOPS` entries from the
right**. Everything further left was written by the caller.

That means **either style of proxy config is safe**. Appending is the common
one and works because your proxy's entry ends up rightmost:

```
client sends nothing        ->  "203.0.113.9"                 -> 203.0.113.9
client forges a header      ->  "1.2.3.4, 203.0.113.9"        -> 203.0.113.9
```

Overwriting works too, and leaves a single entry. Add a hop for each additional
proxy: behind Cloudflare in front of your own nginx, set `TRUSTED_PROXY_HOPS=2`.

### nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name registry.example.com;

    ssl_certificate     /etc/ssl/certs/registry.pem;
    ssl_certificate_key /etc/ssl/private/registry.key;

    # Publishes are large. Match MAX_PUBLISH_BYTES (256 MB default) rather
    # than removing the limit: the app rejects an oversized body on
    # Content-Length before reading it, and a proxy that lets an unbounded
    # one through just moves the memory problem upstream.
    client_max_body_size 256m;
    proxy_read_timeout 300s;
    proxy_buffering off;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy

```caddy
registry.example.com {
    reverse_proxy 127.0.0.1:8000
    request_body {
        max_size 256MB
    }
}
```

Caddy sets `X-Forwarded-For` correctly on its own; no `header_up` is needed.

### Traefik

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.minireg.rule=Host(`registry.example.com`)
  - traefik.http.routers.minireg.tls=true
  - traefik.http.services.minireg.loadbalancer.server.port=8000
```

Then set `PUBLIC_URL=https://registry.example.com` and, if the proxy is on the
same host, leave `BIND_ADDRESS=127.0.0.1` so the app is not directly reachable.

---

## Exposing it directly

Only if you are not using a proxy:

```env
BIND_ADDRESS=0.0.0.0
PORT=8000
# Nothing in front of the app, so nothing may claim to be a proxy.
TRUSTED_PROXY_IPS=
```

**Set `TRUSTED_PROXY_IPS=` (empty) when you do this.** It defaults to the
private ranges because the shipped layout reaches the container over the Docker
bridge. Bind to `0.0.0.0` on a LAN without clearing it and every machine on
that LAN is treated as a trusted proxy, free to set its own address in a
header — and with it, its own rate-limit bucket and audit trail.

There is no TLS in the app itself. Over plain HTTP, API tokens travel in
cleartext — `pip` in particular puts the token in the index URL. Use a proxy
with TLS for anything beyond a trusted LAN.

---

## Upgrading

```bash
git pull
docker compose up -d --build
```

Schema changes are applied at startup: tables are created if missing, and new
*additive* columns are applied from a list in `backend/app/db.py`, under a
Postgres advisory lock so replicas starting together do not race each other.
There is no migration framework, so anything destructive (a drop, a rename, a
type change) has to be handled manually — see
[Operations](operations.md#backups).

Back up the database before upgrading.

Python dependencies install from `backend/requirements.lock` with
`--require-hashes`, so two builds of the same commit install byte-identical
dependencies. After changing `backend/requirements.txt`, regenerate it:

```bash
docker run --rm -v "$PWD/backend:/w" -w /w python:3.12-slim sh -c \
  'pip install -q pip-tools && pip-compile --generate-hashes \
   --no-emit-index-url -o requirements.lock requirements.txt'
```

Generate it inside `python:3.12-slim`, matching the runtime image: markers and
backport packages differ between interpreter versions, so a lock built on a
different Python can install the wrong set. Check the result has no
`--index-url` line before committing — `pip-compile` bakes in whatever the
generating machine's pip config points at, which for anyone using this registry
is an authenticated URL.

---

## What is not exposed

Worth knowing before you go looking for it:

| | |
|---|---|
| `/api/docs`, `/api/openapi.json` | Disabled unless `ENVIRONMENT=dev`. They enumerate every admin route and schema. |
| `/api/metrics` | Admin only. Counters for requests, statuses and fail-open CVE scans. |
| `/api/health/detailed` | Public, but anonymous callers get booleans. Error strings and disk figures need an admin. |
| `/health` | Public and unauthenticated. Runs a real database query, so a wedged pool fails the container healthcheck. |

---

## Uninstalling

```bash
docker compose down          # stop, keep data
docker compose down -v       # stop and delete all data
```

`-v` removes the Postgres database, the Valkey cache, and every cached artifact.
Packages published directly to this registry cannot be recovered from an
upstream — back up the `package-storage` volume first if you have any.
