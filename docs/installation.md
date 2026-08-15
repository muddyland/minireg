# Installation

## Requirements

| | Minimum | Notes |
|---|---|---|
| Docker | 24+ with Compose v2 | `docker compose version` |
| RAM | 2 GB | 4 GB+ if you enable inline CVE scanning under load |
| Disk | 10 GB | Grows with cached artifacts; see [Operations](operations.md#storage) |
| CPU | 2 cores | The registry is I/O bound, not CPU bound |

Nothing else is needed on the host. Postgres, Redis, and the application are
all containers, and the application image is built locally from the included
`Dockerfile` — nothing is pulled from an image registry.

---

## Quick start

```bash
git clone <your-fork> minireg
cd minireg

cp .env.example .env
$EDITOR .env          # set SECRET_KEY and PUBLIC_URL

docker compose up -d --build
```

Generate the secrets:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Then get the initial admin password — only printed if you left
`BOOTSTRAP_ADMIN_PASSWORD` blank:

```bash
docker compose logs minireg | grep -A4 "initial admin"
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

   Without at least one upstream, only packages published directly to this
   registry will resolve.
3. **Test each upstream** with the *Test* button.
4. **Create an API token** (**API tokens → New token**).
5. **Point a client at it** — see [Using the registry](usage.md).

---

## Behind a reverse proxy

The app trusts `X-Forwarded-For` for client IPs in the audit and download logs.
Your proxy must **overwrite** that header, not append to it, or a client can
forge its own source address.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name registry.example.com;

    ssl_certificate     /etc/ssl/certs/registry.pem;
    ssl_certificate_key /etc/ssl/private/registry.key;

    # Package tarballs and wheels are large; do not let the proxy buffer
    # them to disk or cap them.
    client_max_body_size 0;
    proxy_read_timeout 300s;
    proxy_buffering off;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite, not append
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

`client_max_body_size 0` matters: npm publishes and wheel uploads are frequently
tens of megabytes, and nginx's 1 MB default rejects them with a 413 that the
client reports as an unhelpful generic failure.

### Caddy

```caddy
registry.example.com {
    reverse_proxy 127.0.0.1:8000 {
        header_up X-Forwarded-For {remote_host}
    }
    request_body {
        max_size 0
    }
}
```

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
```

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
*additive* columns are applied from a list in `backend/app/db.py`. There is no
migration framework, so anything destructive (a drop, a rename, a type change)
would need to be handled manually — see [Operations](operations.md#backups).

Back up the database before upgrading.

---

## Uninstalling

```bash
docker compose down          # stop, keep data
docker compose down -v       # stop and delete all data
```

`-v` removes the Postgres database, the Redis cache, and every cached artifact.
Packages published directly to this registry cannot be recovered from an
upstream — back up the `package-storage` volume first if you have any.
