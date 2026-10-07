# Container images

minireg serves container images as well as packages. It is a pull-through
cache for Docker Hub, GHCR, Quay, registry.k8s.io and any other OCI registry,
and it hosts images you push. Every image is scanned with Trivy. Policy can
refuse images with known-exploited or denied vulnerabilities, and it holds
images you build to a stricter bar than upstream ones.

There are two reasons to put a registry in the middle:

- **Supply chain.** Every image your builds and clusters run passes through
  one place. That place records it, scans it and can refuse it. "Which of
  our images contain CVE-2024-3094?" becomes one search.
- **Rate limits.** Docker Hub limits anonymous pulls per IP address. A CI
  fleet behind one NAT address hits that limit quickly. minireg pulls each
  layer once, serves it from disk after that, and keeps serving the cached
  copy when the upstream is down or rate-limiting.

## Pulling

Put the registry's hostname in front of the image name:

```
docker pull minireg.example.com/alpine:3.20                    # Docker Hub (library/alpine)
docker pull minireg.example.com/bitnami/redis:7.4              # Docker Hub (bitnami/redis)
docker pull minireg.example.com/ghcr/aquasecurity/trivy:0.75.0 # ghcr.io
docker pull minireg.example.com/quay/prometheus/busybox        # quay.io
docker pull minireg.example.com/k8s/pause:3.10                 # registry.k8s.io
```

The first path segment chooses where the image comes from:

| First segment | Meaning |
|---|---|
| `local` | an image pushed to this registry |
| an upstream's name (`ghcr`, `quay`, …) | that upstream |
| `dockerhub` | Docker Hub, explicitly |
| anything else | Docker Hub, with `library/` added for one-segment names |

`alpine`, `library/alpine` and `dockerhub/library/alpine` are the same
repository and share one cache entry.

When anonymous reads are enabled, pulls need no login. Otherwise, run
`docker login` with your username and an API token that has the `read` scope,
or let the CLI do it with the token it already holds:

```
minireg configure docker
```

To check an image before you run it, `minireg audit --image alpine:3.20`
prints its findings and whether the registry would serve it, and exits non-zero
when it would not. See [The CLI](cli.md#container-images).

### As a Docker Hub mirror

A mirror sends plain `docker pull alpine` through minireg without changing
any image names. Add the registry to `/etc/docker/daemon.json` and restart
dockerd:

```json
{ "registry-mirrors": ["https://minireg.example.com"] }
```

For containerd (Kubernetes nodes), put this in
`/etc/containerd/certs.d/docker.io/hosts.toml`:

```toml
server = "https://registry-1.docker.io"

[host."https://minireg.example.com"]
  capabilities = ["pull", "resolve"]
```

Docker only uses mirrors for Docker Hub images. If the mirror is unreachable,
Docker falls back to Hub directly. That keeps pulls working, but those pulls
skip policy. To make policy mandatory, block Hub at the network edge.

The mirror uses the main hostname by default. In that mode, a Hub image whose
first segment is also an upstream name (a Hub user called `quay`, say)
resolves to that upstream instead. To avoid this, set
`DOCKER_MIRROR_HOSTNAME` to a second hostname that points at the same
service. On that hostname every name is a Docker Hub name.

The **Client setup → Docker** page shows all of this with your hostname
filled in. It also covers Podman's `registries.conf`, a Kubernetes pull
secret, and a GitLab CI snippet.

## Pushing

Images you build go under the `local/` namespace:

```
docker login minireg.example.com -u <username>     # password: an API token
docker tag myapp:1.0 minireg.example.com/local/team-a/myapp:1.0
docker push minireg.example.com/local/team-a/myapp:1.0
```

- The password must be an API token with the **docker:push** scope. Account
  passwords are refused, so a leaked CI variable can't be used to sign in to
  the UI.
- A token can be limited to repository prefixes, for example `local/team-a/`.
  A pipeline token then can't overwrite another team's images.
- The first user to push a repository owns it. Other users can pull it but
  can't push to it, unless they are admins.
- Cross-repository blob mounts (`docker buildx` does these constantly) only
  mount from repositories the pusher can already read.
- Manifests that reference layers stored elsewhere ("foreign layers") are
  refused.

### Pushed images are scanned before they can be pulled

A push is always accepted. Scanning starts straight away, and until it
finishes, pulls of the new digest wait for up to *hold seconds* and then get
a 503. Once the scan finishes, the image is checked against the **push
rules**. By default an image is blocked if it has:

- a vulnerability on CISA's Known Exploited Vulnerabilities list, or
- a CRITICAL finding that already has a fixed version.

The pull error names the reason, for example
`denied: blocked by push policy: CVE-2024-9999 (CRITICAL, fixed in 2.0)`. To
fix it, rebuild on a patched base image and push again. Changing the push
rules re-judges every pushed image immediately.

## Scanning

A separate scanner worker runs Trivy. It claims jobs from minireg over HTTP
and pulls each image by digest from minireg's own `/v2`, so it only ever
scans bytes that minireg has already verified. The worker has:

- no database access,
- no upstream credentials,
- no shared filesystem.

Its token holds only the `scanner` scope. minireg treats the reports it posts
as untrusted input: their size is capped, only the fields minireg uses are
parsed, and text from them is shown as text, never as HTML.

- **When.** An upstream image is scanned the first time it is pulled, and a
  pushed image as soon as it is pushed. Multi-platform images are scanned
  per platform, limited to the platforms in the policy (by default
  `linux/amd64` and `linux/arm64`). Attestations and non-image artifacts,
  such as Helm charts and signatures, are recorded but not scanned.
- **Rescans.** Every image pulled in the last *N* days is rescanned on a
  schedule, by matching its stored SBOM against the current vulnerability
  database. This takes well under a second per image and doesn't pull the
  image again. A newly published CVE therefore shows up on images you
  already have.
- **SBOMs.** Each scanned image gets a CycloneDX SBOM. You can download it
  from the image page.

- **Vulnerability database.** When minireg has a `ghcr` upstream, the worker
  downloads Trivy's database through minireg (`ghcr/aquasecurity/trivy-db`).
  ghcr.io rate-limits that artifact heavily, and routing it through minireg
  means only one copy is fetched.

Run the worker with the shipped compose file:

```sh
# 1. As an admin: API tokens -> "Scanner token" (Account section of the menu).
# 2. Put it in .env:
MINIREG_SCANNER_TOKEN=mrg_...
# 3. Start it:
docker compose --profile scanner up -d
```

The worker talks to minireg inside the compose network at
`http://minireg:8000`. `DOCKER_INTERNAL_URL` tells minireg to accept that as
an origin, so the token challenge sends the worker back to the internal
address and not out through your public proxy. The **Image policy** page shows
when each worker last checked in, and warns when none has.

CI publishes the worker as its own image next to the registry's, built from
the same commit: `<registry image>/scanner:<tag>`, e.g.
`registry.example/minireg/scanner:main` next to `registry.example/minireg:main`.
A deployment that pulls images instead of building them uses the pair, so the
worker always speaks the same scanner API as the registry it talks to.

### What the image page shows

Expand a tag on an image's page (**Images**, then the repository) to see the
image behind it. For a multi-platform tag, pick the platform first. Only
platforms pulled through minireg have details.

| Tab | Shows |
|-----|-------|
| Vulnerabilities | Findings from the latest scan. You can filter by severity, by whether a fix exists and by known-exploited (KEV), or search for a CVE or package. Expand a finding to see the fix and the layer it came from. |
| Packages | Every package in the SBOM, with version, type, licence, the findings against it and the layer that added it. |
| Layers | Each layer with its size, whether it is cached, and the build step that made it (`RUN …`, `COPY …`). Expand a layer to see the packages it added. |
| Config | Entrypoint, command, user (flagged when it is root), working directory, ports, volumes, environment, labels and the full build history. |
| Scan history | Every scan of this digest, with the mode, the Trivy and database versions, and the counts. |

All of this comes from data minireg already holds: the image config blob and
the SBOM. You don't have to pull the image. If a cached image's config blob
was never fetched, minireg fetches it from the upstream on first view. It is a
few kilobytes.

Keep in mind that the config and history are written by whoever built the
image. A build step is only a label: the scan is what tells you what the
layers actually contain.

## Pull policy

Pulls of upstream images are **allowed by default**. Ordinary base images
carry hundreds of findings (`postgres:16` has over 300), so a severity
threshold on pulls would block nearly everything and teach people to route
around the registry. These are the tools that stay useful instead:

| Rule | Effect |
|---|---|
| **Denied CVEs** | Any image containing one is refused, pull or push. Use this for incidents ("nothing with CVE-2024-3094 runs anywhere"). |
| **Block known-exploited** | Refuse images with a CISA KEV finding. minireg refreshes the catalogue daily. |
| **Block at severity** | Off by default for pulls. Can be combined with *only fixable*. |
| **Quarantine** | Refuse every pull of a repository, and show the reason you give. |
| **Accepted risks** | CVEs that never count towards a block. |
| **Strict mode** | Never serve an unscanned image. Clients get 503 with `Retry-After` until the scan finishes. |
| **Hold first pulls** | Wait up to *N* seconds for the scan of a small image before answering. Larger images are served straight away and scanned in the background. |

A refused pull returns the standard `DENIED` error with the reason, which
`docker pull` prints, and the refusal is written to the audit log.

## Caching and upstream rate limits

- **Tags are revalidated with HEAD.** A cached tag is served as-is for
  `DOCKER_TAG_TTL_SECONDS` (default 600). After that, the next pull checks
  the upstream with a HEAD request, which doesn't count against Docker Hub's
  pull quota. The manifest is fetched again, by digest, only when the tag has
  moved.
- **Digests never expire.** A digest is immutable, so `image@sha256:…` is
  never revalidated.
- **Serve-stale.** When the upstream is down, times out or returns 429, the
  cached copy of the tag is served. The response carries a `Warning` header
  saying so.
- **Negative caching.** When the upstream says an image or tag doesn't exist,
  that answer is remembered for a short while (default 60 seconds). A typo
  in a CI matrix then doesn't turn into a stream of upstream requests.
- **Single-flight.** A hundred CI jobs pulling the same cold layer cause one
  upstream download. The first request streams the bytes to its client while
  they are written to disk; the others read the same file as it grows.
- **Rate-limit headers** from Docker Hub are recorded and shown on the
  **Image policy** page.
- **Watched tags** (set on an image's page) are revalidated, pre-fetched and
  rescanned every hour. CI then finds them warm and current, and they are
  never evicted.

Add Docker Hub with a dedicated account (a Personal Access Token with
read-only public repo access). Authenticated pulls get a much higher limit
than anonymous ones, and the limit is tied to the account rather than the
registry's IP address. Upstream credentials are only ever sent to the
registry itself, never to the CDN hosts that layer downloads are redirected
to.

## Storage

Image layers live under `STORAGE_PATH/oci/`, separate from package files. Set
a disk budget on the **Image policy** page. When usage goes over it, the
least recently pulled cached images are evicted until usage is back under
90% of the budget. Some images are never evicted:

- pinned repositories,
- watched tags,
- images pushed here.

Layers shared between images stay on disk until nothing references them.
Garbage collection runs with the regular housekeeping and waits a grace
period before deleting anything, so an upload in progress is never collected
from under a client.

## Upstream security

Every upstream URL is checked before minireg connects to it. The URL:

- must use `https`,
- must name the upstream's host or one of its known CDN hosts,
- must resolve to a public address.

The connection is then pinned to the address that was checked, so a DNS
answer that changes between the check and the connect (DNS rebinding) can't
redirect it. Redirects are followed a bounded number of times, and each hop
is checked again. Manifests larger than `DOCKER_MAX_MANIFEST_BYTES` (4 MiB)
are refused.

The upstream names `local`, `library`, `v2` and `token` are reserved. So are
the preset names (`dockerhub`, `ghcr`, `quay`, `k8s`, `ecr-public`, `gcr`),
unless the upstream is the registry the preset describes. This stops a
misconfigured or malicious upstream from impersonating a well-known one.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DOCKER_ENABLED` | `true` | Serve `/v2` at all. |
| `DOCKER_LOCAL_NAMESPACE` | `local` | Namespace for pushed images. |
| `DOCKER_MIRROR_HOSTNAME` | unset | Extra hostname on which every name is a Docker Hub name. |
| `DOCKER_TAG_TTL_SECONDS` | `600` | How long a cached tag is served before a HEAD revalidation. |
| `DOCKER_NEGATIVE_CACHE_TTL_SECONDS` | `60` | How long an upstream "not found" is remembered. |
| `DOCKER_MAX_MANIFEST_BYTES` | `4194304` | Largest manifest accepted. |
| `DOCKER_TOKEN_TTL_SECONDS` | `300` | Lifetime of registry bearer tokens. |
| `DOCKER_MAX_BLOB_BYTES` | 16 GiB | Largest single layer. |
| `DOCKER_STORAGE_BUDGET_BYTES` | 200 GiB | Starting disk budget; the UI can change it. |

Registry bearer tokens are short-lived and point back at the API token that
issued them, so revoking an API token takes effect at once.

## Troubleshooting

- **`http: server gave HTTP response to HTTPS client`**: Docker only talks
  plain HTTP to `localhost`, or to registries listed in
  `insecure-registries`. Serve minireg over TLS.
- **`denied: blocked by …`**: policy refused the image, and the message says
  why. Open the image in the UI to see the findings. Ask an admin to accept
  the risk, or move to a patched tag.
- **`503 … not scanned yet`**: strict mode or a pushed image is waiting for
  its scan. If this doesn't clear, check the **Image policy** page to see
  whether a scanner worker is running.
- **`unauthorized` on push**: the password must be an API token with
  `docker:push`, and the repository must be under `local/` and inside the
  token's prefixes.
