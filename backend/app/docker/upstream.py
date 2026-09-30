"""Talking to an upstream OCI registry.

Covers the parts of the distribution protocol a pull-through cache needs:
the ``WWW-Authenticate`` bearer challenge, manifest HEAD/GET, blob GET with
the redirect every public registry answers it with, tag listing and the
referrers API.

Security properties, each one of which a hostile or compromised upstream
would otherwise get to decide:

* **Where we connect.** Every URL -- the registry, its token realm, each
  redirect hop -- goes through ``check_target``: https only (unless the
  operator allows http), host must be the registry, a configured blob host,
  or a known auth host, and every address the name resolves to must be
  public. The resolved address is then *pinned* for the connection, so a DNS
  answer that changes between the check and the connect (rebinding) cannot
  steer the socket onto the internal network.
* **Who sees our credentials.** Upstream credentials go only to the registry
  host and its token realm. A redirect to a CDN is followed with no
  Authorization header at all.
* **How much we read.** Manifests are capped in bytes before parsing,
  redirects are capped in hops.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import logging
import re
import socket
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from httpcore import AsyncNetworkBackend

from ..config import settings
from ..core.metrics import bump, gauge
from ..core.security import decrypt_credential
from ..models import Upstream, UpstreamKind
from ..upstreams.base import user_agent
from .errors import RegistryError
from .naming import PRESETS, host_matches

log = logging.getLogger(__name__)

MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        # Schema 1 is refused on arrival, but advertising it lets an upstream
        # that has nothing else say so instead of answering 404.
        "application/vnd.docker.distribution.manifest.v1+prettyjws",
    ]
)

_CHALLENGE_PARAM = re.compile(r'(\w+)="([^"]*)"')


class UpstreamUnavailable(Exception):
    """The upstream could not answer (network, 5xx, 429, auth failure).

    Distinct from "not found": an unavailable upstream is a reason to serve
    stale data, a 404 is not.
    """

    def __init__(self, message: str, *, status: int | None = None, retry_after: str | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class UpstreamNotFound(Exception):
    """The upstream said the manifest, blob or repository does not exist."""


class BlockedTarget(Exception):
    """We refuse to connect to this URL."""


# --------------------------------------------------------------------------- #
# Network guard with DNS pinning
# --------------------------------------------------------------------------- #
def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or ip in ipaddress.ip_network("100.64.0.0/10")  # carrier-grade NAT
    )


async def _resolve(host: str, port: int) -> list[str]:
    """Resolve, retrying transient failures.

    Resolvers in container networks (Docker's embedded DNS forwarding to a
    site resolver) intermittently answer EAI_NODATA/EAI_AGAIN for names that
    resolve a moment later. One such answer used to fail a cold layer
    download outright; three quick attempts ride it out.
    """
    loop = asyncio.get_running_loop()
    last: OSError | None = None
    for attempt in range(3):
        try:
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            return list(dict.fromkeys(str(info[4][0]) for info in infos))
        except socket.gaierror as exc:
            if exc.errno == socket.EAI_NONAME:
                raise  # the name really does not exist
            last = exc
            await asyncio.sleep(0.2 * (attempt + 1))
    assert last is not None
    raise last


class _PinnedBackend(AsyncNetworkBackend):
    """httpcore network backend that connects only to pre-approved addresses.

    ``check_target`` resolves a host and approves its addresses; this backend
    then refuses any connection to that host on an address it did not
    approve, and resolves nothing itself. Closing the gap between "the name
    resolved to something public when we checked" and "the socket went
    somewhere public" is the whole point: without it a rebinding DNS server
    answers the check with a public address and the connect with 10.0.0.5.
    """

    def __init__(self) -> None:
        from httpcore._backends.auto import AutoBackend

        self._inner = AutoBackend()
        self.pins: dict[str, tuple[float, list[str]]] = {}

    def pin(self, host: str, addresses: list[str]) -> None:
        self.pins[host.lower()] = (time.monotonic() + 300, addresses)
        if len(self.pins) > 4096:
            now = time.monotonic()
            self.pins = {h: v for h, v in self.pins.items() if v[0] > now}

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        entry = self.pins.get(host.lower())
        if entry is None or entry[0] < time.monotonic():
            raise httpx.ConnectError(f"connection to {host} was not approved")
        last: Exception | None = None
        for address in entry[1]:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # try the next address
                last = exc
        raise last or httpx.ConnectError(f"could not connect to {host}")

    async def connect_unix_socket(self, *args, **kwargs):  # pragma: no cover
        raise httpx.ConnectError("unix sockets are not used for upstreams")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


_backend = _PinnedBackend()
_clients: dict[bool, httpx.AsyncClient] = {}


def _client(verify: bool) -> httpx.AsyncClient:
    client = _clients.get(verify)
    if client is None:
        import httpcore

        pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=verify),
            max_connections=settings.upstream_max_connections,
            max_keepalive_connections=settings.upstream_max_keepalive,
            keepalive_expiry=30,
            http1=True,
            http2=True,
            network_backend=_backend,
        )
        transport = httpx.AsyncHTTPTransport(verify=verify, http2=True)
        # Swap in the pool built on the pinned backend. The transport's own
        # pool is closed first so it does not leak.
        old = transport._pool
        transport._pool = pool
        with contextlib.suppress(Exception):
            asyncio.get_running_loop().create_task(old.aclose())
        client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(
                settings.upstream_timeout_seconds, connect=settings.upstream_connect_timeout_seconds
            ),
            follow_redirects=False,
            headers={"user-agent": user_agent()},
        )
        _clients[verify] = client
    return client


async def close_clients() -> None:
    for client in list(_clients.values()):
        with contextlib.suppress(Exception):
            await client.aclose()
    _clients.clear()


#: Test hook: when set, used instead of the pinned client (respx mocks sit
#: on a plain transport). check_target still runs its host rules.
_test_client: httpx.AsyncClient | None = None


def set_test_client(client: httpx.AsyncClient | None) -> None:
    global _test_client
    _test_client = client


# --------------------------------------------------------------------------- #
# Upstream wrapper
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ManifestResponse:
    digest: str
    media_type: str
    body: bytes | None  # None for HEAD
    size: int


class RegistryClient:
    """One upstream registry."""

    def __init__(self, upstream: Upstream) -> None:
        self.upstream = upstream
        self.name = upstream.name
        extra = upstream.extra or {}
        if upstream.kind == UpstreamKind.gitlab_oci:
            # GitLab puts the container registry on its own host; `url` is the
            # GitLab instance, `extra.registry_url` the registry.
            base = extra.get("registry_url") or upstream.url
        else:
            base = upstream.url
        self.base = base.rstrip("/")
        parts = urlsplit(self.base)
        self.host = (parts.hostname or "").lower()
        self.path_prefix = parts.path.rstrip("/")
        preset = PRESETS.get(upstream.name)
        self.blob_hosts: tuple[str, ...] = tuple(extra.get("blob_hosts") or ()) or (
            preset.blob_hosts if preset else ()
        )
        self.auth_hosts: tuple[str, ...] = tuple(extra.get("auth_hosts") or ()) + (
            preset.auth_hosts if preset else ()
        )
        if upstream.kind == UpstreamKind.gitlab_oci:
            gitlab_host = (urlsplit(upstream.url).hostname or "").lower()
            if gitlab_host:
                self.auth_hosts += (gitlab_host,)
        self._tokens: dict[str, tuple[str, float]] = {}

    # -- target checks ------------------------------------------------------ #
    async def check_target(self, url: str, *, purpose: str) -> None:
        """Refuse a URL we must not connect to, and pin what we will."""
        parts = urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise BlockedTarget(f"refusing a non-HTTP URL ({scheme or 'no scheme'})")
        if scheme == "http" and not settings.upstream_allow_plaintext_http:
            raise BlockedTarget("refusing plaintext http; set UPSTREAM_ALLOW_PLAINTEXT_HTTP")
        host = (parts.hostname or "").lower()
        if not host:
            raise BlockedTarget("URL has no host")

        allowed = host == self.host
        if not allowed and purpose == "auth":
            allowed = host_matches(host, self.auth_hosts)
        if not allowed and purpose in ("blob", "mirror"):
            # "mirror": a registry that redirects its API itself (not only
            # layer downloads) to a regional mirror -- registry.k8s.io sends
            # manifest requests to *-docker.pkg.dev. The mirror hosts are the
            # upstream's configured blob hosts; nothing else is followed.
            allowed = host_matches(host, self.blob_hosts) or host_matches(
                host, settings.artifact_host_allowlist
            )
        if not allowed:
            bump("docker.upstream.blocked_host", upstream=self.name)
            raise BlockedTarget(
                f"'{host}' is not an allowed {purpose} host for upstream '{self.name}'. "
                "Add it to the upstream's blob hosts if this registry really serves from there."
            )

        port = parts.port or (443 if scheme == "https" else 80)
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            try:
                addresses = await _resolve(host, port)
            except OSError as exc:
                raise UpstreamUnavailable(f"{self.name}: cannot resolve {host}: {exc}") from exc
        if not settings.upstream_allow_private_addresses:
            bad = [a for a in addresses if not _is_public(a)]
            if bad:
                bump("docker.upstream.blocked_private", upstream=self.name)
                raise BlockedTarget(
                    f"'{host}' resolves to a private or reserved address ({bad[0]}); refusing"
                )
        _backend.pin(host, addresses)

    def _http(self) -> httpx.AsyncClient:
        if _test_client is not None:
            return _test_client
        return _client(bool(getattr(self.upstream, "verify_ssl", True)))

    # -- credentials -------------------------------------------------------- #
    def _basic(self) -> tuple[str, str] | None:
        secret = decrypt_credential(self.upstream.credential_enc)
        if not secret:
            return None
        auth_type = (self.upstream.auth_type or "none").lower()
        if auth_type in ("basic", "none") and ":" in secret:
            user, _, password = secret.partition(":")
            return user, password
        # A bare token: GitLab and most registries accept any username with a
        # token as the password in the token exchange.
        return ("minireg", secret)

    async def _token_for(self, challenge: str, scope: str, *, mirror: bool = False) -> str:
        """Exchange a bearer challenge for a token.

        ``mirror`` is a challenge from a redirect target rather than the
        registry itself: the token is requested anonymously (our credentials
        belong to the registry, never to whoever it hands us to), and the
        realm may only be on a mirror host.
        """
        params = dict(_CHALLENGE_PARAM.findall(challenge))
        realm = params.get("realm")
        if not realm:
            raise UpstreamUnavailable(f"{self.name}: auth challenge has no realm")
        key = f"{realm}|{params.get('service', '')}|{params.get('scope') or scope}|{mirror}"
        cached = self._tokens.get(key)
        if cached and cached[1] > time.monotonic():
            return cached[0]

        await self.check_target(realm, purpose="mirror" if mirror else "auth")
        query = {"service": params.get("service", ""), "scope": params.get("scope") or scope}
        headers = {}
        basic = None if mirror else self._basic()
        if basic:
            raw = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
            headers["authorization"] = f"Basic {raw}"
        try:
            resp = await self._http().get(realm, params=query, headers=headers, timeout=20)
        except httpx.HTTPError as exc:
            raise UpstreamUnavailable(f"{self.name}: token request failed: {exc}") from exc
        if resp.status_code in (401, 403):
            raise UpstreamUnavailable(
                f"{self.name}: the registry refused our credentials ({resp.status_code})",
                status=resp.status_code,
            )
        if resp.status_code == 429:
            raise UpstreamUnavailable(f"{self.name}: token endpoint rate limited", status=429)
        if resp.status_code >= 400:
            raise UpstreamUnavailable(
                f"{self.name}: token endpoint answered {resp.status_code}", status=resp.status_code
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise UpstreamUnavailable(f"{self.name}: token endpoint sent non-JSON") from exc
        token = body.get("token") or body.get("access_token")
        if not token:
            raise UpstreamUnavailable(f"{self.name}: token endpoint sent no token")
        ttl = body.get("expires_in") or 60
        try:
            ttl = max(30, min(int(ttl), 3600))
        except (TypeError, ValueError):
            ttl = 60
        self._tokens[key] = (token, time.monotonic() + ttl - 15)
        if len(self._tokens) > 2048:
            self._tokens.clear()
        return token

    # -- requests ----------------------------------------------------------- #
    def url_for(self, remote: str, tail: str) -> str:
        return f"{self.base}/v2/{remote}/{tail}"

    async def _send(
        self,
        method: str,
        url: str,
        *,
        remote: str,
        headers: dict[str, str] | None = None,
        stream: bool = False,
        purpose: str = "registry",
    ) -> httpx.Response:
        """One request with the bearer dance and manual, re-checked redirects."""
        http = self._http()
        scope = f"repository:{remote}:pull"
        base_headers = dict(headers or {})
        auth: dict[str, str] = {}
        basic = self._basic()
        current = url
        tried_auth: set[str] = set()
        # Bearer tokens from a mirror, keyed by host; never sent anywhere else.
        mirror_auth: dict[str, dict[str, str]] = {}
        for _hop in range(settings.docker_max_redirects + 3):
            cur_host = (urlsplit(current).hostname or "").lower()
            on_registry = cur_host == self.host
            if on_registry:
                target_purpose = "registry"
            elif purpose == "registry":
                target_purpose = "mirror"
            else:
                target_purpose = purpose
            await self.check_target(current, purpose=target_purpose)
            if on_registry:
                send_headers = {**base_headers, **auth}
            else:
                send_headers = {**base_headers, **mirror_auth.get(cur_host, {})}
            try:
                req = http.build_request(method, current, headers=send_headers)
                resp = await http.send(req, stream=stream)
            except httpx.TimeoutException as exc:
                bump("docker.upstream.errors", upstream=self.name, kind="timeout")
                raise UpstreamUnavailable(f"{self.name}: timed out") from exc
            except httpx.HTTPError as exc:
                bump("docker.upstream.errors", upstream=self.name, kind="network")
                raise UpstreamUnavailable(f"{self.name}: {exc}") from exc

            bump("docker.upstream.requests", upstream=self.name, status=str(resp.status_code))
            if on_registry:
                self._record_ratelimit(resp)

            if resp.status_code == 401 and not on_registry and cur_host not in tried_auth:
                # A mirror asking for its own (anonymous) token. Only bearer is
                # answered, and only anonymously.
                challenge = resp.headers.get("www-authenticate", "")
                await resp.aclose()
                tried_auth.add(cur_host)
                if not challenge.lower().startswith("bearer"):
                    raise UpstreamUnavailable(
                        f"{self.name}: redirect target {cur_host} wants credentials", status=401
                    )
                # The mirror names the repository its own way
                # (k8s-artifacts-prod/images/pause); if its challenge carries
                # no scope, take the repository from the path we were sent to.
                m = re.match(r"/v2/(.+)/(?:manifests|blobs)/[^/]+$", urlsplit(current).path)
                mirror_scope = f"repository:{m.group(1)}:pull" if m else scope
                token = await self._token_for(challenge, mirror_scope, mirror=True)
                mirror_auth[cur_host] = {"authorization": f"Bearer {token}"}
                continue

            if resp.status_code == 401 and on_registry and self.host not in tried_auth:
                challenge = resp.headers.get("www-authenticate", "")
                await resp.aclose()
                tried_auth.add(self.host)
                if challenge.lower().startswith("bearer"):
                    token = await self._token_for(challenge, scope)
                    auth = {"authorization": f"Bearer {token}"}
                elif challenge.lower().startswith("basic") and basic:
                    raw = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
                    auth = {"authorization": f"Basic {raw}"}
                else:
                    raise UpstreamUnavailable(
                        f"{self.name}: authentication required and no usable credentials",
                        status=401,
                    )
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                await resp.aclose()
                if not location:
                    raise UpstreamUnavailable(f"{self.name}: redirect with no Location")
                current = str(httpx.URL(current).join(location))
                if resp.status_code == 303:
                    method = "GET"
                continue
            return resp
        raise UpstreamUnavailable(f"{self.name}: too many redirects")

    def _record_ratelimit(self, resp: httpx.Response) -> None:
        """Keep the upstream's quota where the UI and /metrics can see it.

        Docker Hub sends ``ratelimit-limit: 100;w=21600`` and
        ``ratelimit-remaining: 76;w=21600`` on manifest requests.
        """
        limit = resp.headers.get("ratelimit-limit")
        remaining = resp.headers.get("ratelimit-remaining")
        if limit is None and remaining is None:
            return
        lim = _leading_int(limit)
        rem = _leading_int(remaining)
        window = _window(limit or remaining)
        state = {
            "limit": lim,
            "remaining": rem,
            "window_seconds": window,
            "source": resp.headers.get("docker-ratelimit-source"),
            "observed_at": datetime.now(UTC).isoformat(),
        }
        RATELIMITS[self.name] = state
        if rem is not None:
            gauge("docker_upstream_ratelimit_remaining", rem, upstream=self.name)
            if rem <= settings.docker_ratelimit_warn_remaining:
                log.warning(
                    "upstream %s has %s of %s pulls left in its rate-limit window",
                    self.name,
                    rem,
                    lim,
                )
        if lim is not None:
            gauge("docker_upstream_ratelimit_limit", lim, upstream=self.name)

    @staticmethod
    def _raise_for(resp: httpx.Response, what: str, name: str) -> None:
        if resp.status_code == 404:
            raise UpstreamNotFound(f"{name}: {what} not found upstream")
        if resp.status_code == 429:
            raise UpstreamUnavailable(
                f"{name}: rate limited by the upstream",
                status=429,
                retry_after=resp.headers.get("retry-after"),
            )
        if resp.status_code in (401, 403):
            raise UpstreamUnavailable(
                f"{name}: upstream refused access to {what} ({resp.status_code})",
                status=resp.status_code,
            )
        if resp.status_code >= 400:
            raise UpstreamUnavailable(
                f"{name}: upstream answered {resp.status_code} for {what}", status=resp.status_code
            )

    # -- API ---------------------------------------------------------------- #
    async def manifest(self, remote: str, reference: str, *, head: bool = False) -> ManifestResponse:
        url = self.url_for(remote, f"manifests/{reference}")
        resp = await self._send(
            "HEAD" if head else "GET",
            url,
            remote=remote,
            headers={"accept": MANIFEST_ACCEPT},
            stream=not head,
        )
        try:
            self._raise_for(resp, f"manifest {remote}:{reference}", self.name)
            media_type = (resp.headers.get("content-type") or "").split(";")[0].strip()
            digest = resp.headers.get("docker-content-digest") or ""
            if head:
                size = int(resp.headers.get("content-length") or 0)
                return ManifestResponse(digest=digest, media_type=media_type, body=None, size=size)
            limit = settings.docker_max_manifest_bytes
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > limit:
                raise RegistryError(
                    "MANIFEST_INVALID",
                    f"upstream manifest is {declared} bytes, over the {limit} byte limit",
                    status=502,
                )
            buf = bytearray()
            async for chunk in resp.aiter_raw():
                buf.extend(chunk)
                if len(buf) > limit:
                    raise RegistryError(
                        "MANIFEST_INVALID",
                        f"upstream manifest exceeds the {limit} byte limit",
                        status=502,
                    )
            return ManifestResponse(digest=digest, media_type=media_type, body=bytes(buf), size=len(buf))
        finally:
            await resp.aclose()

    async def blob_stream(self, remote: str, digest: str) -> AsyncIterator[bytes]:
        """Yield a blob's bytes. Raises before the first yield on failure."""
        url = self.url_for(remote, f"blobs/{digest}")
        resp = await self._send("GET", url, remote=remote, stream=True, purpose="blob")
        try:
            self._raise_for(resp, f"blob {digest}", self.name)
        except BaseException:
            await resp.aclose()
            raise

        async def _iter() -> AsyncIterator[bytes]:
            try:
                # Raw, not decoded: the digest is over the bytes as stored,
                # and a CDN that adds Content-Encoding must not change them.
                async for chunk in resp.aiter_raw(256 * 1024):
                    yield chunk
            except httpx.HTTPError as exc:
                raise UpstreamUnavailable(f"{self.name}: blob download broke: {exc}") from exc
            finally:
                await resp.aclose()

        return _iter()

    async def tags(self, remote: str, *, limit: int = 1000) -> list[str]:
        url = self.url_for(remote, f"tags/list?n={limit}")
        resp = await self._send("GET", url, remote=remote)
        try:
            self._raise_for(resp, f"tags of {remote}", self.name)
            data = resp.json() if resp.content else {}
        finally:
            await resp.aclose()
        return [t for t in (data.get("tags") or []) if isinstance(t, str)][:limit]

    async def referrers(self, remote: str, digest: str) -> bytes | None:
        url = self.url_for(remote, f"referrers/{digest}")
        resp = await self._send("GET", url, remote=remote, headers={"accept": "application/vnd.oci.image.index.v1+json"})
        try:
            if resp.status_code in (404, 405):
                return None
            self._raise_for(resp, f"referrers of {digest}", self.name)
            if len(resp.content) > settings.docker_max_manifest_bytes:
                return None
            return resp.content
        finally:
            await resp.aclose()

    async def ping(self) -> tuple[bool, str | None]:
        """Health check: GET /v2/ and, if challenged, get an anonymous-scope
        token. Any 2xx or a well-formed 401 challenge counts as reachable."""
        try:
            await self.check_target(f"{self.base}/v2/", purpose="registry")
            resp = await self._http().get(f"{self.base}/v2/", timeout=10)
            if resp.status_code == 200:
                return True, None
            if resp.status_code == 401 and resp.headers.get("www-authenticate"):
                challenge = resp.headers["www-authenticate"]
                if challenge.lower().startswith("bearer"):
                    await self._token_for(challenge, "registry:catalog:*")
                return True, None
            return False, f"GET /v2/ answered {resp.status_code}"
        except (UpstreamUnavailable, BlockedTarget) as exc:
            return False, str(exc)
        except httpx.HTTPError as exc:
            return False, str(exc)

    async def list_gitlab_repositories(self) -> list[str]:
        """Every container repository under the configured GitLab project or
        group, as registry paths. Used to make them searchable."""
        from ..core.security import decrypt_credential as _dec

        extra = self.upstream.extra or {}
        gitlab = self.upstream.url.rstrip("/")
        token = _dec(self.upstream.credential_enc)
        headers = {"PRIVATE-TOKEN": token.split(":", 1)[-1]} if token else {}
        if self.upstream.gitlab_project_id:
            path = f"/api/v4/projects/{self.upstream.gitlab_project_id}/registry/repositories"
        elif self.upstream.gitlab_group_id:
            path = f"/api/v4/groups/{self.upstream.gitlab_group_id}/registry/repositories"
        else:
            raise UpstreamUnavailable("set a GitLab project or group to list repositories")
        names: list[str] = []
        page = 1
        http = self._http()
        while page <= 50:
            url = f"{gitlab}{path}?per_page=100&page={page}"
            parsed = urlsplit(url)
            if (parsed.hostname or "").lower() not in {(urlsplit(gitlab).hostname or "").lower()}:
                break
            await self._check_gitlab(url)
            resp = await http.get(url, headers=headers, timeout=20)
            if resp.status_code >= 400:
                raise UpstreamUnavailable(f"GitLab answered {resp.status_code} listing repositories")
            batch = resp.json()
            if not isinstance(batch, list) or not batch:
                break
            names.extend(r["path"] for r in batch if isinstance(r, dict) and r.get("path"))
            if not resp.headers.get("x-next-page"):
                break
            page += 1
        prefix = extra.get("strip_prefix") or ""
        return [n[len(prefix):].lstrip("/") if prefix and n.startswith(prefix) else n for n in names]

    async def _check_gitlab(self, url: str) -> None:
        host = (urlsplit(url).hostname or "").lower()
        saved = self.auth_hosts
        self.auth_hosts = (*saved, host)
        try:
            await self.check_target(url, purpose="auth")
        finally:
            self.auth_hosts = saved


#: Last rate-limit headers seen per upstream name. Process-local; the UI
#: reads it through the admin API, Prometheus through /metrics.
RATELIMITS: dict[str, dict[str, Any]] = {}


def _leading_int(value: str | None) -> int | None:
    if not value:
        return None
    m = re.match(r"\s*(\d+)", value)
    return int(m.group(1)) if m else None


def _window(value: str | None) -> int | None:
    if not value:
        return None
    m = re.search(r"w=(\d+)", value)
    return int(m.group(1)) if m else None
