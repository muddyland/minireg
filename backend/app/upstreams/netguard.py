"""Where the fetcher is allowed to connect.

Artifact URLs are not ours. npm's `dist.tarball`, PyPI's file hrefs and
cargo's `dl` template all come out of upstream metadata, so a hostile,
misconfigured or spoofed upstream chooses them -- and the registry fetches
them with the upstream's credentials attached, stores the bytes, and serves
them to anonymous readers. Without a check that made minireg a read-SSRF
oracle into whatever network it sits in, and a way to walk a GitLab token off
to another host.

Two rules:

* The host must be the upstream's own, or on the operator's allowlist.
* The address it resolves to must be public, unless the operator says
  otherwise (a self-hosted GitLab on an internal address is legitimate, so
  this is configuration rather than a hard rule).

Both are re-applied to every redirect hop, because a 302 is exactly how a
permitted host hands off to a forbidden one.

The address rule is only as good as the connection that follows it. If the
check resolves the name and the HTTP client then resolves it again to
connect, a DNS server that answers the first lookup with a public address
and the second with 10.0.0.5 walks straight past it (rebinding). So
:func:`guard_url` resolves once, approves the addresses, and *pins* them on
a :class:`PinnedBackend`; a client built on that backend connects only to
pinned addresses and never resolves anything itself. The container-image
upstreams (docker/upstream.py) and the package upstreams (upstreams/base.py)
share this module, so they also share one definition of "private".
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

import httpx
from httpcore import AsyncNetworkBackend

from ..config import settings

log = logging.getLogger(__name__)


class BlockedUrl(Exception):
    """The URL is not one this deployment will fetch."""


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #
#: Ranges refused on top of everything ``ipaddress`` already calls private,
#: loopback, link-local, reserved, multicast or unspecified.
EXTRA_BLOCKED_NETWORKS = (
    # Carrier-grade NAT. Not "private" to ipaddress, but it is where
    # Tailscale and many cloud VPC internals live.
    ipaddress.ip_network("100.64.0.0/10"),
)


def is_public_address(address: str) -> bool:
    """Whether ``address`` is somewhere an upstream may legitimately live.

    The single definition for every outbound fetch. IPv4-mapped IPv6
    (``::ffff:10.0.0.1``) is judged as the IPv4 address it carries.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False
    return not any(ip in net for net in EXTRA_BLOCKED_NETWORKS if net.version == ip.version)


async def resolve_host(host: str, port: int) -> list[str]:
    """Resolve, retrying transient failures.

    Resolvers in container networks (Docker's embedded DNS forwarding to a
    site resolver) intermittently answer EAI_NODATA/EAI_AGAIN for names that
    resolve a moment later. One such answer used to fail a cold download
    outright; three quick attempts ride it out.
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


# --------------------------------------------------------------------------- #
# DNS pinning
# --------------------------------------------------------------------------- #
class PinnedBackend(AsyncNetworkBackend):
    """httpcore network backend that connects only to pre-approved addresses.

    A guard resolves a host and approves its addresses; this backend then
    refuses any connection to that host on an address it did not approve,
    and resolves nothing itself. Closing the gap between "the name resolved
    to something public when we checked" and "the socket went somewhere
    public" is the whole point.

    ``require_pin`` decides, per connection, whether an unpinned host is
    refused (the default) or connected to normally. The package upstreams
    pass "unless private addresses are allowed": with that switch on there
    is no address to keep anyone away from, and nothing is resolved twice.
    """

    def __init__(self, require_pin: Callable[[], bool] | None = None) -> None:
        from httpcore._backends.auto import AutoBackend

        self._inner = AutoBackend()
        self._require_pin = require_pin or (lambda: True)
        self.pins: dict[str, tuple[float, list[str]]] = {}

    def pin(self, host: str, addresses: list[str]) -> None:
        self.pins[host.lower()] = (time.monotonic() + 300, addresses)
        if len(self.pins) > 4096:
            now = time.monotonic()
            self.pins = {h: v for h, v in self.pins.items() if v[0] > now}

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        entry = self.pins.get(host.lower())
        if entry is None or entry[0] < time.monotonic():
            if self._require_pin():
                raise httpx.ConnectError(f"connection to {host} was not approved")
            addresses = [host]
        else:
            addresses = entry[1]
        last: Exception | None = None
        for address in addresses:
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


def pinned_client(
    backend: PinnedBackend,
    *,
    verify: bool,
    timeout: httpx.Timeout,
    max_connections: int,
    max_keepalive: int,
    headers: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    """An httpx client whose every connection goes through ``backend``.

    Redirects are never followed by the client: each hop has to pass the
    guard (and be pinned) before it is taken, so callers follow them.
    """
    import contextlib

    import httpcore

    pool = httpcore.AsyncConnectionPool(
        ssl_context=httpx.create_ssl_context(verify=verify),
        max_connections=max_connections,
        max_keepalive_connections=max_keepalive,
        keepalive_expiry=30,
        http1=True,
        http2=True,
        network_backend=backend,
    )
    transport = httpx.AsyncHTTPTransport(verify=verify, http2=True)
    # Swap in the pool built on the pinned backend. The transport's own
    # pool has opened nothing yet; close it so it does not leak.
    old = transport._pool
    transport._pool = pool
    with contextlib.suppress(Exception):
        asyncio.get_running_loop().create_task(old.aclose())
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
        headers=headers or {},
    )


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def same_origin(a: str, b: str) -> bool:
    """Whether two URLs share scheme, host and effective port."""
    pa, pb = urlsplit(a), urlsplit(b)
    if pa.scheme != pb.scheme:
        return False
    if (pa.hostname or "").lower() != (pb.hostname or "").lower():
        return False
    default = {"https": 443, "http": 80}
    return (pa.port or default.get(pa.scheme)) == (pb.port or default.get(pb.scheme))


def _check_url_shape(
    url: str, *, upstream_url: str | None, extra_hosts: Iterable[str] = ()
) -> str:
    """Scheme and host rules. Returns the (lower-cased) host."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise BlockedUrl(f"refusing to fetch a non-HTTP URL ({scheme or 'no scheme'})")
    if scheme == "http" and not settings.upstream_allow_plaintext_http:
        raise BlockedUrl(
            "refusing to fetch from an upstream over plaintext HTTP; set "
            "UPSTREAM_ALLOW_PLAINTEXT_HTTP=true if an internal mirror needs it"
        )

    host = _host_of(url)
    if not host:
        raise BlockedUrl("artifact URL has no host")

    permitted = set(settings.artifact_host_allowlist)
    permitted.update(h.lower() for h in extra_hosts if h)
    if upstream_url:
        upstream_host = _host_of(upstream_url)
        if upstream_host:
            permitted.add(upstream_host)
    if host not in permitted:
        raise BlockedUrl(
            f"'{host}' is not an allowed artifact host. Add it to "
            "UPSTREAM_ARTIFACT_HOSTS if this upstream serves its files from there."
        )
    return host


def _literal(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


def _resolves_private(host: str) -> bool:
    """Whether any address for ``host`` is unsafe to reach.

    Returns True (i.e. "blocked") if *any* resolved address is private,
    loopback, link-local or reserved -- a name that resolves to both a public
    and a private address is a rebinding attempt, not a mixed deployment.
    """
    literal = _literal(host)
    if literal is not None:
        return not is_public_address(literal)
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        # Cannot resolve: let the HTTP layer fail on it rather than guessing.
        return False
    return any(not is_public_address(str(info[4][0])) for info in infos)


def check_fetchable(url: str, *, upstream_url: str | None = None) -> None:
    """Raise :class:`BlockedUrl` unless this URL may be fetched.

    ``upstream_url`` is the configured base URL of the upstream that supplied
    the artifact URL; its host is always permitted.

    A synchronous pre-check: it resolves the name with the blocking resolver
    and does not pin. Fetches made through an upstream provider are guarded
    again, and pinned, by :func:`guard_url` on every hop.
    """
    host = _check_url_shape(url, upstream_url=upstream_url)
    if not settings.upstream_allow_private_addresses and _resolves_private(host):
        raise BlockedUrl(
            f"'{host}' resolves to a private or link-local address; refusing to fetch"
        )


async def guard_url(
    url: str,
    *,
    upstream_url: str | None,
    backend: PinnedBackend,
    extra_hosts: Iterable[str] = (),
) -> None:
    """:func:`check_fetchable`, then resolve once and pin the result.

    ``extra_hosts`` widens the host rule for this call only -- the package
    providers pass the host of the URL they built from configuration (a
    cargo registry's separate API host, say), which an admin chose, while a
    URL taken from upstream metadata gets no such allowance.

    With UPSTREAM_ALLOW_PRIVATE_ADDRESSES on, nothing is resolved or pinned:
    every address is acceptable, and the backend connects normally.
    """
    host = _check_url_shape(url, upstream_url=upstream_url, extra_hosts=extra_hosts)
    if settings.upstream_allow_private_addresses:
        return
    literal = _literal(host)
    if literal is not None:
        addresses = [literal]
    else:
        parts = urlsplit(url)
        try:
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        except ValueError as exc:
            raise BlockedUrl(f"'{url[:200]}' has an invalid port") from exc
        try:
            addresses = await resolve_host(host, port)
        except OSError as exc:
            raise BlockedUrl(f"cannot resolve '{host}': {exc}") from exc
    bad = [a for a in addresses if not is_public_address(a)]
    if bad or not addresses:
        raise BlockedUrl(
            f"'{host}' resolves to a private or link-local address; refusing to fetch"
        )
    backend.pin(host, addresses)
