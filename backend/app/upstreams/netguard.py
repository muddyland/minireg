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
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlsplit

from ..config import settings

log = logging.getLogger(__name__)


class BlockedUrl(Exception):
    """The URL is not one this deployment will fetch."""


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


def _resolves_private(host: str) -> bool:
    """Whether every address for ``host`` is safe to reach.

    Returns True (i.e. "blocked") if *any* resolved address is private,
    loopback, link-local or reserved -- a name that resolves to both a public
    and a private address is a rebinding attempt, not a mixed deployment.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        # Cannot resolve: let the HTTP layer fail on it rather than guessing.
        return False
    for info in infos:
        address = info[4][0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
            or parsed.is_unspecified
        ):
            return True
    return False


def check_fetchable(url: str, *, upstream_url: str | None = None) -> None:
    """Raise :class:`BlockedUrl` unless this URL may be fetched.

    ``upstream_url`` is the configured base URL of the upstream that supplied
    the artifact URL; its host is always permitted.
    """
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise BlockedUrl(f"refusing to fetch a non-HTTP URL ({scheme or 'no scheme'})")
    if scheme == "http" and not settings.upstream_allow_plaintext_http:
        raise BlockedUrl(
            "refusing to fetch an artifact over plaintext HTTP; set "
            "UPSTREAM_ALLOW_PLAINTEXT_HTTP=true if an internal mirror needs it"
        )

    host = _host_of(url)
    if not host:
        raise BlockedUrl("artifact URL has no host")

    permitted = set(settings.artifact_host_allowlist)
    if upstream_url:
        upstream_host = _host_of(upstream_url)
        if upstream_host:
            permitted.add(upstream_host)
    if host not in permitted:
        raise BlockedUrl(
            f"'{host}' is not an allowed artifact host. Add it to "
            "UPSTREAM_ARTIFACT_HOSTS if this upstream serves its files from there."
        )

    if not settings.upstream_allow_private_addresses and _resolves_private(host):
        raise BlockedUrl(
            f"'{host}' resolves to a private or link-local address; refusing to fetch"
        )
